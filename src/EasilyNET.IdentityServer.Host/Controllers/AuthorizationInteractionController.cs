using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// 授权交互协议端点，供登录/账号选择/同意 UI 使用
/// </summary>
[ApiController]
public class AuthorizationInteractionController(
    IAuthorizationRequestContextService authorizationRequestContextService,
    IAuthorizationAccountService authorizationAccountService,
    IAuthorizationScopeMetadataService authorizationScopeMetadataService,
    IAuthorizationService authorizationService,
    IdentityServerOptions options) : ControllerBase
{
    [HttpGet("/connect/authorize/context/{requestId}")]
    public async Task<IActionResult> GetContext(string requestId, CancellationToken cancellationToken)
    {
        var context = await authorizationRequestContextService.GetAsync(requestId, cancellationToken);
        if (context == null)
        {
            return NotFound(new ProblemDetails
            {
                Title = "Authorization request context not found",
                Detail = "The authorization request context was not found or has expired.",
                Status = StatusCodes.Status404NotFound
            });
        }

        var availableAccounts = await GetAvailableAccountsAsync(context, cancellationToken);
        var scopeDetails = await GetScopeDetailsAsync(context, cancellationToken);

        return Ok(new AuthorizationRequestContextResponse
        {
            RequestId = context.RequestId,
            ClientId = context.ClientId,
            ClientName = context.ClientName,
            ClientUri = context.ClientUri,
            LogoUri = context.LogoUri,
            RedirectUri = context.RedirectUri,
            State = context.State,
            Prompt = context.Prompt,
            LoginHint = context.LoginHint,
            MaxAge = context.MaxAge,
            RequestedScopes = context.RequestedScopes,
            RequestedScopeDetails = scopeDetails,
            PendingConsentScopes = context.PendingConsentScopes.Length == 0 ? context.RequestedScopes : context.PendingConsentScopes,
            RequiresConsent = context.RequiresConsent,
            RememberConsentAllowed = context.RememberConsentAllowed,
            SubjectId = context.SubjectId,
            SelectedAccount = availableAccounts.FirstOrDefault(account => account.IsCurrent),
            AvailableAccounts = availableAccounts,
            CreatedAt = context.CreationTime,
            ExpiresAt = context.ExpirationTime,
            ContinueEndpoint = "/connect/authorize/interaction",
            CancelEndpoint = "/connect/authorize/interaction",
            ContextEndpoint = $"/connect/authorize/context/{context.RequestId}"
        });
    }

    [HttpPost("/connect/authorize/interaction")]
    public async Task<IActionResult> ContinueInteraction([FromBody] AuthorizationInteractionCommand command, CancellationToken cancellationToken)
    {
        var context = await authorizationRequestContextService.GetAsync(command.RequestId, cancellationToken);
        if (context == null)
        {
            return NotFound(new ProblemDetails
            {
                Title = "Authorization request context not found",
                Detail = "The authorization request context was not found or has expired.",
                Status = StatusCodes.Status404NotFound
            });
        }

        var approvedScopes = ResolveApprovedScopes(context, command.Scopes);

        if (string.Equals(command.Action, "deny", StringComparison.OrdinalIgnoreCase) || command.ConsentGranted == false)
        {
            await authorizationService.DenyAuthorizationRequestAsync(command.RequestId, cancellationToken);
            return Ok(new AuthorizationInteractionResult
            {
                Outcome = "redirect",
                RedirectUrl = BuildErrorRedirectUrl(context.RedirectUri, context.State, "access_denied", "The resource owner denied the authorization request")
            });
        }

        var subjectId = command.SubjectId ?? context.SubjectId;
        AuthorizationAccountCandidate? selectedAccount = null;

        if (string.Equals(command.Action, "login", StringComparison.OrdinalIgnoreCase) || string.Equals(command.Action, "select_account", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(subjectId))
            {
                return BadRequest(new ProblemDetails
                {
                    Title = "subject_id is required",
                    Detail = $"Action '{command.Action}' requires a subject identifier.",
                    Status = StatusCodes.Status400BadRequest
                });
            }

            selectedAccount = await authorizationAccountService.FindBySubjectIdAsync(subjectId, cancellationToken);
            if (selectedAccount == null)
            {
                return BadRequest(new ProblemDetails
                {
                    Title = "Unknown subject_id",
                    Detail = $"No account candidate was found for subject '{subjectId}'.",
                    Status = StatusCodes.Status400BadRequest
                });
            }

            if (context.IdentityProviderRestrictions.Length > 0 &&
                !string.IsNullOrWhiteSpace(selectedAccount.IdentityProvider) &&
                !context.IdentityProviderRestrictions.Contains(selectedAccount.IdentityProvider, StringComparer.OrdinalIgnoreCase))
            {
                return BadRequest(new ProblemDetails
                {
                    Title = "Identity provider is not allowed",
                    Detail = $"Account '{subjectId}' uses an identity provider that is not allowed for this client.",
                    Status = StatusCodes.Status400BadRequest
                });
            }

            context = WithUpdatedInteractionState(context, selectedAccount, approvedScopes);
            await authorizationRequestContextService.StoreAsync(context, cancellationToken);
        }

        if (RequiresSubject(command.Action) && string.IsNullOrWhiteSpace(subjectId))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "subject_id is required",
                Detail = $"Action '{command.Action}' requires a subject identifier.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        if (approvedScopes.Length == 0)
        {
            return BadRequest(new ProblemDetails
            {
                Title = "No scopes approved",
                Detail = "At least one requested scope must be approved.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        if (context.RequiresConsent && !string.Equals(command.Action, "consent", StringComparison.OrdinalIgnoreCase))
        {
            var availableAccounts = await GetAvailableAccountsAsync(context, cancellationToken);
            return Ok(await BuildInteractionRequiredResponseAsync(context, "consent", "User consent is required", availableAccounts, cancellationToken));
        }

        var approval = await authorizationService.ApproveAuthorizationRequestAsync(new()
        {
            ClientId = context.ClientId,
            RequestId = context.RequestId,
            SubjectId = subjectId!,
            Scopes = approvedScopes,
            RedirectUri = context.RedirectUri,
            Nonce = context.Nonce,
            CodeChallenge = context.CodeChallenge,
            CodeChallengeMethod = context.CodeChallengeMethod,
            RememberConsent = command.RememberConsent && context.RememberConsentAllowed
        }, cancellationToken);

        if (!approval.IsSuccess || string.IsNullOrEmpty(approval.AuthorizationCode))
        {
            return BadRequest(new ProblemDetails
            {
                Title = approval.Error ?? "Authorization interaction failed",
                Detail = approval.ErrorDescription ?? "The authorization interaction could not be completed.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        return Ok(new AuthorizationInteractionResult
        {
            Outcome = "redirect",
            RedirectUrl = BuildSuccessRedirectUrl(context.RedirectUri, approval.AuthorizationCode, context.State)
        });
    }

    private static bool RequiresSubject(string action) =>
        string.Equals(action, "login", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(action, "select_account", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(action, "consent", StringComparison.OrdinalIgnoreCase);

    private async Task<AuthorizationInteractionResult> BuildInteractionRequiredResponseAsync(
        AuthorizationRequestContext context,
        string interactionType,
        string detail,
        IReadOnlyCollection<AuthorizationAccountCandidate> availableAccounts,
        CancellationToken cancellationToken)
    {
        var scopeDetails = await GetScopeDetailsAsync(context, cancellationToken);
        return
        new()
        {
            Outcome = "interaction_required",
            Interaction = new AuthorizationInteractionResponsePayload
            {
                Error = "interaction_required",
                ErrorDescription = detail,
                InteractionType = interactionType,
                RequestId = context.RequestId,
                ClientId = context.ClientId,
                ClientName = context.ClientName,
                RedirectUri = context.RedirectUri,
                State = context.State,
                LoginHint = context.LoginHint,
                RequestedScopes = context.RequestedScopes,
                RequestedScopeDetails = scopeDetails,
                RememberConsentAllowed = context.RememberConsentAllowed,
                Prompt = context.Prompt,
                MaxAge = context.MaxAge,
                SubjectId = context.SubjectId,
                SelectedAccount = availableAccounts.FirstOrDefault(account => account.IsCurrent),
                AvailableAccounts = availableAccounts.ToArray(),
                PendingConsentScopes = context.PendingConsentScopes.Length == 0 ? context.RequestedScopes : context.PendingConsentScopes,
                ContinueEndpoint = "/connect/authorize/interaction",
                ContextEndpoint = $"/connect/authorize/context/{context.RequestId}",
                AvailableActions = interactionType switch
                {
                    "login" => ["login", "deny"],
                    "select_account" => ["select_account", "deny"],
                    _ => ["consent", "deny"]
                }
            }
        };
    }

    private async Task<AuthorizationAccountCandidate[]> GetAvailableAccountsAsync(AuthorizationRequestContext context, CancellationToken cancellationToken)
    {
        var accounts = await authorizationAccountService.GetAccountsAsync(new AuthorizationAccountQuery
        {
            CurrentSubjectId = context.SubjectId,
            LoginHint = context.LoginHint,
            IdentityProviderRestrictions = context.IdentityProviderRestrictions
        }, cancellationToken);

        return accounts.ToArray();
    }

    private static string[] ResolveApprovedScopes(AuthorizationRequestContext context, string[]? scopes)
    {
        var effectiveScopes = scopes?.Where(scope => context.RequestedScopes.Contains(scope, StringComparer.Ordinal)).ToArray();
        if (effectiveScopes is { Length: > 0 })
        {
            return effectiveScopes;
        }

        return context.PendingConsentScopes.Length == 0 ? context.RequestedScopes : context.PendingConsentScopes;
    }

    private static AuthorizationRequestContext WithUpdatedInteractionState(
        AuthorizationRequestContext context,
        AuthorizationAccountCandidate selectedAccount,
        string[] approvedScopes) =>
        new()
        {
            RequestId = context.RequestId,
            ClientId = context.ClientId,
            ClientName = context.ClientName,
            ClientUri = context.ClientUri,
            LogoUri = context.LogoUri,
            CodeChallenge = context.CodeChallenge,
            CodeChallengeMethod = context.CodeChallengeMethod,
            CreationTime = context.CreationTime,
            ExpirationTime = context.ExpirationTime,
            IdentityProviderRestrictions = context.IdentityProviderRestrictions,
            LoginHint = context.LoginHint,
            MaxAge = context.MaxAge,
            Nonce = context.Nonce,
            PendingConsentScopes = approvedScopes,
            Prompt = context.Prompt,
            RememberConsentAllowed = context.RememberConsentAllowed,
            RequiresConsent = context.RequiresConsent,
            RedirectUri = context.RedirectUri,
            RequestedScopes = context.RequestedScopes,
            State = context.State,
            SubjectId = selectedAccount.SubjectId,
            SubjectDisplayName = selectedAccount.DisplayName,
            SubjectIdentityProvider = selectedAccount.IdentityProvider
        };

    private async Task<AuthorizationScopeDescriptor[]> GetScopeDetailsAsync(AuthorizationRequestContext context, CancellationToken cancellationToken)
    {
        var selectedScopes = context.PendingConsentScopes.Length == 0 ? context.RequestedScopes : context.PendingConsentScopes;
        var descriptors = await authorizationScopeMetadataService.DescribeScopesAsync(context.RequestedScopes, selectedScopes, cancellationToken);
        return descriptors.ToArray();
    }

    private string BuildSuccessRedirectUrl(string redirectUri, string code, string? state)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrEmpty(state))
        {
            url += $"&state={Uri.EscapeDataString(state)}";
        }

        url += $"&iss={Uri.EscapeDataString(options.Issuer)}";
        return url;
    }

    private string BuildErrorRedirectUrl(string redirectUri, string? state, string error, string errorDescription)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{separator}error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(errorDescription)}";
        if (!string.IsNullOrEmpty(state))
        {
            url += $"&state={Uri.EscapeDataString(state)}";
        }

        url += $"&iss={Uri.EscapeDataString(options.Issuer)}";
        return url;
    }
}

public class AuthorizationInteractionCommand
{
    public required string Action { get; set; }

    public bool ConsentGranted { get; set; } = true;

    public bool RememberConsent { get; set; }

    public required string RequestId { get; set; }

    public string[]? Scopes { get; set; }

    public string? SubjectId { get; set; }
}

public class AuthorizationRequestContextResponse
{
    public AuthorizationAccountCandidate[] AvailableAccounts { get; set; } = [];

    public string? CancelEndpoint { get; set; }

    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public string? ClientUri { get; set; }

    public string? ContextEndpoint { get; set; }

    public string? ContinueEndpoint { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    public string? LoginHint { get; set; }

    public string? LogoUri { get; set; }

    public int? MaxAge { get; set; }

    public string[] PendingConsentScopes { get; set; } = [];

    public AuthorizationScopeDescriptor[] RequestedScopeDetails { get; set; } = [];

    public string? Prompt { get; set; }

    public bool RememberConsentAllowed { get; set; }

    public required string RedirectUri { get; set; }

    public required string RequestId { get; set; }

    public required string[] RequestedScopes { get; set; }

    public bool RequiresConsent { get; set; }

    public AuthorizationAccountCandidate? SelectedAccount { get; set; }

    public string? State { get; set; }

    public string? SubjectId { get; set; }
}

public class AuthorizationInteractionResult
{
    public AuthorizationInteractionResponsePayload? Interaction { get; set; }

    public required string Outcome { get; set; }

    public string? RedirectUrl { get; set; }
}

public class AuthorizationInteractionResponsePayload
{
    public AuthorizationAccountCandidate[] AvailableAccounts { get; set; } = [];

    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public string? ContextEndpoint { get; set; }

    public string? ContinueEndpoint { get; set; }

    public required string Error { get; set; }

    public required string ErrorDescription { get; set; }

    public required string InteractionType { get; set; }

    public string? LoginHint { get; set; }

    public int? MaxAge { get; set; }

    public string[] PendingConsentScopes { get; set; } = [];

    public string? Prompt { get; set; }

    public bool RememberConsentAllowed { get; set; }

    public required string RedirectUri { get; set; }

    public required string RequestId { get; set; }

    public required string[] RequestedScopes { get; set; }

    public AuthorizationScopeDescriptor[] RequestedScopeDetails { get; set; } = [];

    public AuthorizationAccountCandidate? SelectedAccount { get; set; }

    public string? State { get; set; }

    public string? SubjectId { get; set; }

    public required string[] AvailableActions { get; set; }
}