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
            RequiresConsent = context.RequiresConsent,
            RememberConsentAllowed = context.RememberConsentAllowed,
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

        if (string.Equals(command.Action, "deny", StringComparison.OrdinalIgnoreCase) || command.ConsentGranted == false)
        {
            await authorizationService.DenyAuthorizationRequestAsync(command.RequestId, cancellationToken);
            return Ok(new AuthorizationInteractionResult
            {
                Outcome = "redirect",
                RedirectUrl = BuildErrorRedirectUrl(context.RedirectUri, context.State, "access_denied", "The resource owner denied the authorization request")
            });
        }

        var subjectId = command.SubjectId;
        if (RequiresSubject(command.Action) && string.IsNullOrWhiteSpace(subjectId))
        {
            return BadRequest(new ProblemDetails
            {
                Title = "subject_id is required",
                Detail = $"Action '{command.Action}' requires a subject identifier.",
                Status = StatusCodes.Status400BadRequest
            });
        }

        var scopes = command.Scopes?.Where(scope => context.RequestedScopes.Contains(scope, StringComparer.Ordinal)).ToArray() ?? context.RequestedScopes;
        if (scopes.Length == 0)
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
            return Ok(BuildInteractionRequiredResponse(context, "consent", "User consent is required"));
        }

        var approval = await authorizationService.ApproveAuthorizationRequestAsync(new()
        {
            ClientId = context.ClientId,
            RequestId = context.RequestId,
            SubjectId = subjectId!,
            Scopes = scopes,
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

    private AuthorizationInteractionResult BuildInteractionRequiredResponse(AuthorizationRequestContext context, string interactionType, string detail) =>
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
                RememberConsentAllowed = context.RememberConsentAllowed,
                Prompt = context.Prompt,
                MaxAge = context.MaxAge,
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

    public string? Prompt { get; set; }

    public bool RememberConsentAllowed { get; set; }

    public required string RedirectUri { get; set; }

    public required string RequestId { get; set; }

    public required string[] RequestedScopes { get; set; }

    public bool RequiresConsent { get; set; }

    public string? State { get; set; }
}

public class AuthorizationInteractionResult
{
    public AuthorizationInteractionResponsePayload? Interaction { get; set; }

    public required string Outcome { get; set; }

    public string? RedirectUrl { get; set; }
}

public class AuthorizationInteractionResponsePayload
{
    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public string? ContextEndpoint { get; set; }

    public string? ContinueEndpoint { get; set; }

    public required string Error { get; set; }

    public required string ErrorDescription { get; set; }

    public required string InteractionType { get; set; }

    public string? LoginHint { get; set; }

    public int? MaxAge { get; set; }

    public string? Prompt { get; set; }

    public bool RememberConsentAllowed { get; set; }

    public required string RedirectUri { get; set; }

    public required string RequestId { get; set; }

    public required string[] RequestedScopes { get; set; }

    public string? State { get; set; }

    public required string[] AvailableActions { get; set; }
}