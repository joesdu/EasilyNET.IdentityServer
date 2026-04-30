using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.1 Authorization Endpoint
/// </summary>
[ApiController]
public class AuthorizeController : ControllerBase
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IAuthorizationScopeMetadataService _authorizationScopeMetadataService;
    private readonly IUserConsentStore? _consentStore;
    private readonly IdentityServerOptions _options;

    public AuthorizeController(
        IAuthorizationService authorizationService,
        IAuthorizationScopeMetadataService authorizationScopeMetadataService,
        IdentityServerOptions options,
        IUserConsentStore? consentStore = null)
    {
        _authorizationService = authorizationService;
        _authorizationScopeMetadataService = authorizationScopeMetadataService;
        _options = options;
        _consentStore = consentStore;
    }

    /// <summary>
    /// 授权端点
    /// </summary>
    [HttpGet("/connect/authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery]
        string response_type,
        [FromQuery]
        string client_id,
        [FromQuery]
        string redirect_uri,
        [FromQuery]
        string? scope,
        [FromQuery]
        string? state,
        [FromQuery]
        string? nonce,
        [FromQuery]
        string? code_challenge,
        [FromQuery]
        string? code_challenge_method,
        [FromQuery]
        string? prompt,
        [FromQuery]
        int? max_age,
        [FromQuery]
        string? login_hint,
        CancellationToken cancellationToken)
    {
        // 添加点击劫持保护 (OAuth 2.1 安全要求)
        // X-Frame-Options: 防止页面在 iframe 中渲染
        Response.Headers.XFrameOptions = "DENY";
        // Content-Security-Policy: 更严格的防护
        Response.Headers.ContentSecurityPolicy = "frame-ancestors 'none'";
        // X-Content-Type-Options: 防止 MIME 类型嗅探
        Response.Headers.XContentTypeOptions = "nosniff";
        // X-XSS-Protection: 传统 XSS 防护 (现代浏览器已内置)
        Response.Headers.XXSSProtection = "1; mode=block";
        // Referrer-Policy: 控制引用来源信息
        Response.Headers["Referrer-Policy"] = "no-referrer";

        if (string.IsNullOrEmpty(client_id))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }
        if (string.IsNullOrEmpty(redirect_uri))
        {
            return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
        }

        // 验证 state 长度 (OAuth 2.1 建议不超过 512 字符)
        if (!string.IsNullOrEmpty(state) && state.Length > 512)
        {
            return BadRequest(new { error = "invalid_request", error_description = "state parameter exceeds maximum length of 512 characters" });
        }

        // 验证 nonce 长度 (OIDC 建议不超过 512 字符)
        if (!string.IsNullOrEmpty(nonce) && nonce.Length > 512)
        {
            return BadRequest(new { error = "invalid_request", error_description = "nonce parameter exceeds maximum length of 512 characters" });
        }

        var requestedScopes = string.IsNullOrEmpty(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var validation = await _authorizationService.ValidateAuthorizationRequestAsync(new()
        {
            ClientId = client_id,
            ResponseType = response_type,
            RedirectUri = redirect_uri,
            Scopes = requestedScopes,
            State = state,
            Nonce = nonce,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method,
            Prompt = prompt,
            MaxAge = max_age,
            LoginHint = login_hint
        }, cancellationToken);
        if (!validation.IsSuccess)
        {
            return CanRedirectError(validation.Error)
                ? RedirectWithError(redirect_uri, state, validation.Error!, validation.ErrorDescription ?? validation.Error!)
                : BadRequest(new { error = validation.Error, error_description = validation.ErrorDescription });
        }
        var client = validation.Client!;
        if (requestedScopes.Count == 0)
        {
            requestedScopes = client.AllowedScopes.ToList();
        }

        var prompts = SplitPrompt(prompt);
        var authContext = ResolveAuthenticationContext();
        var subjectId = authContext.SubjectId;
        var requiresFreshLogin = max_age.HasValue && !HasFreshAuthentication(authContext.AuthenticationTime, max_age.Value);

        if (prompts.Contains("select_account", StringComparer.Ordinal))
        {
            if (prompts.Contains("none", StringComparer.Ordinal))
            {
                return RedirectWithError(redirect_uri, state, "account_selection_required", "The request requires end-user account selection");
            }

            return await BuildInteractionRequiredResponse(StatusCodes.Status409Conflict, "select_account", client, validation.RequestId!, requestedScopes, redirect_uri, state,
                "Account selection is required", login_hint, prompt, max_age);
        }

        if (prompts.Contains("login", StringComparer.Ordinal))
        {
            return await BuildLoginInteractionResponse(prompts.Contains("none", StringComparer.Ordinal), redirect_uri, state, client, validation.RequestId!, requestedScopes, login_hint,
                prompt,
                max_age,
                prompts.Contains("none", StringComparer.Ordinal)
                    ? "The request requires user re-authentication"
                    : "User re-authentication is required");
        }

        if (requiresFreshLogin)
        {
            return await BuildLoginInteractionResponse(prompts.Contains("none", StringComparer.Ordinal), redirect_uri, state, client, validation.RequestId!, requestedScopes, login_hint,
                prompt,
                max_age,
                prompts.Contains("none", StringComparer.Ordinal)
                    ? "The authenticated session is too old"
                    : "User re-authentication is required because max_age was exceeded");
        }

        if (prompts.Contains("none", StringComparer.Ordinal) && string.IsNullOrEmpty(subjectId))
        {
            return RedirectWithError(redirect_uri, state, "login_required", "User is not authenticated");
        }

        // 检查用户是否已登录
        if (string.IsNullOrEmpty(subjectId))
        {
            return await BuildInteractionRequiredResponse(StatusCodes.Status401Unauthorized, "login", client, validation.RequestId!, requestedScopes, redirect_uri, state,
                "User authentication is required", login_hint, prompt, max_age);
        }

        // 检查是否需要 consent (prompt=consent 强制要求)
        var forceConsent = prompts.Contains("consent", StringComparer.Ordinal);
        var consentAccepted = string.Equals(Request.Query["consent"], "accept", StringComparison.OrdinalIgnoreCase);
        var consentRejected = string.Equals(Request.Query["consent"], "deny", StringComparison.OrdinalIgnoreCase);
        if (consentRejected)
        {
            return RedirectWithError(redirect_uri, state, "access_denied", "The resource owner denied the consent request");
        }

        var existingConsent = _consentStore == null ? null : await _consentStore.GetAsync(subjectId, client.ClientId, cancellationToken);
        var existingScopes = existingConsent?.Scopes.ToHashSet(StringComparer.Ordinal) ?? [];
        var hasExistingConsent = existingConsent != null && requestedScopes.All(existingScopes.Contains);
        var needsConsent = forceConsent || (validation.NeedsConsent && !hasExistingConsent);
        if (needsConsent && prompts.Contains("none", StringComparer.Ordinal))
        {
            return RedirectWithError(redirect_uri, state, "consent_required", "User consent is required");
        }

        if (needsConsent && !consentAccepted)
        {
            return await BuildInteractionRequiredResponse(StatusCodes.Status403Forbidden, "consent", client, validation.RequestId!, requestedScopes, redirect_uri, state,
                "User consent is required", login_hint, prompt, max_age);
        }

        var rememberConsentRequested = string.Equals(Request.Query["remember_consent"], "true", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(Request.Query["remember_consent"], "on", StringComparison.OrdinalIgnoreCase);

        var approval = await _authorizationService.ApproveAuthorizationRequestAsync(new()
        {
            ClientId = client.ClientId,
            RequestId = validation.RequestId!,
            SubjectId = subjectId,
            Scopes = requestedScopes,
            RedirectUri = redirect_uri,
            Nonce = nonce,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method,
            RememberConsent = consentAccepted && rememberConsentRequested && client.AllowRememberConsent && _options.AllowRememberConsent
        }, cancellationToken);
        if (!approval.IsSuccess || string.IsNullOrEmpty(approval.AuthorizationCode))
        {
            return RedirectWithError(redirect_uri, state, approval.Error ?? "server_error", approval.ErrorDescription ?? "Authorization request could not be approved");
        }

        // 重定向回客户端
        var redirectUrl = BuildRedirectUrl(redirect_uri, approval.AuthorizationCode, state);
        return Redirect(redirectUrl);
    }

    private IActionResult RedirectWithError(string redirectUri, string? state, string error, string errorDescription)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{separator}error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(errorDescription)}";
        if (!string.IsNullOrEmpty(state))
        {
            url += $"&state={Uri.EscapeDataString(state)}";
        }
        url += $"&iss={Uri.EscapeDataString(_options.Issuer)}";
        return Redirect(url);
    }

    private string BuildRedirectUrl(string redirectUri, string code, string? state)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrEmpty(state))
        {
            url += $"&state={Uri.EscapeDataString(state)}";
        }
        url += $"&iss={Uri.EscapeDataString(_options.Issuer)}";
        return url;
    }

    private static bool CanRedirectError(string? error) => error is not "invalid_client";

    private static string[] SplitPrompt(string? prompt) =>
        string.IsNullOrWhiteSpace(prompt) ? [] : prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    private async Task<IActionResult> BuildLoginInteractionResponse(
        bool redirectForPromptNone,
        string redirectUri,
        string? state,
        Client client,
        string requestId,
        IEnumerable<string> requestedScopes,
        string? loginHint,
        string? prompt,
        int? maxAge,
        string detail)
    {
        return redirectForPromptNone
            ? RedirectWithError(redirectUri, state, "login_required", detail)
            : await BuildInteractionRequiredResponse(StatusCodes.Status401Unauthorized, "login", client, requestId, requestedScopes, redirectUri, state, detail, loginHint, prompt, maxAge);
    }

    private static bool HasFreshAuthentication(DateTimeOffset? authenticationTime, int maxAgeSeconds)
    {
        if (authenticationTime == null)
        {
            return false;
        }

        return DateTimeOffset.UtcNow - authenticationTime.Value <= TimeSpan.FromSeconds(maxAgeSeconds);
    }

    private AuthenticationContext ResolveAuthenticationContext() =>
        new(ResolveSubjectId(), ResolveAuthenticationTime());

    private DateTimeOffset? ResolveAuthenticationTime()
    {
        var authTimeValue = User.FindFirstValue("auth_time");
        if (TryParseAuthenticationTime(authTimeValue, out var authTime))
        {
            return authTime;
        }

        var headerAuthTime = Request.Headers["X-Auth-Time"].ToString();
        if (TryParseAuthenticationTime(headerAuthTime, out authTime))
        {
            return authTime;
        }

        var queryAuthTime = Request.Query["auth_time"].ToString();
        return TryParseAuthenticationTime(queryAuthTime, out authTime) ? authTime : null;
    }

    private static bool TryParseAuthenticationTime(string? value, out DateTimeOffset authTime)
    {
        authTime = default;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (long.TryParse(value, out var epochSeconds))
        {
            authTime = DateTimeOffset.FromUnixTimeSeconds(epochSeconds);
            return true;
        }

        return DateTimeOffset.TryParse(value, out authTime);
    }

    private string? ResolveSubjectId()
    {
        var principalSubjectId = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrWhiteSpace(principalSubjectId))
        {
            return principalSubjectId;
        }

        var headerSubjectId = Request.Headers["X-Subject-Id"].ToString();
        if (!string.IsNullOrWhiteSpace(headerSubjectId))
        {
            return headerSubjectId;
        }

        var querySubjectId = Request.Query["subject_id"].ToString();
        return string.IsNullOrWhiteSpace(querySubjectId) ? null : querySubjectId;
    }

    private async Task<ObjectResult> BuildInteractionRequiredResponse(
        int statusCode,
        string interactionType,
        Client client,
        string requestId,
        IEnumerable<string> requestedScopes,
        string redirectUri,
        string? state,
        string detail,
        string? loginHint,
        string? prompt,
        int? maxAge)
    {
        var scopeDetails = await _authorizationScopeMetadataService.DescribeScopesAsync(requestedScopes, requestedScopes);
        return StatusCode(statusCode, new AuthorizationInteractionResponse
        {
            Error = "interaction_required",
            ErrorDescription = detail,
            InteractionType = interactionType,
            RequestId = requestId,
            ClientId = client.ClientId,
            ClientName = client.ClientName,
            RedirectUri = redirectUri,
            State = state,
            LoginHint = loginHint,
            RequestedScopes = requestedScopes.ToArray(),
            RequestedScopeDetails = scopeDetails.ToArray(),
            RememberConsentAllowed = client.AllowRememberConsent && _options.AllowRememberConsent,
            Prompt = prompt,
            MaxAge = maxAge,
            ContextEndpoint = $"/connect/authorize/context/{requestId}",
            ContinueEndpoint = "/connect/authorize/interaction",
            AvailableActions = interactionType switch
            {
                "login" => ["login", "deny"],
                "select_account" => ["select_account", "deny"],
                _ => ["consent", "deny"]
            }
        });
    }
}

internal sealed class AuthorizationInteractionResponse
{
    public required string[] AvailableActions { get; init; }

    public required string ClientId { get; init; }

    public string? ClientName { get; init; }

    public string? ContextEndpoint { get; init; }

    public string? ContinueEndpoint { get; init; }

    public required string Error { get; init; }

    public required string ErrorDescription { get; init; }

    public required string InteractionType { get; init; }

    public string? LoginHint { get; init; }

    public int? MaxAge { get; init; }

    public string? Prompt { get; init; }

    public required AuthorizationScopeDescriptor[] RequestedScopeDetails { get; init; }

    public bool RememberConsentAllowed { get; init; }

    public required string RedirectUri { get; init; }

    public required string RequestId { get; init; }

    public required string[] RequestedScopes { get; init; }

    public string? State { get; init; }
}

internal sealed record AuthenticationContext(string? SubjectId, DateTimeOffset? AuthenticationTime);
