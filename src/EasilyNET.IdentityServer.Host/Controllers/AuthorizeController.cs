using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.1 Authorization Endpoint
/// </summary>
[ApiController]
public class AuthorizeController : ControllerBase
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IUserConsentStore? _consentStore;
    private readonly IdentityServerOptions _options;

    public AuthorizeController(
        IAuthorizationService authorizationService,
        IdentityServerOptions options,
        IUserConsentStore? consentStore = null)
    {
        _authorizationService = authorizationService;
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

        // 处理 prompt 参数 (OIDC)
        var subjectId = Request.Headers["X-Subject-Id"].ToString();
        if (string.IsNullOrEmpty(subjectId))
        {
            subjectId = Request.Query["subject_id"].ToString();
        }

        // 根据 prompt 参数处理
        if (!string.IsNullOrEmpty(prompt))
        {
            var promptsArray = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // prompt=none: 不能显示登录或consent页面
            if (promptsArray.Contains("none"))
            {
                if (string.IsNullOrEmpty(subjectId))
                {
                    // 用户未登录且 prompt=none
                    return RedirectWithError(redirect_uri, state, "login_required", "User is not authenticated");
                }
                // 注意: 实际实现应该检查是否存在有效的 session 且用户已同意
            }

            // prompt=login: 强制重新认证
            if (promptsArray.Contains("login"))
            {
                // 强制重新登录 - 清除现有 subjectId
                subjectId = string.Empty;
            }
        }

        // 检查用户是否已登录
        if (string.IsNullOrEmpty(subjectId))
        {
            // 返回需要登录的提示
            return RedirectWithError(redirect_uri, state, "login_required", "User authentication is required");
        }

        // 检查是否需要 consent (prompt=consent 强制要求)
        var prompts = SplitPrompt(prompt);
        var forceConsent = prompts.Contains("consent", StringComparer.Ordinal);
        var consentAccepted = string.Equals(Request.Query["consent"], "accept", StringComparison.OrdinalIgnoreCase);
        var existingConsent = _consentStore == null ? null : await _consentStore.GetAsync(subjectId, client.ClientId, cancellationToken);
        var existingScopes = existingConsent?.Scopes.ToHashSet(StringComparer.Ordinal) ?? [];
        var hasExistingConsent = existingConsent != null && requestedScopes.All(existingScopes.Contains);
        var needsConsent = forceConsent || (client.RequireConsent && !hasExistingConsent);
        if (needsConsent && !consentAccepted)
        {
            return RedirectWithError(redirect_uri, state, "consent_required", "User consent is required");
        }

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
            RememberConsent = consentAccepted && client.AllowRememberConsent
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
}
