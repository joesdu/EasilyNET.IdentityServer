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
    private readonly IdentityServerOptions _options;

    public AuthorizeController(
        IAuthorizationService authorizationService,
        IdentityServerOptions options)
    {
        _authorizationService = authorizationService;
        _options = options;
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
        if (string.IsNullOrEmpty(client_id))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }
        if (string.IsNullOrEmpty(redirect_uri))
        {
            return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
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

        // 在实际应用中，这里应该检查用户是否已登录
        // 如果未登录，重定向到登录页面
        // 如果需要 consent，重定向到 consent 页面
        // 这里简化处理：假设用户已登录，SubjectId 从 header 或 query 获取
        var subjectId = Request.Headers["X-Subject-Id"].ToString();
        if (string.IsNullOrEmpty(subjectId))
        {
            subjectId = Request.Query["subject_id"].ToString();
        }
        if (string.IsNullOrEmpty(subjectId))
        {
            // 返回需要登录的提示
            return Unauthorized(new
            {
                error = "login_required",
                error_description = "User authentication is required. Provide X-Subject-Id header or subject_id query parameter.",
                authorize_url = Request.Path.Value,
                client_id,
                redirect_uri,
                scope = string.Join(" ", requestedScopes),
                state
            });
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
            RememberConsent = false
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
}
