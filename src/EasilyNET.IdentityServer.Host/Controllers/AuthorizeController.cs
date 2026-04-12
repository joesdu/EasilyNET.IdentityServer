using System.Security.Cryptography;
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
    private readonly IClientStore _clientStore;
    private readonly IPersistedGrantStore _grantStore;
    private readonly IdentityServerOptions _options;
    private readonly IResourceStore _resourceStore;
    private readonly ITokenService _tokenService;

    public AuthorizeController(
        IClientStore clientStore,
        IResourceStore resourceStore,
        ITokenService tokenService,
        IPersistedGrantStore grantStore,
        IdentityServerOptions options)
    {
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _tokenService = tokenService;
        _grantStore = grantStore;
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
        // 验证 response_type
        if (response_type != "code")
        {
            return BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response type is supported (OAuth 2.1)" });
        }

        // 验证客户端
        if (string.IsNullOrEmpty(client_id))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }
        var client = await _clientStore.FindClientByIdAsync(client_id, cancellationToken);
        if (client == null || !client.Enabled)
        {
            return BadRequest(new { error = "invalid_client", error_description = "Client not found or disabled" });
        }

        // 验证 grant type
        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
        {
            return BadRequest(new { error = "unauthorized_client", error_description = "Client is not authorized for authorization_code grant" });
        }

        // 验证 redirect_uri (严格匹配 - OAuth 2.1 要求)
        if (string.IsNullOrEmpty(redirect_uri))
        {
            return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
        }
        if (!client.RedirectUris.Contains(redirect_uri))
        {
            return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is not registered" });
        }

        // PKCE 验证 (OAuth 2.1 强制要求)
        if (_options.RequirePkce || client.RequirePkce)
        {
            if (string.IsNullOrEmpty(code_challenge))
            {
                return RedirectWithError(redirect_uri, state, "invalid_request", "code_challenge is required (PKCE)");
            }

            // OAuth 2.1 只允许 S256
            if (!string.IsNullOrEmpty(code_challenge_method) && code_challenge_method != "S256")
            {
                if (!_options.AllowPlainTextPkce)
                {
                    return RedirectWithError(redirect_uri, state, "invalid_request", "Only S256 code_challenge_method is supported");
                }
            }
        }

        // state 参数 (OAuth 2.1 强烈推荐)
        if (string.IsNullOrEmpty(state))
        {
            return RedirectWithError(redirect_uri, state, "invalid_request", "state parameter is required");
        }

        // 验证 scopes
        var requestedScopes = string.IsNullOrEmpty(scope)
                                  ? client.AllowedScopes.ToList()
                                  : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var allowedScopes = client.AllowedScopes.ToHashSet();
        foreach (var s in requestedScopes)
        {
            if (!allowedScopes.Contains(s))
            {
                return RedirectWithError(redirect_uri, state, "invalid_scope", $"Scope '{s}' is not allowed");
            }
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

        // 生成授权码
        var authCode = GenerateAuthorizationCode();

        // 存储授权码
        var properties = new Dictionary<string, string>
        {
            ["redirect_uri"] = redirect_uri,
            ["scope"] = string.Join(" ", requestedScopes),
            ["nonce"] = nonce ?? ""
        };
        if (!string.IsNullOrEmpty(code_challenge))
        {
            properties["code_challenge"] = code_challenge;
            properties["code_challenge_method"] = code_challenge_method ?? "S256";
        }
        await _grantStore.StoreAsync(new()
        {
            Key = authCode,
            Type = "authorization_code",
            ClientId = client.ClientId,
            SubjectId = subjectId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(_options.AuthorizationCodeLifetime),
            Data = "",
            Properties = properties
        }, cancellationToken);

        // 重定向回客户端
        var redirectUrl = BuildRedirectUrl(redirect_uri, authCode, state);
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
        return Redirect(url);
    }

    private static string BuildRedirectUrl(string redirectUri, string code, string? state)
    {
        var separator = redirectUri.Contains('?') ? '&' : '?';
        var url = $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrEmpty(state))
        {
            url += $"&state={Uri.EscapeDataString(state)}";
        }
        return url;
    }

    private static string GenerateAuthorizationCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
                      .TrimEnd('=')
                      .Replace('+', '-')
                      .Replace('/', '_');
    }
}