using System.Security.Cryptography;
using System.Text;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.1 Token Endpoint
/// </summary>
[ApiController]
public class TokenController : ControllerBase
{
    private readonly IClientAuthenticationService _clientAuth;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private readonly IPersistedGrantStore _grantStore;
    private readonly IdentityServerOptions _options;
    private readonly IResourceStore _resourceStore;
    private readonly ITokenService _tokenService;

    public TokenController(
        IClientAuthenticationService clientAuth,
        ITokenService tokenService,
        IPersistedGrantStore grantStore,
        IResourceStore resourceStore,
        IDeviceFlowStore deviceFlowStore,
        IdentityServerOptions options)
    {
        _clientAuth = clientAuth;
        _tokenService = tokenService;
        _grantStore = grantStore;
        _resourceStore = resourceStore;
        _deviceFlowStore = deviceFlowStore;
        _options = options;
    }

    /// <summary>
    /// Token 端点
    /// </summary>
    [HttpPost("/connect/token")]
    public async Task<IActionResult> Token(CancellationToken cancellationToken)
    {
        var form = await Request.ReadFormAsync(cancellationToken);
        var grantType = form["grant_type"].ToString();
        if (string.IsNullOrEmpty(grantType))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "grant_type is required"));
        }

        // 提取客户端凭据 (支持 Basic Auth 和 POST body)
        var (clientId, clientSecret) = ExtractClientCredentials(form);
        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest(new TokenErrorResponse("invalid_client", "client_id is required"));
        }

        // 认证客户端
        var authResult = await _clientAuth.AuthenticateClientAsync(new()
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            GrantType = grantType
        }, cancellationToken);
        if (!authResult.IsSuccess)
        {
            return Unauthorized(new TokenErrorResponse(authResult.Error ?? "invalid_client", authResult.ErrorDescription));
        }
        var client = authResult.Client!;
        return grantType switch
        {
            GrantType.ClientCredentials                    => await HandleClientCredentials(client, form, cancellationToken),
            GrantType.AuthorizationCode                    => await HandleAuthorizationCode(client, form, cancellationToken),
            GrantType.RefreshToken                         => await HandleRefreshToken(client, form, cancellationToken),
            "urn:ietf:params:oauth:grant-type:device_code" => await HandleDeviceCode(client, form, cancellationToken),
            _                                              => BadRequest(new TokenErrorResponse("unsupported_grant_type", $"Grant type '{grantType}' is not supported"))
        };
    }

    private async Task<IActionResult> HandleClientCredentials(Client client, IFormCollection form, CancellationToken ct)
    {
        var scope = form["scope"].ToString();
        var scopes = string.IsNullOrEmpty(scope) ? client.AllowedScopes : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // 验证 scopes
        var validScopes = await ValidateScopes(scopes, client, ct);
        if (validScopes == null)
        {
            return BadRequest(new TokenErrorResponse("invalid_scope", "One or more requested scopes are not allowed"));
        }
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.ClientCredentials,
            Scopes = validScopes
        }, ct);
        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IActionResult> HandleAuthorizationCode(Client client, IFormCollection form, CancellationToken ct)
    {
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();
        if (string.IsNullOrEmpty(code))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "code is required"));
        }

        // 查找授权码
        var grant = await _grantStore.GetAsync(code, ct);
        if (grant == null || grant.Type != "authorization_code" || grant.ClientId != client.ClientId)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid authorization code"));
        }

        // 检查过期
        if (grant.ExpirationTime.HasValue && grant.ExpirationTime < DateTime.UtcNow)
        {
            await _grantStore.RemoveAsync(code, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has expired"));
        }

        // 检查是否已消费
        if (grant.ConsumedTime.HasValue)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has already been used"));
        }

        // PKCE 验证
        if (client.RequirePkce)
        {
            if (string.IsNullOrEmpty(codeVerifier))
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier is required"));
            }
            var codeChallenge = grant.Properties.TryGetValue("code_challenge", out var cc) ? cc : null;
            var codeChallengeMethod = grant.Properties.TryGetValue("code_challenge_method", out var ccm) ? ccm : "S256";
            if (!ValidatePkce(codeVerifier, codeChallenge, codeChallengeMethod))
            {
                return BadRequest(new TokenErrorResponse("invalid_grant", "PKCE validation failed"));
            }
        }

        // 验证 redirect_uri
        var storedRedirectUri = grant.Properties.TryGetValue("redirect_uri", out var sru) ? sru : null;
        if (!string.IsNullOrEmpty(storedRedirectUri) && storedRedirectUri != redirectUri)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "redirect_uri mismatch"));
        }

        // 消费授权码
        await _grantStore.RemoveAsync(code, ct);

        // 解析 scopes
        var scopes = (grant.Properties.TryGetValue("scope", out var scopeStr) ? scopeStr : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.AuthorizationCode,
            Scopes = scopes,
            SubjectId = grant.SubjectId,
            CodeVerifier = codeVerifier
        }, ct);
        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IActionResult> HandleRefreshToken(Client client, IFormCollection form, CancellationToken ct)
    {
        var refreshToken = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(refreshToken))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "refresh_token is required"));
        }
        var grant = await _grantStore.GetAsync(refreshToken, ct);
        if (grant == null || grant.Type != "refresh_token" || grant.ClientId != client.ClientId)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid refresh token"));
        }
        if (grant.ExpirationTime.HasValue && grant.ExpirationTime < DateTime.UtcNow)
        {
            await _grantStore.RemoveAsync(refreshToken, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Refresh token has expired"));
        }

        // Refresh Token 轮换 (OAuth 2.1 要求)
        await _grantStore.RemoveAsync(refreshToken, ct);
        var scopes = (grant.Properties.TryGetValue("scope", out var scopeStr2) ? scopeStr2 : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.RefreshToken,
            Scopes = scopes,
            SubjectId = grant.SubjectId
        }, ct);

        // 存储新的 Refresh Token
        if (result.RefreshToken != null)
        {
            await _grantStore.StoreAsync(new()
            {
                Key = result.RefreshToken,
                Type = "refresh_token",
                ClientId = client.ClientId,
                SubjectId = grant.SubjectId,
                CreationTime = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.AddSeconds(_options.RefreshTokenLifetime),
                Data = "",
                Properties = new Dictionary<string, string>
                {
                    ["scope"] = string.Join(" ", scopes)
                }
            }, ct);
        }
        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IActionResult> HandleDeviceCode(Client client, IFormCollection form, CancellationToken ct)
    {
        var deviceCode = form["device_code"].ToString();
        if (string.IsNullOrEmpty(deviceCode))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "device_code is required"));
        }
        if (!client.AllowedGrantTypes.Contains(GrantType.DeviceCode))
        {
            return BadRequest(new TokenErrorResponse("unauthorized_client", "Client is not authorized for device_code grant"));
        }
        var deviceCodeData = await _deviceFlowStore.FindByDeviceCodeAsync(deviceCode, ct);
        if (deviceCodeData == null || deviceCodeData.ClientId != client.ClientId)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid device code"));
        }

        // Check expiration
        if (deviceCodeData.ExpirationTime < DateTime.UtcNow)
        {
            await _deviceFlowStore.RemoveAsync(deviceCode, ct);
            return BadRequest(new TokenErrorResponse("expired_token", "Device code has expired"));
        }

        // Check if already consumed
        if (deviceCodeData.Data == "consumed")
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Device code has already been used"));
        }

        // Check if user has authorized (SubjectId set)
        if (string.IsNullOrEmpty(deviceCodeData.SubjectId))
        {
            // RFC 8628 Section 3.5 - authorization_pending
            return BadRequest(new TokenErrorResponse("authorization_pending", "The user has not yet authorized this device"));
        }

        // User has authorized - consume the device code and issue tokens
        await _deviceFlowStore.ConsumeDeviceCodeAsync(deviceCode, ct);
        var scopes = (deviceCodeData.Properties.TryGetValue("scope", out var scopeStr) ? scopeStr : null)?
                     .Split(' ', StringSplitOptions.RemoveEmptyEntries) ??
                     client.AllowedScopes.ToArray();
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.DeviceCode,
            Scopes = scopes,
            SubjectId = deviceCodeData.SubjectId
        }, ct);

        // Clean up
        await _deviceFlowStore.RemoveAsync(deviceCode, ct);
        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IEnumerable<string>?> ValidateScopes(IEnumerable<string> requestedScopes, Client client, CancellationToken ct)
    {
        var allowed = client.AllowedScopes.ToHashSet();
        var requested = requestedScopes.ToList();
        foreach (var scope in requested)
        {
            if (!allowed.Contains(scope))
            {
                return null;
            }
        }
        return requested;
    }

    private (string? clientId, string? clientSecret) ExtractClientCredentials(IFormCollection form)
    {
        // 优先从 Authorization header 提取 (Basic Auth)
        var authHeader = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var encoded = authHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':', 2);
            if (parts.Length == 2)
            {
                return (Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1]));
            }
        }

        // 从 POST body 提取
        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }

    private static bool ValidatePkce(string codeVerifier, string? codeChallenge, string? method)
    {
        if (string.IsNullOrEmpty(codeChallenge))
        {
            return false;
        }
        if (method == "S256")
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            var computed = Base64UrlEncode(hash);
            return computed == codeChallenge;
        }

        // plain 方法 (OAuth 2.1 不推荐)
        return codeVerifier == codeChallenge;
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input)
               .TrimEnd('=')
               .Replace('+', '-')
               .Replace('/', '_');
}

/// <summary>
/// Token 错误响应
/// </summary>
internal sealed class TokenErrorResponse
{
    public TokenErrorResponse(string error, string? errorDescription = null)
    {
        this.error = error;
        error_description = errorDescription;
    }

    public string error { get; }

    public string? error_description { get; }
}

/// <summary>
/// Token 成功响应
/// </summary>
internal sealed class TokenSuccessResponse
{
    public TokenSuccessResponse(TokenResult result)
    {
        access_token = result.AccessToken;
        token_type = result.TokenType;
        expires_in = result.ExpiresIn;
        refresh_token = result.RefreshToken;
        scope = result.Scope;
    }

    public string access_token { get; }

    public string token_type { get; }

    public int expires_in { get; }

    public string? refresh_token { get; }

    public string? scope { get; }
}