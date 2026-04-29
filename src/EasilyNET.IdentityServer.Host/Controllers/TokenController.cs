using System.Security.Cryptography;
using System.Text;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.1 Token Endpoint
/// </summary>
[ApiController]
public class TokenController : ControllerBase
{
    private readonly IClientAuthenticationService _clientAuth;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private readonly ILogger<TokenController> _logger;
    private readonly IPersistedGrantStore _grantStore;
    private readonly IdentityServerOptions _options;
    private readonly ITokenService _tokenService;

    public TokenController(
        IClientAuthenticationService clientAuth,
        ITokenService tokenService,
        IPersistedGrantStore grantStore,
        IDeviceFlowStore deviceFlowStore,
        IdentityServerOptions options,
        ILogger<TokenController> logger)
    {
        _clientAuth = clientAuth;
        _tokenService = tokenService;
        _grantStore = grantStore;
        _deviceFlowStore = deviceFlowStore;
        _options = options;
        _logger = logger;
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
        var result = grantType switch
        {
            GrantType.ClientCredentials                    => await HandleClientCredentials(client, form, cancellationToken),
            GrantType.AuthorizationCode                    => await HandleAuthorizationCode(client, form, cancellationToken),
            GrantType.RefreshToken                         => await HandleRefreshToken(client, form, cancellationToken),
            "urn:ietf:params:oauth:grant-type:device_code" => await HandleDeviceCode(client, form, cancellationToken),
            _                                              => BadRequest(new TokenErrorResponse("unsupported_grant_type", $"Grant type '{grantType}' is not supported"))
        };
        SetSensitiveResponseHeaders();
        return result;
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

        // OAuth 2.1 要求：授权码只能使用一次 (RFC 6749 Section 4.1.2)
        // 检查是否已消费或已过期 - 使用原子操作防止竞态条件
        if (grant.ConsumedTime.HasValue)
        {
            // 已被消费 - 清除任何残留记录并拒绝
            await _grantStore.RemoveAsync(code, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has already been used"));
        }

        // 检查过期
        if (grant.ExpirationTime.HasValue && grant.ExpirationTime < DateTime.UtcNow)
        {
            await _grantStore.RemoveAsync(code, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has expired"));
        }

        // PKCE 验证 (OAuth 2.1: 如果授权请求包含code_challenge,则必须验证code_verifier)
        var codeChallenge = grant.Properties.TryGetValue("code_challenge", out var cc) ? cc : null;
        var codeChallengeMethod = grant.Properties.TryGetValue("code_challenge_method", out var ccm) ? ccm : "S256";
        if (!string.IsNullOrEmpty(codeChallenge))
        {
            // 授权请求包含code_challenge,必须验证code_verifier
            if (string.IsNullOrEmpty(codeVerifier))
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier is required when code_challenge was present"));
            }
            if (!ValidatePkce(codeVerifier, codeChallenge, codeChallengeMethod))
            {
                return BadRequest(new TokenErrorResponse("invalid_grant", "PKCE validation failed"));
            }
        }
        else if (!string.IsNullOrEmpty(codeVerifier))
        {
            // 如果授权请求没有code_challenge但token请求包含code_verifier,拒绝
            return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier must not be included when no code_challenge was used"));
        }
        else if (client.RequirePkce)
        {
            // 客户端强制要求PKCE但授权请求没有code_challenge
            return BadRequest(new TokenErrorResponse("invalid_request", "code_challenge is required for this client"));
        }

        // 验证 redirect_uri (RFC 6749 / OAuth 2.1)
        // 如果授权码绑定了特定的 redirect_uri，token 请求必须提供相同值
        var storedRedirectUri = grant.Properties.TryGetValue("redirect_uri", out var sru) ? sru : null;
        if (!string.IsNullOrEmpty(storedRedirectUri))
        {
            // 授权码绑定到特定 URI，token 请求必须提供并匹配
            if (string.IsNullOrEmpty(redirectUri))
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "redirect_uri is required because the authorization code was bound to a specific redirect URI"));
            }
            if (!string.Equals(storedRedirectUri, redirectUri, StringComparison.Ordinal))
            {
                return BadRequest(new TokenErrorResponse("invalid_grant", "redirect_uri mismatch"));
            }
        }

        // 消费授权码 - 使用原子操作防止竞态条件
        // 先标记为已消费，再删除
        var consumedGrant = new PersistedGrant
        {
            Key = grant.Key,
            Type = grant.Type,
            SubjectId = grant.SubjectId,
            ClientId = grant.ClientId,
            SessionId = grant.SessionId,
            Description = grant.Description,
            CreationTime = grant.CreationTime,
            ExpirationTime = grant.ExpirationTime,
            ConsumedTime = DateTime.UtcNow,
            Data = grant.Data,
            Properties = grant.Properties
        };
        try
        {
            await _grantStore.StoreAsync(consumedGrant, ct);
            await _grantStore.RemoveAsync(code, ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // 并发冲突 - 授权码已被其他请求使用
            _logger.LogWarning("Concurrency conflict detected for authorization code: {Code}", code);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has already been used"));
        }

        // 解析 scopes 和 nonce
        var scopes = (grant.Properties.TryGetValue("scope", out var scopeStr) ? scopeStr : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var nonce = grant.Properties.TryGetValue("nonce", out var n) ? n : null;
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.AuthorizationCode,
            Scopes = scopes,
            SubjectId = grant.SubjectId,
            CodeVerifier = codeVerifier,
            Nonce = nonce
        }, ct);
        await StoreRefreshTokenGrantAsync(client, grant.SubjectId, scopes, result, nonce, ct);
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

        // 检查绝对生命周期 (OAuth 2.1 滑动窗口过期)
        if (_options.EnableAbsoluteRefreshTokenLifetime)
        {
            var absoluteExpiration = grant.CreationTime.AddSeconds(_options.AbsoluteRefreshTokenLifetime);
            if (absoluteExpiration < DateTime.UtcNow)
            {
                await _grantStore.RemoveAsync(refreshToken, ct);
                return BadRequest(new TokenErrorResponse("invalid_grant", "Refresh token has exceeded its maximum lifetime"));
            }
        }

        var originalScopes = (grant.Properties.TryGetValue("scope", out var originalScopeValue) ? originalScopeValue : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var requestedScope = form["scope"].ToString();
        var scopes = string.IsNullOrEmpty(requestedScope) ? originalScopes : requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!IsSubset(scopes, originalScopes))
        {
            return BadRequest(new TokenErrorResponse("invalid_scope", "Requested scope exceeds the originally granted scope"));
        }

        // Refresh Token 轮换 (OAuth 2.1 要求)
        await _grantStore.RemoveAsync(refreshToken, ct);
        var nonce = grant.Properties.TryGetValue("nonce", out var n) ? n : null;
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            GrantType = GrantType.RefreshToken,
            Scopes = scopes,
            SubjectId = grant.SubjectId,
            Nonce = nonce
        }, ct);

        // 存储新的 Refresh Token
        await StoreRefreshTokenGrantAsync(client, grant.SubjectId, scopes, result, nonce, ct);
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

        var pollEvaluation = await EvaluateDevicePollingAsync(deviceCodeData, ct);
        if (pollEvaluation != null)
        {
            return pollEvaluation;
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

    private static bool IsSubset(IEnumerable<string> requestedScopes, IEnumerable<string> grantedScopes)
    {
        var granted = grantedScopes.ToHashSet(StringComparer.Ordinal);
        foreach (var scope in requestedScopes)
        {
            if (!granted.Contains(scope))
            {
                return false;
            }
        }
        return true;
    }

    private async Task<IActionResult?> EvaluateDevicePollingAsync(DeviceCodeData deviceCodeData, CancellationToken ct)
    {
        var interval = ReadDevicePollingInterval(deviceCodeData);
        if (deviceCodeData.Properties.TryGetValue("last_poll_utc", out var lastPollValue) &&
            DateTime.TryParse(lastPollValue, null, System.Globalization.DateTimeStyles.RoundtripKind, out var lastPollUtc))
        {
            var elapsed = DateTime.UtcNow - lastPollUtc;
            if (elapsed < TimeSpan.FromSeconds(interval))
            {
                var increasedInterval = interval + DeviceAuthorizationController.SlowDownStepSeconds;
                await PersistDevicePollingStateAsync(deviceCodeData, DateTime.UtcNow, increasedInterval, ct);
                return BadRequest(new TokenErrorResponse("slow_down", "The client is polling too quickly"));
            }
        }

        await PersistDevicePollingStateAsync(deviceCodeData, DateTime.UtcNow, interval, ct);
        return null;
    }

    private async Task PersistDevicePollingStateAsync(DeviceCodeData deviceCodeData, DateTime lastPollUtc, int intervalSeconds, CancellationToken ct)
    {
        var updatedProperties = new Dictionary<string, string>(deviceCodeData.Properties)
        {
            ["last_poll_utc"] = lastPollUtc.ToString("O"),
            ["interval_seconds"] = intervalSeconds.ToString()
        };
        await _deviceFlowStore.StoreAsync(new DeviceCodeData
        {
            Code = deviceCodeData.Code,
            UserCode = deviceCodeData.UserCode,
            SubjectId = deviceCodeData.SubjectId,
            ClientId = deviceCodeData.ClientId,
            Description = deviceCodeData.Description,
            CreationTime = deviceCodeData.CreationTime,
            ExpirationTime = deviceCodeData.ExpirationTime,
            Data = deviceCodeData.Data,
            Properties = updatedProperties
        }, ct);
    }

    private static int ReadDevicePollingInterval(DeviceCodeData deviceCodeData)
    {
        return deviceCodeData.Properties.TryGetValue("interval_seconds", out var intervalValue) &&
               int.TryParse(intervalValue, out var parsedInterval) &&
               parsedInterval > 0
            ? parsedInterval
            : DeviceAuthorizationController.DefaultPollingIntervalSeconds;
    }

    private Task StoreRefreshTokenGrantAsync(Client client, string? subjectId, IEnumerable<string> scopes, TokenResult result, string? nonce, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(result.RefreshToken))
        {
            return Task.CompletedTask;
        }
        var properties = new Dictionary<string, string>
        {
            ["scope"] = string.Join(" ", scopes)
        };
        if (!string.IsNullOrEmpty(nonce))
        {
            properties["nonce"] = nonce;
        }
        return _grantStore.StoreAsync(new()
        {
            Key = result.RefreshToken,
            Type = "refresh_token",
            ClientId = client.ClientId,
            SubjectId = subjectId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(client.RefreshTokenLifetime > 0 ? client.RefreshTokenLifetime : _options.RefreshTokenLifetime),
            Data = "",
            Properties = properties
        }, ct);
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

    private void SetSensitiveResponseHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }
}

/// <summary>
/// Token 错误响应 (RFC 6749 Section 5.2)
/// </summary>
internal sealed class TokenErrorResponse
{
    public string error { get; }

    public string? error_description { get; }

    /// <summary>
    /// 可选的错误URI，提供更多错误信息
    /// </summary>
    public string? error_uri { get; }

    /// <summary>
    /// 与uthorization Server关联的唯一请求ID
    /// </summary>
    public string? state { get; }

    public TokenErrorResponse(string error, string? errorDescription = null, string? errorUri = null, string? state = null)
    {
        this.error = error;
        error_description = errorDescription;
        this.error_uri = errorUri;
        this.state = state;
    }
}

/// <summary>
/// Token 成功响应
/// </summary>
internal sealed class TokenSuccessResponse
{
    public string access_token { get; }

    public int expires_in { get; }

    /// <summary>
    /// Identity Token (OIDC)
    /// </summary>
    public string? id_token { get; }

    public string? refresh_token { get; }

    public string? scope { get; }

    public string token_type { get; }

    public TokenSuccessResponse(TokenResult result)
    {
        access_token = result.AccessToken;
        token_type = result.TokenType;
        expires_in = result.ExpiresIn;
        refresh_token = result.RefreshToken;
        scope = result.Scope;
        id_token = result.IdToken;
    }
}
