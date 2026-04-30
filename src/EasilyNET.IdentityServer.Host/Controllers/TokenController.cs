using System.Security.Cryptography;
using System.Text;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Host.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.1 Token Endpoint
/// </summary>
[ApiController]
public class TokenController : ControllerBase
{
    private const string AuthorizationCodeType = "authorization_code";
    private const string ConsumedRefreshTokenType = "consumed_refresh_token";
    private const string IssuedAccessTokenProperty = "issued_access_token";
    private const string IssuedRefreshTokenProperty = "issued_refresh_token";
    private const string RefreshTokenType = "refresh_token";
    private readonly IAuditService _auditService;
    private readonly IClientAuthenticationService _clientAuth;
    private readonly IDPoPService _dpopService;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private readonly ILogger<TokenController> _logger;
    private readonly IPersistedGrantStore _grantStore;
    private readonly IdentityServerOptions _options;
    private readonly ITokenService _tokenService;

    public TokenController(
        IClientAuthenticationService clientAuth,
        IDPoPService dpopService,
        ITokenService tokenService,
        IPersistedGrantStore grantStore,
        IDeviceFlowStore deviceFlowStore,
        IdentityServerOptions options,
        ILogger<TokenController> logger,
        IAuditService auditService)
    {
        _clientAuth = clientAuth;
        _dpopService = dpopService;
        _tokenService = tokenService;
        _grantStore = grantStore;
        _deviceFlowStore = deviceFlowStore;
        _options = options;
        _logger = logger;
        _auditService = auditService;
    }

    /// <summary>
    /// Token 端点
    /// </summary>
    [HttpPost("/connect/token")]
    public async Task<IActionResult> Token(CancellationToken cancellationToken)
    {
        SetSensitiveResponseHeaders();
        var form = await Request.ReadFormAsync(cancellationToken);
        var grantType = form["grant_type"].ToString();
        if (string.IsNullOrEmpty(grantType))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "grant_type is required"));
        }

        // 提取客户端凭据 (支持 Basic Auth 和 POST body)
        var clientId = OAuthRequestHelpers.ResolveClientId(form);
        var (resolvedClientId, clientSecret) = OAuthRequestHelpers.ExtractClientCredentials(Request, form);
        clientId ??= resolvedClientId;
        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest(new TokenErrorResponse("invalid_client", "client_id is required"));
        }

        var endpoint = OAuthRequestHelpers.BuildAbsoluteEndpointUri(Request);

        // 认证客户端
        var authResult = await _clientAuth.AuthenticateClientAsync(new()
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            ClientAssertion = form["client_assertion"].ToString(),
            ClientAssertionType = form["client_assertion_type"].ToString(),
            ClientCertificate = OAuthRequestHelpers.GetClientCertificate(HttpContext),
            GrantType = grantType,
            RedirectUri = form["redirect_uri"].ToString(),
            RequestedEndpoint = endpoint
        }, cancellationToken);
        if (!authResult.IsSuccess)
        {
            return Unauthorized(new TokenErrorResponse(authResult.Error ?? "invalid_client", authResult.ErrorDescription));
        }
        var client = authResult.Client!;
        string? dpopJkt = null;
        var dpopProof = Request.Headers["DPoP"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(dpopProof))
        {
            if (!_options.EnableDpop)
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "DPoP proof is not enabled."));
            }

            var proofValidation = await _dpopService.ValidateTokenRequestAsync(dpopProof, new()
            {
                HttpMethod = Request.Method,
                Htu = endpoint
            }, cancellationToken);
            if (!proofValidation.IsSuccess)
            {
                return BadRequest(new TokenErrorResponse(proofValidation.Error ?? "invalid_dpop_proof", proofValidation.ErrorDescription));
            }

            dpopJkt = proofValidation.Jkt;
        }
        else if (client.RequireDpopProof)
        {
            return BadRequest(new TokenErrorResponse("use_dpop_proof", "This client requires a DPoP proof."));
        }

        var result = grantType switch
        {
            GrantType.ClientCredentials => await HandleClientCredentials(client, form, dpopJkt, cancellationToken),
            GrantType.AuthorizationCode => await HandleAuthorizationCode(client, form, dpopJkt, cancellationToken),
            GrantType.RefreshToken => await HandleRefreshToken(client, form, dpopJkt, cancellationToken),
            "urn:ietf:params:oauth:grant-type:device_code" => await HandleDeviceCode(client, form, dpopJkt, cancellationToken),
            _ => BadRequest(new TokenErrorResponse("unsupported_grant_type", $"Grant type '{grantType}' is not supported"))
        };
        return result;
    }

    private async Task<IActionResult> HandleClientCredentials(Client client, IFormCollection form, string? dpopJkt, CancellationToken ct)
    {
        var scope = form["scope"].ToString();
        var scopes = string.IsNullOrEmpty(scope) ? client.AllowedScopes : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // 验证 scopes
        var validScopes = await ValidateScopes(scopes, client, ct);
        if (validScopes == null)
        {
            await _auditService.LogAuthenticationFailedAsync(client.ClientId, GrantType.ClientCredentials,
                "Invalid scope", GetClientIpAddress(), ct);
            return BadRequest(new TokenErrorResponse("invalid_scope", "One or more requested scopes are not allowed"));
        }
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            DPoPConfirmationJkt = dpopJkt,
            GrantType = GrantType.ClientCredentials,
            Scopes = validScopes
        }, ct);

        // 记录审计日志
        await _auditService.LogTokenIssuedAsync(client.ClientId, null, GrantType.ClientCredentials,
            validScopes, GetClientIpAddress(), ct);

        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IActionResult> HandleAuthorizationCode(Client client, IFormCollection form, string? dpopJkt, CancellationToken ct)
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
        if (grant == null || grant.Type != AuthorizationCodeType || grant.ClientId != client.ClientId)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid authorization code"));
        }

        // 检查过期
        if (grant.ExpirationTime.HasValue && grant.ExpirationTime < DateTime.UtcNow)
        {
            await _grantStore.RemoveAsync(code, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has expired"));
        }

        // PKCE 验证 (OAuth 2.1: 如果授权请求包含code_challenge,则必须验证code_verifier)
        var codeChallenge = grant.Properties.TryGetValue("code_challenge", out var cc) ? cc : null;
        var codeChallengeMethod = grant.Properties.TryGetValue("code_challenge_method", out var ccm) && !string.IsNullOrWhiteSpace(ccm) ? ccm : "plain";
        if (!string.IsNullOrEmpty(codeChallenge))
        {
            // 授权请求包含code_challenge,必须验证code_verifier
            if (string.IsNullOrEmpty(codeVerifier))
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier is required when code_challenge was present"));
            }
            if (!IsValidPkceValue(codeVerifier))
            {
                return BadRequest(new TokenErrorResponse("invalid_request", "code_verifier must be 43-128 characters using RFC 7636 unreserved characters"));
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
        else if (client.RequirePkce || _options.RequirePkce)
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

        if (grant.ConsumedTime.HasValue)
        {
            await RevokeTokensIssuedFromAuthorizationCodeAsync(grant, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has already been used"));
        }

        var originalGrant = await _grantStore.TryConsumeAsync(code, AuthorizationCodeType, client.ClientId, ct);
        if (originalGrant == null)
        {
            var consumedGrant = await _grantStore.GetAsync(code, ct);
            if (consumedGrant?.ConsumedTime.HasValue == true)
            {
                await RevokeTokensIssuedFromAuthorizationCodeAsync(consumedGrant, ct);
            }
            _logger.LogWarning("Concurrency conflict detected for authorization code: {Code}", code);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Authorization code has already been used"));
        }

        // 解析 scopes 和 nonce
        var scopes = (grant.Properties.TryGetValue("scope", out var scopeStr) ? scopeStr : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var nonce = grant.Properties.TryGetValue("nonce", out var n) ? n : null;
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            DPoPConfirmationJkt = dpopJkt,
            GrantType = GrantType.AuthorizationCode,
            Scopes = scopes,
            SubjectId = grant.SubjectId,
            CodeVerifier = codeVerifier,
            Nonce = nonce
        }, ct);
        await StoreRefreshTokenGrantAsync(client, grant.SubjectId, scopes, result, nonce, ct);
        await PersistIssuedTokenReferencesAsync(originalGrant, result, ct);

        // 记录审计日志
        await _auditService.LogAuthorizationCodeExchangedAsync(client.ClientId, grant.SubjectId, GetClientIpAddress(), ct);
        await _auditService.LogTokenIssuedAsync(client.ClientId, grant.SubjectId, GrantType.AuthorizationCode,
            scopes, GetClientIpAddress(), ct);

        return Ok(new TokenSuccessResponse(result));
    }

    private async Task<IActionResult> HandleRefreshToken(Client client, IFormCollection form, string? dpopJkt, CancellationToken ct)
    {
        var refreshToken = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(refreshToken))
        {
            return BadRequest(new TokenErrorResponse("invalid_request", "refresh_token is required"));
        }
        var grant = await _grantStore.GetAsync(refreshToken, ct);
        if (grant != null && IsConsumedRefreshToken(grant, client.ClientId))
        {
            await RevokeRefreshTokenFamilyAsync(grant, ct);
            return BadRequest(new TokenErrorResponse("invalid_grant", "Refresh token reuse detected"));
        }
        if (grant == null || grant.Type != RefreshTokenType || grant.ClientId != client.ClientId)
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

        var originalGrant = await _grantStore.TryConsumeAsync(refreshToken, RefreshTokenType, client.ClientId, ct);
        if (originalGrant == null)
        {
            var consumedGrant = await _grantStore.GetAsync(refreshToken, ct);
            if (IsConsumedRefreshToken(consumedGrant, client.ClientId))
            {
                await RevokeRefreshTokenFamilyAsync(consumedGrant!, ct);
            }
            return BadRequest(new TokenErrorResponse("invalid_grant", "Refresh token reuse detected"));
        }

        var originalScopes = (originalGrant.Properties.TryGetValue("scope", out var originalScopeValue) ? originalScopeValue : null)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? client.AllowedScopes.ToArray();
        var requestedScope = form["scope"].ToString();
        var scopes = string.IsNullOrEmpty(requestedScope) ? originalScopes : requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!IsSubset(scopes, originalScopes))
        {
            return BadRequest(new TokenErrorResponse("invalid_scope", "Requested scope exceeds the originally granted scope"));
        }

        // OAuth 2.1: 公开客户端不应使用刷新令牌轮换
        // 公开客户端使用一次性刷新令牌模式，删除旧令牌但不颁发新令牌
        var isPublicClient = client.ClientType == ClientType.Public || !client.RequireClientSecret;
        if (isPublicClient)
        {
            // 公开客户端：使用一次性刷新令牌，旧令牌会留下已消费标记用于重放检测
            var nonce = originalGrant.Properties.TryGetValue("nonce", out var n) ? n : null;
            var result = await _tokenService.CreateAccessTokenAsync(new()
            {
                Client = client,
                DPoPConfirmationJkt = dpopJkt,
                GrantType = GrantType.RefreshToken,
                Scopes = scopes,
                SubjectId = originalGrant.SubjectId,
                Nonce = nonce
            }, ct);

            // 记录审计日志
            await _auditService.LogRefreshTokenUsedAsync(client.ClientId, originalGrant.SubjectId, false, GetClientIpAddress(), ct);
            await _auditService.LogTokenIssuedAsync(client.ClientId, originalGrant.SubjectId, GrantType.RefreshToken,
                scopes, GetClientIpAddress(), ct);

            await StoreRefreshTokenGrantAsync(client, originalGrant.SubjectId, scopes, result, nonce, ct, GetRefreshTokenFamilyId(originalGrant));
            return Ok(new TokenSuccessResponse(result));
        }

        // 机密客户端：使用标准滑动窗口刷新令牌（轮换机制）
        // Refresh Token 轮换 (OAuth 2.1 要求)
        var refreshNonce = originalGrant.Properties.TryGetValue("nonce", out var rn) ? rn : null;
        var tokenResult = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            DPoPConfirmationJkt = dpopJkt,
            GrantType = GrantType.RefreshToken,
            Scopes = scopes,
            SubjectId = originalGrant.SubjectId,
            Nonce = refreshNonce
        }, ct);

        // 存储新的 Refresh Token
        await StoreRefreshTokenGrantAsync(client, originalGrant.SubjectId, scopes, tokenResult, refreshNonce, ct, GetRefreshTokenFamilyId(originalGrant));

        // 记录审计日志
        await _auditService.LogRefreshTokenUsedAsync(client.ClientId, originalGrant.SubjectId, true, GetClientIpAddress(), ct);
        await _auditService.LogTokenIssuedAsync(client.ClientId, originalGrant.SubjectId, GrantType.RefreshToken,
            scopes, GetClientIpAddress(), ct);

        return Ok(new TokenSuccessResponse(tokenResult));
    }

    private async Task<IActionResult> HandleDeviceCode(Client client, IFormCollection form, string? dpopJkt, CancellationToken ct)
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
        var hashedDeviceCode = DeviceFlowCodeHasher.HashDeviceCode(deviceCode);
        var deviceCodeData = await _deviceFlowStore.FindByDeviceCodeAsync(hashedDeviceCode, ct);
        if (deviceCodeData == null || deviceCodeData.ClientId != client.ClientId)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Invalid device code"));
        }

        // Check expiration
        if (deviceCodeData.ExpirationTime < DateTime.UtcNow)
        {
            await _deviceFlowStore.RemoveAsync(hashedDeviceCode, ct);
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

        // User has authorized - 原子消费设备代码并签发令牌
        var consumedDeviceCode = await _deviceFlowStore.TryConsumeDeviceCodeAsync(hashedDeviceCode, client.ClientId, ct);
        if (consumedDeviceCode == null)
        {
            return BadRequest(new TokenErrorResponse("invalid_grant", "Device code has already been used"));
        }
        var scopes = (deviceCodeData.Properties.TryGetValue("scope", out var scopeStr) ? scopeStr : null)?
                     .Split(' ', StringSplitOptions.RemoveEmptyEntries) ??
                     client.AllowedScopes.ToArray();
        var result = await _tokenService.CreateAccessTokenAsync(new()
        {
            Client = client,
            DPoPConfirmationJkt = dpopJkt,
            GrantType = GrantType.DeviceCode,
            Scopes = scopes,
            SubjectId = deviceCodeData.SubjectId
        }, ct);

        // Clean up
        await _deviceFlowStore.RemoveAsync(hashedDeviceCode, ct);
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

    private Task StoreRefreshTokenGrantAsync(Client client, string? subjectId, IEnumerable<string> scopes, TokenResult result, string? nonce, CancellationToken ct, string? familyId = null)
    {
        if (string.IsNullOrEmpty(result.RefreshToken))
        {
            return Task.CompletedTask;
        }
        familyId ??= Guid.NewGuid().ToString("N");
        var properties = new Dictionary<string, string>
        {
            ["scope"] = string.Join(" ", scopes),
            ["family_id"] = familyId
        };
        if (!string.IsNullOrEmpty(nonce))
        {
            properties["nonce"] = nonce;
        }
        return _grantStore.StoreAsync(new()
        {
            Key = result.RefreshToken,
            Type = RefreshTokenType,
            ClientId = client.ClientId,
            SubjectId = subjectId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(client.RefreshTokenLifetime > 0 ? client.RefreshTokenLifetime : _options.RefreshTokenLifetime),
            Data = "",
            Properties = properties
        }, ct);
    }

    private async Task PersistIssuedTokenReferencesAsync(PersistedGrant originalGrant, TokenResult result, CancellationToken ct)
    {
        var updatedProperties = new Dictionary<string, string>(originalGrant.Properties)
        {
            [IssuedAccessTokenProperty] = result.AccessToken
        };

        if (!string.IsNullOrEmpty(result.RefreshToken))
        {
            updatedProperties[IssuedRefreshTokenProperty] = result.RefreshToken;
        }

        await _grantStore.StoreAsync(new PersistedGrant
        {
            Key = originalGrant.Key,
            Type = originalGrant.Type,
            SubjectId = originalGrant.SubjectId,
            ClientId = originalGrant.ClientId,
            SessionId = originalGrant.SessionId,
            Description = originalGrant.Description,
            CreationTime = originalGrant.CreationTime,
            ExpirationTime = originalGrant.ExpirationTime,
            ConsumedTime = DateTime.UtcNow,
            Data = originalGrant.Data,
            Properties = updatedProperties
        }, ct);
    }

    private static bool IsConsumedRefreshToken(PersistedGrant? grant, string clientId) =>
        grant != null &&
        grant.ClientId == clientId &&
        (grant.Type == ConsumedRefreshTokenType || (grant.Type == RefreshTokenType && grant.ConsumedTime.HasValue));

    private async Task RevokeTokensIssuedFromAuthorizationCodeAsync(PersistedGrant grant, CancellationToken ct)
    {
        if (grant.Properties.TryGetValue(IssuedRefreshTokenProperty, out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken))
        {
            await _grantStore.RemoveAsync(refreshToken, ct);
        }

        if (grant.Properties.TryGetValue(IssuedAccessTokenProperty, out var accessToken) && !string.IsNullOrWhiteSpace(accessToken))
        {
            await _tokenService.RevokeAsync(accessToken, ct);
        }
    }

    private async Task RevokeRefreshTokenFamilyAsync(PersistedGrant reusedGrant, CancellationToken ct)
    {
        var familyId = GetRefreshTokenFamilyId(reusedGrant);
        if (string.IsNullOrEmpty(familyId))
        {
            return;
        }
        var activeGrants = await _grantStore.GetAllAsync(new()
        {
            ClientId = reusedGrant.ClientId,
            SubjectId = reusedGrant.SubjectId,
            Type = RefreshTokenType
        }, ct);
        foreach (var grant in activeGrants.Where(g =>
                     g.Properties.TryGetValue("family_id", out var value) &&
                     string.Equals(value, familyId, StringComparison.Ordinal)))
        {
            await _grantStore.RemoveAsync(grant.Key, ct);
        }
    }

    private static string? GetRefreshTokenFamilyId(PersistedGrant grant) =>
        grant.Properties.TryGetValue("family_id", out var familyId) ? familyId : null;

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

    private static bool IsValidPkceValue(string value) =>
        value.Length is >= 43 and <= 128 && value.All(IsPkceCharacter);

    private static bool IsPkceCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) || value is '-' or '.' or '_' or '~';

    private string? GetClientIpAddress()
    {
        // 优先从 X-Forwarded-For 获取（代理场景）
        var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }
        return HttpContext.Connection.RemoteIpAddress?.ToString();
    }

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

/// <summary>
/// 公开客户端 Token 响应（不包含刷新令牌，OAuth 2.1 规范）
/// </summary>
internal sealed class PublicClientTokenResponse
{
    public string access_token { get; }

    public int expires_in { get; }

    public string? id_token { get; }

    public string? scope { get; }

    public string token_type { get; }

    /// <summary>
    /// 公开客户端不颁发刷新令牌（OAuth 2.1 要求）
    /// </summary>
    public string? refresh_token => null;

    public PublicClientTokenResponse(TokenResult result)
    {
        access_token = result.AccessToken;
        token_type = result.TokenType;
        expires_in = result.ExpiresIn;
        scope = result.Scope;
        id_token = result.IdToken;
    }
}
