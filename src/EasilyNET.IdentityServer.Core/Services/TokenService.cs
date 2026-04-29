using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Claim = System.Security.Claims.Claim;
using TokenValidationResult = EasilyNET.IdentityServer.Abstractions.Services.TokenValidationResult;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// JWT Token 服务实现
/// </summary>
public class TokenService : ITokenService, IDisposable
{
    private readonly ILogger<TokenService> _logger;
    private readonly IdentityServerOptions _options;
    private readonly ConcurrentDictionary<string, DateTime> _revokedTokens = new(StringComparer.Ordinal);
    private readonly ISerializationService _serialization;
    private readonly ISigningService _signingService;
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    // 撤销令牌保留时间 (24小时)
    private static readonly TimeSpan RevokedTokenRetentionPeriod = TimeSpan.FromHours(24);

    public TokenService(
        IOptions<IdentityServerOptions> options,
        ILogger<TokenService> logger,
        ISerializationService serialization,
        ISigningService signingService)
    {
        _options = options.Value;
        _logger = logger;
        _serialization = serialization;
        _signingService = signingService;

        // 每小时清理过期的撤销记录
        _cleanupTimer = new Timer(
            _ => CleanupExpiredRevokedTokens(),
            null,
            TimeSpan.FromHours(1),
            TimeSpan.FromHours(1));
    }

    /// <inheritdoc />
    public async Task<TokenResult> CreateAccessTokenAsync(TokenRequest request, CancellationToken cancellationToken = default)
    {
        var signingKey = await _signingService.GetSigningKeyAsync(cancellationToken);

        // 验证签名算法
        if (!_options.AllowedAccessTokenSigningAlgorithms.Contains(signingKey.Algorithm))
        {
            throw new InvalidOperationException($"Signing algorithm '{signingKey.Algorithm}' is not allowed for access tokens. Allowed: [{string.Join(", ", _options.AllowedAccessTokenSigningAlgorithms)}]");
        }

        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(_options.AccessTokenLifetime);
        var scopes = request.Scopes.Distinct(StringComparer.Ordinal).ToList();
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new("client_id", request.Client.ClientId)
        };
        if (!string.IsNullOrEmpty(request.SubjectId))
        {
            claims.Add(new(JwtRegisteredClaimNames.Sub, request.SubjectId));
        }
        foreach (var scope in scopes)
        {
            claims.Add(new("scope", scope));
        }

        // 添加请求的 Claims
        if (request.Claims != null)
        {
            foreach (var claim in request.Claims)
            {
                claims.Add(new(claim.Key, claim.Value.ToString() ?? ""));
            }
        }
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new(claims),
            IssuedAt = now,
            Expires = expires,
            Issuer = _options.Issuer,
            Audience = string.Join(" ", scopes), // 使用 scopes 作为 audience
            SigningCredentials = signingKey.Credentials
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        // 生成 id_token (OIDC)
        var idTokenRequest = new TokenRequest
        {
            AuthorizationCode = request.AuthorizationCode,
            Claims = request.Claims,
            Client = request.Client,
            CodeVerifier = request.CodeVerifier,
            GrantType = request.GrantType,
            Nonce = request.Nonce,
            RefreshToken = request.RefreshToken,
            Scopes = scopes,
            SubjectId = request.SubjectId
        };
        var idToken = await CreateIdentityTokenAsync(idTokenRequest, cancellationToken);

        var refreshToken = ShouldIssueRefreshToken(request)
                               ? Guid.NewGuid().ToString("N")
                               : null;
        return new()
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = _options.AccessTokenLifetime,
            Scope = string.Join(" ", scopes),
            RefreshToken = refreshToken,
            IdToken = idToken
        };
    }

    /// <inheritdoc />
    public async Task<string?> CreateIdentityTokenAsync(TokenRequest request, CancellationToken cancellationToken = default)
    {
        var scopes = request.Scopes as IEnumerable<string> ?? request.Scopes;
        if (!scopes.Contains("openid"))
        {
            return null; // 只有包含 openid scope 时才返回 id_token
        }

        var signingKey = await _signingService.GetSigningKeyAsync(cancellationToken);

        // 验证签名算法
        if (!_options.AllowedIdentityTokenSigningAlgorithms.Contains(signingKey.Algorithm))
        {
            throw new InvalidOperationException($"Signing algorithm '{signingKey.Algorithm}' is not allowed for identity tokens. Allowed: [{string.Join(", ", _options.AllowedIdentityTokenSigningAlgorithms)}]");
        }

        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(_options.AccessTokenLifetime);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Sub, request.SubjectId ?? ""),
            new("client_id", request.Client.ClientId),
            new("auth_time", EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64)
        };

        // 添加 nonce (OIDC 必需)
        if (!string.IsNullOrEmpty(request.Nonce))
        {
            claims.Add(new("nonce", request.Nonce));
        }

        // 添加请求的 Claims
        if (request.Claims != null)
        {
            foreach (var claim in request.Claims)
            {
                claims.Add(new(claim.Key, claim.Value.ToString() ?? ""));
            }
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new(claims),
            IssuedAt = now,
            Expires = expires,
            Issuer = _options.Issuer,
            Audience = request.Client.ClientId, // id_token 的 audience 是 client_id
            SigningCredentials = signingKey.Credentials
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <inheritdoc />
    public Task<string> CreateAuthorizationCodeAsync(AuthorizationCodeRequest request, CancellationToken cancellationToken = default)
    {
        var code = Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N")));
        return Task.FromResult(code);
    }

    /// <inheritdoc />
    public async Task<TokenValidationResult> ValidateAccessTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            if (_revokedTokens.ContainsKey(token))
            {
                return new()
                {
                    IsValid = false,
                    Error = "invalid_token",
                    ErrorDescription = "Token has been revoked"
                };
            }
            var signingKey = await _signingService.GetSigningKeyAsync(cancellationToken);
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey.Key,
                ValidateIssuer = true,
                ValidIssuer = _options.Issuer,
                ValidateAudience = false, // 不验证 audience,因为我们使用 scopes
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            var clientId = principal.FindFirst("client_id")?.Value;
            var subjectId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var scopes = principal.FindAll("scope").Select(x => x.Value).Distinct(StringComparer.Ordinal).ToArray();
            DateTime? expirationTime = validatedToken.ValidTo == DateTime.MinValue
                                           ? null
                                           : validatedToken.ValidTo;
            return new()
            {
                IsValid = true,
                ClientId = clientId,
                SubjectId = subjectId,
                Scopes = scopes,
                ExpirationTime = expirationTime
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation failed");
            return new()
            {
                IsValid = false,
                Error = "invalid_token",
                ErrorDescription = "Token validation failed"
            };
        }
    }

    /// <inheritdoc />
    public Task RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        _revokedTokens[token] = DateTime.UtcNow;
        return Task.CompletedTask;
    }

    private static bool ShouldIssueRefreshToken(TokenRequest request) =>
        request.Client.AllowedGrantTypes.Contains(GrantType.RefreshToken) &&
        request.GrantType is GrantType.AuthorizationCode or GrantType.RefreshToken or GrantType.DeviceCode;

    /// <summary>
    /// 清理过期的撤销令牌记录，防止内存泄漏
    /// </summary>
    private void CleanupExpiredRevokedTokens()
    {
        try
        {
            var cutoff = DateTime.UtcNow.Subtract(RevokedTokenRetentionPeriod);
            var expiredKeys = _revokedTokens
                .Where(kvp => kvp.Value < cutoff)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredKeys)
            {
                _revokedTokens.TryRemove(key, out _);
            }

            if (expiredKeys.Count > 0)
            {
                _logger.LogDebug("Cleaned up {Count} expired revoked tokens", expiredKeys.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up expired revoked tokens");
        }
    }

    /// <summary>
    /// 销毁清理资源
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanupTimer?.Dispose();
    }
}

/// <summary>
/// Token 响应生成器
/// </summary>
public interface ITokenResponseGenerator
{
    Task<TokenResult> GenerateAsync(TokenRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// 默认 Token 响应生成器
/// </summary>
public class DefaultTokenResponseGenerator : ITokenResponseGenerator
{
    private readonly ITokenService _tokenService;

    public DefaultTokenResponseGenerator(ITokenService tokenService)
    {
        _tokenService = tokenService;
    }

    public Task<TokenResult> GenerateAsync(TokenRequest request, CancellationToken cancellationToken = default) => _tokenService.CreateAccessTokenAsync(request, cancellationToken);
}

/// <summary>
/// 签名服务接口
/// </summary>
public interface ISigningService
{
    Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取RSA公钥用于JWKS暴露
    /// </summary>
    RSA? GetPublicKey();
}

/// <summary>
/// 签名密钥结果
/// </summary>
public class SigningKeyResult
{
    public SigningCredentials Credentials { get; init; } = default!;

    public SecurityKey Key { get; init; } = default!;

    public string? KeyId { get; init; }

    /// <summary>
    /// 签名算法
    /// </summary>
    public string Algorithm { get; init; } = "RS256";
}

/// <summary>
/// 默认签名服务 (开发环境使用)
/// </summary>
public class DefaultSigningService : ISigningService
{
    private readonly IdentityServerOptions _options;
    private SigningCredentials? _cachedCredentials;
    private RSA? _cachedRsa;
    private RsaSecurityKey? _cachedKey;

    public DefaultSigningService(IOptions<IdentityServerOptions> options)
    {
        _options = options.Value;
    }

    public Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedKey == null)
        {
            // 使用RSA进行签名,支持JWKS公开
            _cachedRsa = RSA.Create(2048);
            var parameters = _cachedRsa.ExportParameters(false);
            _cachedKey = new RsaSecurityKey(parameters)
            {
                KeyId = "rsa-key-1"
            };
            _cachedCredentials = new(_cachedKey, SecurityAlgorithms.RsaSha256);
        }
        return Task.FromResult(new SigningKeyResult
        {
            Key = _cachedKey,
            Credentials = _cachedCredentials!,
            KeyId = _cachedKey.KeyId,
            Algorithm = SecurityAlgorithms.RsaSha256
        });
    }

    /// <summary>
    /// 获取RSA公钥用于JWKS暴露
    /// </summary>
    public RSA? GetPublicKey() => _cachedRsa;

    /// <summary>
    /// 销毁密钥资源
    /// </summary>
    public void Dispose()
    {
        _cachedRsa?.Dispose();
    }
}
