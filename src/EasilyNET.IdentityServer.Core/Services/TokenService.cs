using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
public class TokenService : ITokenService
{
    private readonly ILogger<TokenService> _logger;
    private readonly IdentityServerOptions _options;
    private readonly ConcurrentDictionary<string, DateTime> _revokedTokens = new(StringComparer.Ordinal);
    private readonly ISerializationService _serialization;
    private readonly ISigningService _signingService;

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
    }

    /// <inheritdoc />
    public async Task<TokenResult> CreateAccessTokenAsync(TokenRequest request, CancellationToken cancellationToken = default)
    {
        var signingKey = await _signingService.GetSigningKeyAsync(cancellationToken);
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(_options.AccessTokenLifetime);
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
        foreach (var scope in request.Scopes.Distinct(StringComparer.Ordinal))
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
            Audience = string.Join(" ", request.Scopes), // 使用 scopes 作为 audience
            SigningCredentials = signingKey.Credentials
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);
        var refreshToken = ShouldIssueRefreshToken(request)
                               ? Guid.NewGuid().ToString("N")
                               : null;
        return new()
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = _options.AccessTokenLifetime,
            Scope = string.Join(" ", request.Scopes),
            RefreshToken = refreshToken
        };
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
}

/// <summary>
/// 签名密钥结果
/// </summary>
public class SigningKeyResult
{
    public SigningCredentials Credentials { get; init; } = default!;

    public SecurityKey Key { get; init; } = default!;

    public string? KeyId { get; init; }
}

/// <summary>
/// 默认签名服务 (开发环境使用)
/// </summary>
public class DefaultSigningService : ISigningService
{
    private readonly IOptions<IdentityServerOptions> _options;
    private SigningCredentials? _cachedCredentials;
    private SecurityKey? _cachedKey;

    public DefaultSigningService(IOptions<IdentityServerOptions> options)
    {
        _options = options;
    }

    public Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedKey == null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Convert.ToBase64String(Guid.NewGuid().ToByteArray()) +
                                                                      Convert.ToBase64String(Guid.NewGuid().ToByteArray())));
            _cachedKey = key;
            _cachedCredentials = new(key, SecurityAlgorithms.HmacSha256);
        }
        return Task.FromResult(new SigningKeyResult
        {
            Key = _cachedKey,
            Credentials = _cachedCredentials!,
            KeyId = "default-key"
        });
    }
}
