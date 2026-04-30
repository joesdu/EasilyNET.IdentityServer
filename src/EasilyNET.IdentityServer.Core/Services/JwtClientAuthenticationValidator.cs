using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Models;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// JWT 客户端认证验证器 (RFC 7523)
/// </summary>
public class JwtClientAuthenticationValidator
{
    private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private readonly ILogger<JwtClientAuthenticationValidator> _logger;
    private readonly HttpClient _httpClient;

    public JwtClientAuthenticationValidator(ILogger<JwtClientAuthenticationValidator> logger, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClient = httpClientFactory.CreateClient("JwksClient");
    }

    /// <summary>
    /// 验证 JWT 客户端断言 (RFC 7523)
    /// </summary>
    public async Task<(bool IsValid, string? ErrorDescription)> ValidateJwtAsync(
        string assertion,
        string assertionType,
        Client client,
        string tokenEndpoint,
        CancellationToken cancellationToken = default)
    {
        // 验证断言类型
        if (assertionType != JwtBearerAssertionType)
        {
            return (false, $"Invalid client_assertion_type. Expected: {JwtBearerAssertionType}");
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();

            // 读取 JWT 而不验证（先检查基本结构）
            if (!handler.CanReadToken(assertion))
            {
                _logger.LogWarning("Cannot read JWT assertion");
                return (false, "Invalid JWT format");
            }

            var jwt = handler.ReadJwtToken(assertion);

            // 验证必需的声明
            var iss = jwt.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
            var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            var aud = jwt.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;
            var exp = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
            var jti = jwt.Claims.FirstOrDefault(c => c.Type == "jti")?.Value;

            // RFC 7523: iss 和 sub 必须等于 client_id
            if (string.IsNullOrEmpty(iss) || iss != client.ClientId)
            {
                _logger.LogWarning("Invalid 'iss' claim. Expected: {ClientId}, Got: {Iss}", client.ClientId, iss);
                return (false, "JWT issuer must be the client_id");
            }

            if (string.IsNullOrEmpty(sub) || sub != client.ClientId)
            {
                _logger.LogWarning("Invalid 'sub' claim. Expected: {ClientId}, Got: {Sub}", client.ClientId, sub);
                return (false, "JWT subject must be the client_id");
            }

            // RFC 7523: aud 必须包含令牌端点 URL
            if (string.IsNullOrEmpty(aud) || !IsValidAudience(aud, tokenEndpoint))
            {
                _logger.LogWarning("Invalid 'aud' claim. Expected: {TokenEndpoint}, Got: {Aud}", tokenEndpoint, aud);
                return (false, "JWT audience must be the token endpoint URL");
            }

            // RFC 7523: exp 必须存在且不能过期
            if (string.IsNullOrEmpty(exp))
            {
                return (false, "JWT must include 'exp' claim");
            }

            // RFC 7523: jti 推荐但不强制
            if (string.IsNullOrEmpty(jti))
            {
                _logger.LogWarning("JWT missing recommended 'jti' claim for replay prevention");
            }

            // 获取客户端的公钥
            var signingKeys = await GetClientSigningKeysAsync(client, cancellationToken);
            if (signingKeys == null || !signingKeys.Any())
            {
                _logger.LogWarning("No signing keys found for client {ClientId}", client.ClientId);
                return (false, "Client has no registered public keys");
            }

            // 验证 JWT 签名
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = client.ClientId,
                ValidateAudience = true,
                ValidAudience = tokenEndpoint,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ClockSkew = TimeSpan.FromMinutes(5), // 允许 5 分钟时钟偏差
                RequireExpirationTime = true,
                RequireSignedTokens = true
            };

            // 限制允许的签名算法 (OAuth 安全最佳实践)
            var allowedAlgorithms = new[] { SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512 };
            if (!string.IsNullOrEmpty(client.TokenEndpointAuthSigningAlg) && !allowedAlgorithms.Contains(client.TokenEndpointAuthSigningAlg))
            {
                _logger.LogWarning("Client specified unsupported signing algorithm: {Alg}", client.TokenEndpointAuthSigningAlg);
                return (false, $"Unsupported signing algorithm: {client.TokenEndpointAuthSigningAlg}");
            }

            if (!string.IsNullOrEmpty(client.TokenEndpointAuthSigningAlg))
            {
                validationParameters.ValidAlgorithms = new[] { client.TokenEndpointAuthSigningAlg };
            }

            // 验证 JWT
            var principal = handler.ValidateToken(assertion, validationParameters, out var validatedToken);

            _logger.LogInformation("Successfully validated JWT assertion for client {ClientId}", client.ClientId);
            return (true, null);
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogWarning("JWT assertion expired for client {ClientId}", client.ClientId);
            return (false, "JWT has expired");
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            _logger.LogWarning("Invalid JWT signature for client {ClientId}", client.ClientId);
            return (false, "Invalid JWT signature");
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "JWT validation failed for client {ClientId}", client.ClientId);
            return (false, $"JWT validation failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating JWT for client {ClientId}", client.ClientId);
            return (false, "JWT validation error");
        }
    }

    /// <summary>
    /// 获取客户端的签名公钥
    /// </summary>
    private async Task<IEnumerable<SecurityKey>?> GetClientSigningKeysAsync(Client client, CancellationToken cancellationToken)
    {
        var keys = new List<SecurityKey>();

        // 1. 从客户端的 JWKS 中获取 (内联)
        if (!string.IsNullOrEmpty(client.Jwks))
        {
            try
            {
                var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(client.Jwks);
                if (jwks?.Keys != null)
                {
                    keys.AddRange(jwks.Keys);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse JWKS for client {ClientId}", client.ClientId);
            }
        }

        // 2. 从 JWKS URI 获取 (远程)
        if (!string.IsNullOrEmpty(client.JwksUri))
        {
            try
            {
                var response = await _httpClient.GetStringAsync(client.JwksUri, cancellationToken);
                var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(response);
                if (jwks?.Keys != null)
                {
                    keys.AddRange(jwks.Keys);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to fetch JWKS from URI {JwksUri} for client {ClientId}",
                    client.JwksUri, client.ClientId);
            }
        }

        return keys.Any() ? keys : null;
    }

    /// <summary>
    /// 验证受众 (aud) 声明
    /// </summary>
    private bool IsValidAudience(string aud, string tokenEndpoint)
    {
        // JWT aud 声明可能包含多个值（空格分隔或数组）
        // RFC 7523: aud 必须包含令牌端点 URL
        var audiences = aud.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return audiences.Any(a => string.Equals(a, tokenEndpoint, StringComparison.OrdinalIgnoreCase));
    }
}
