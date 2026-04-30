using System.Security.Cryptography;
using System.Text;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 客户端认证服务实现
/// </summary>
public class ClientAuthenticationService : IClientAuthenticationService
{
    private readonly IClientStore _clientStore;
    private readonly ILogger<ClientAuthenticationService> _logger;
    private readonly IOptions<IdentityServerOptions> _options;
    private readonly JwtClientAuthenticationValidator? _jwtValidator;

    public ClientAuthenticationService(
        IClientStore clientStore,
        IOptions<IdentityServerOptions> options,
        ILogger<ClientAuthenticationService> logger,
        JwtClientAuthenticationValidator? jwtValidator = null)
    {
        _clientStore = clientStore;
        _options = options;
        _logger = logger;
        _jwtValidator = jwtValidator;
    }

    /// <inheritdoc />
    public async Task<ClientAuthenticationResult> AuthenticateClientAsync(ClientAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        var client = await _clientStore.FindClientByIdAsync(request.ClientId, cancellationToken);
        if (client == null)
        {
            _logger.LogWarning("Client not found: {ClientId}", request.ClientId);
            return new()
            {
                IsSuccess = false,
                Error = "invalid_client",
                ErrorDescription = "Client not found"
            };
        }
        if (!client.Enabled)
        {
            _logger.LogWarning("Client is disabled: {ClientId}", request.ClientId);
            return new()
            {
                IsSuccess = false,
                Error = "invalid_client",
                ErrorDescription = "Client is disabled"
            };
        }

        // 验证客户端类型和授权类型
        var allowedGrantTypes = client.AllowedGrantTypes.ToHashSet();
        var normalizedGrantType = NormalizeGrantType(request.GrantType);
        if (!allowedGrantTypes.Contains(normalizedGrantType))
        {
            _logger.LogWarning("Grant type not allowed: {GrantType}", request.GrantType);
            return new()
            {
                IsSuccess = false,
                Error = "unsupported_grant_type",
                ErrorDescription = "Grant type not allowed for this client"
            };
        }
        if (normalizedGrantType == GrantType.ClientCredentials && client.ClientType != ClientType.Confidential)
        {
            _logger.LogWarning("Public client attempted to use client_credentials: {ClientId}", request.ClientId);
            return new()
            {
                IsSuccess = false,
                Error = "unauthorized_client",
                ErrorDescription = "client_credentials grant requires a confidential client"
            };
        }

        // 确定客户端认证方法
        var authMethod = DetermineAuthMethod(request, client);

        // 根据认证方法验证客户端
        switch (authMethod)
        {
            case "private_key_jwt":
                // RFC 7523: Private Key JWT 客户端认证
                if (_jwtValidator == null)
                {
                    _logger.LogWarning("JWT validator not configured but client uses private_key_jwt");
                    return new()
                    {
                        IsSuccess = false,
                        Error = "invalid_client",
                        ErrorDescription = "JWT authentication not supported"
                    };
                }
                if (string.IsNullOrEmpty(request.ClientAssertion) || string.IsNullOrEmpty(request.ClientAssertionType))
                {
                    _logger.LogWarning("Client assertion required for private_key_jwt");
                    return new()
                    {
                        IsSuccess = false,
                        Error = "invalid_client",
                        ErrorDescription = "client_assertion and client_assertion_type are required"
                    };
                }
                if (string.IsNullOrEmpty(request.TokenEndpoint))
                {
                    _logger.LogWarning("Token endpoint required for JWT validation");
                    return new()
                    {
                        IsSuccess = false,
                        Error = "invalid_client",
                        ErrorDescription = "Token endpoint required for validation"
                    };
                }
                var (isValid, errorDesc) = await _jwtValidator.ValidateJwtAsync(
                    request.ClientAssertion,
                    request.ClientAssertionType,
                    client,
                    request.TokenEndpoint,
                    cancellationToken);
                if (!isValid)
                {
                    _logger.LogWarning("JWT assertion validation failed: {Error}", errorDesc);
                    return new()
                    {
                        IsSuccess = false,
                        Error = "invalid_client",
                        ErrorDescription = errorDesc
                    };
                }
                break;

            case "client_secret_basic":
            case "client_secret_post":
                // 传统的客户端密钥认证
                if (client.ClientType == ClientType.Confidential && client.RequireClientSecret)
                {
                    if (string.IsNullOrEmpty(request.ClientSecret))
                    {
                        _logger.LogWarning("Client secret required but not provided");
                        return new()
                        {
                            IsSuccess = false,
                            Error = "invalid_client",
                            ErrorDescription = "Client secret is required"
                        };
                    }
                    if (!ValidateClientSecret(client.ClientSecrets, request.ClientSecret))
                    {
                        _logger.LogWarning("Invalid client secret");
                        return new()
                        {
                            IsSuccess = false,
                            Error = "invalid_client",
                            ErrorDescription = "Invalid client credentials"
                        };
                    }
                }
                break;

            case "none":
                // 公开客户端，无需认证
                if (client.ClientType != ClientType.Public && client.RequireClientSecret)
                {
                    _logger.LogWarning("Public authentication method used for confidential client");
                    return new()
                    {
                        IsSuccess = false,
                        Error = "invalid_client",
                        ErrorDescription = "Confidential client requires authentication"
                    };
                }
                break;

            default:
                _logger.LogWarning("Unsupported authentication method: {Method}", authMethod);
                return new()
                {
                    IsSuccess = false,
                    Error = "invalid_client",
                    ErrorDescription = $"Authentication method '{authMethod}' is not supported"
                };
        }

        return new()
        {
            IsSuccess = true,
            Client = client
        };
    }

    /// <summary>
    /// 确定客户端使用的认证方法
    /// </summary>
    private static string DetermineAuthMethod(ClientAuthenticationRequest request, Client client)
    {
        // 如果客户端指定了认证方法，使用它
        if (!string.IsNullOrEmpty(client.TokenEndpointAuthMethod))
        {
            return client.TokenEndpointAuthMethod;
        }

        // 否则根据请求参数推断
        if (!string.IsNullOrEmpty(request.ClientAssertion))
        {
            return "private_key_jwt";
        }

        if (!string.IsNullOrEmpty(request.ClientSecret))
        {
            return "client_secret_post"; // 默认使用 POST
        }

        // 公开客户端
        return "none";
    }

    private static bool ValidateClientSecret(IEnumerable<Secret> secrets, string secret)
    {
        foreach (var s in secrets)
        {
            if (s.Expiration.HasValue && s.Expiration < DateTime.UtcNow)
            {
                continue; // 跳过过期的密钥
            }

            // 使用常量时间比较防止时序攻击 (OAuth 2.1 安全要求)
            var isMatch = s.Type switch
            {
                // 支持明文凭据（仅用于开发/测试，不推荐生产环境）
                "PlainText" => FixedTimeEquals(s.Value, secret),
                // 默认使用 SHA256 哈希比较（推荐）
                _ => SecretHasher.VerifySecret(secret, s.Value)
            };
            if (isMatch)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// 常量时间字符串比较，防止时序攻击
    /// </summary>
    private static bool FixedTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
        {
            // 为了保持常量时间，即使长度不同也要进行比较
            var dummyA = new byte[Math.Max(a.Length, b.Length)];
            var dummyB = new byte[Math.Max(a.Length, b.Length)];
            CryptographicOperations.FixedTimeEquals(dummyA, dummyB);
            return false;
        }
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }

    /// <summary>
    /// Normalize URN-form grant types to short form for matching against client configuration.
    /// RFC 8628 uses "urn:ietf:params:oauth:grant-type:device_code" in token requests.
    /// </summary>
    private static string NormalizeGrantType(string grantType)
    {
        return grantType switch
        {
            "urn:ietf:params:oauth:grant-type:device_code" => GrantType.DeviceCode,
            _                                              => grantType
        };
    }
}
