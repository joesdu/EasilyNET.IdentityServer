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
    private readonly IJwtClientAuthenticationValidator _jwtClientAuthenticationValidator;
    private readonly ILogger<ClientAuthenticationService> _logger;
    private readonly IMtlsClientAuthenticationValidator _mtlsClientAuthenticationValidator;
    private readonly IOptions<IdentityServerOptions> _options;

    public ClientAuthenticationService(
        IClientStore clientStore,
        IJwtClientAuthenticationValidator jwtClientAuthenticationValidator,
        IMtlsClientAuthenticationValidator mtlsClientAuthenticationValidator,
        IOptions<IdentityServerOptions> options,
        ILogger<ClientAuthenticationService> logger)
    {
        _clientStore = clientStore;
        _jwtClientAuthenticationValidator = jwtClientAuthenticationValidator;
        _mtlsClientAuthenticationValidator = mtlsClientAuthenticationValidator;
        _options = options;
        _logger = logger;
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

        var tokenEndpointAuthMethod = ResolveTokenEndpointAuthMethod(client);
        if (string.Equals(tokenEndpointAuthMethod, "private_key_jwt", StringComparison.Ordinal))
        {
            var validation = await _jwtClientAuthenticationValidator.ValidateAsync(client, request, cancellationToken);
            if (!validation.IsSuccess)
            {
                return new()
                {
                    IsSuccess = false,
                    Error = validation.Error,
                    ErrorDescription = validation.ErrorDescription
                };
            }
            return new()
            {
                IsSuccess = true,
                Client = client
            };
        }

        if (string.Equals(tokenEndpointAuthMethod, "tls_client_auth", StringComparison.Ordinal) ||
            string.Equals(tokenEndpointAuthMethod, "self_signed_tls_client_auth", StringComparison.Ordinal))
        {
            var validation = await _mtlsClientAuthenticationValidator.ValidateAsync(client, request, cancellationToken);
            if (!validation.IsSuccess)
            {
                return new()
                {
                    IsSuccess = false,
                    Error = validation.Error,
                    ErrorDescription = validation.ErrorDescription
                };
            }
            return new()
            {
                IsSuccess = true,
                Client = client
            };
        }

        if (string.Equals(tokenEndpointAuthMethod, "none", StringComparison.Ordinal) || !client.RequireClientSecret)
        {
            return new()
            {
                IsSuccess = true,
                Client = client
            };
        }

        // 验证客户端 Secret (仅对机密客户端)
        if (client.ClientType == ClientType.Confidential)
        {
            if (client.RequireClientSecret)
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
        }
        return new()
        {
            IsSuccess = true,
            Client = client
        };
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
            _ => grantType
        };
    }

    private static string ResolveTokenEndpointAuthMethod(Client client)
    {
        if (!string.IsNullOrWhiteSpace(client.TokenEndpointAuthMethod))
        {
            return client.TokenEndpointAuthMethod;
        }

        if (client.ClientType == ClientType.Public || !client.RequireClientSecret)
        {
            return "none";
        }

        return "client_secret_basic";
    }
}
