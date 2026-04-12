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

    public ClientAuthenticationService(
        IClientStore clientStore,
        IOptions<IdentityServerOptions> options,
        ILogger<ClientAuthenticationService> logger)
    {
        _clientStore = clientStore;
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

            // 简单比较 (生产环境应使用常量时间比较)
            if (s.Value == secret)
            {
                return true;
            }

            // 支持哈希后的密钥比较
            if (s.Type == "Sha256")
            {
                var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
                if (hash == s.Value)
                {
                    return true;
                }
            }
        }
        return false;
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