using System.Security.Cryptography;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Logging;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 授权服务实现
/// </summary>
public class AuthorizationService : IAuthorizationService
{
    private readonly IClientStore _clientStore;
    private readonly IUserConsentStore? _consentStore;
    private readonly IPersistedGrantStore _grantStore;
    private readonly ILogger<AuthorizationService> _logger;
    private readonly IdentityServerOptions _options;
    private readonly IResourceStore _resourceStore;

    public AuthorizationService(
        IClientStore clientStore,
        IResourceStore resourceStore,
        IPersistedGrantStore grantStore,
        IdentityServerOptions options,
        ILogger<AuthorizationService> logger,
        IUserConsentStore? consentStore = null)
    {
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _grantStore = grantStore;
        _options = options;
        _logger = logger;
        _consentStore = consentStore;
    }

    /// <inheritdoc />
    public async Task<AuthorizationResult> ValidateAuthorizationRequestAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        // 验证 response_type (OAuth 2.1 只允许 code)
        if (request.ResponseType != "code")
        {
            return new()
            {
                IsSuccess = false,
                Error = "unsupported_response_type",
                ErrorDescription = "Only 'code' response type is supported"
            };
        }

        // 查找客户端
        var client = await _clientStore.FindClientByIdAsync(request.ClientId, cancellationToken);
        if (client == null || !client.Enabled)
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_client",
                ErrorDescription = "Client not found or disabled"
            };
        }

        // 验证 grant type
        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode))
        {
            return new()
            {
                IsSuccess = false,
                Error = "unauthorized_client",
                ErrorDescription = "Client is not authorized for authorization_code grant"
            };
        }

        // 严格匹配 redirect_uri (OAuth 2.1 要求)
        if (!client.RedirectUris.Contains(request.RedirectUri))
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "redirect_uri is not registered"
            };
        }

        // PKCE 验证 (OAuth 2.1 强制)
        if ((_options.RequirePkce || client.RequirePkce) && string.IsNullOrEmpty(request.CodeChallenge))
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "code_challenge is required"
            };
        }

        // 验证 scopes
        var allowedScopes = client.AllowedScopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                return new()
                {
                    IsSuccess = false,
                    Error = "invalid_scope",
                    ErrorDescription = $"Scope '{scope}' is not allowed"
                };
            }
        }
        var requestId = Guid.NewGuid().ToString("N");
        return new()
        {
            IsSuccess = true,
            RequestId = requestId,
            Client = client,
            NeedsConsent = client.RequireConsent,
            NeedsLogin = true // 由调用方判断用户是否已登录
        };
    }

    /// <inheritdoc />
    public async Task<ApprovedAuthorizationResult> ApproveAuthorizationRequestAsync(ApprovedAuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        // 生成授权码
        var codeBytes = RandomNumberGenerator.GetBytes(32);
        var authorizationCode = Convert.ToBase64String(codeBytes)
                                       .TrimEnd('=')
                                       .Replace('+', '-')
                                       .Replace('/', '_');

        // 存储 consent (如果需要)
        if (request.RememberConsent && _consentStore != null)
        {
            await _consentStore.StoreAsync(new()
            {
                SubjectId = request.SubjectId,
                ClientId = request.RequestId, // 这里应该是 clientId，需要从上下文获取
                Scopes = request.Scopes,
                CreationTime = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.AddSeconds(_options.ConsentLifetime)
            }, cancellationToken);
        }
        return new()
        {
            IsSuccess = true,
            AuthorizationCode = authorizationCode
        };
    }

    /// <inheritdoc />
    public async Task DenyAuthorizationRequestAsync(string requestId, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Authorization request {RequestId} denied", requestId);
        await Task.CompletedTask;
    }
}