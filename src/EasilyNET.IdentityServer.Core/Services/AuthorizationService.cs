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
    private static readonly string[] SupportedPromptValues = ["none", "login", "consent", "select_account"];
    private readonly IAuthorizationRequestContextService _authorizationRequestContextService;
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
        IAuthorizationRequestContextService authorizationRequestContextService,
        IdentityServerOptions options,
        ILogger<AuthorizationService> logger,
        IUserConsentStore? consentStore = null)
    {
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _grantStore = grantStore;
        _authorizationRequestContextService = authorizationRequestContextService;
        _options = options;
        _logger = logger;
        _consentStore = consentStore;
    }

    /// <inheritdoc />
    public async Task<AuthorizationResult> ValidateAuthorizationRequestAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        var prompts = ParsePromptValues(request.Prompt);
        var unsupportedPrompts = prompts.Where(prompt => !SupportedPromptValues.Contains(prompt, StringComparer.Ordinal)).ToArray();
        if (unsupportedPrompts.Length > 0)
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = $"Unsupported prompt value(s): {string.Join(", ", unsupportedPrompts)}"
            };
        }

        if (prompts.Contains("none", StringComparer.Ordinal) && prompts.Length > 1)
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "prompt=none must not be combined with other prompt values"
            };
        }

        if (request.MaxAge is < 0)
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "max_age must be greater than or equal to 0"
            };
        }

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

        if (prompts.Length > 0 && client.AuthorizationPromptTypes.Any())
        {
            var allowedPrompts = client.AuthorizationPromptTypes.Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
            var disallowedPrompts = prompts.Where(prompt => !allowedPrompts.Contains(prompt)).ToArray();
            if (disallowedPrompts.Length > 0)
            {
                return new()
                {
                    IsSuccess = false,
                    Error = "invalid_request",
                    ErrorDescription = $"Client does not allow prompt value(s): {string.Join(", ", disallowedPrompts)}"
                };
            }
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

        // OAuth 2.1 要求精确字符串匹配。唯一例外是原生应用回环 IP 重定向 URI，
        // 规范要求授权服务器允许请求时使用任意端口。
        if (!ValidateRedirectUri(client.RedirectUris, request.RedirectUri))
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
        if (!string.IsNullOrEmpty(request.CodeChallengeMethod) && request.CodeChallengeMethod != "S256")
        {
            var plainPkceAllowed = _options.AllowPlainTextPkce && client.AllowPlainTextPkce;
            if (!plainPkceAllowed)
            {
                return new()
                {
                    IsSuccess = false,
                    Error = "invalid_request",
                    ErrorDescription = "Only S256 code_challenge_method is supported"
                };
            }
        }

        // 验证 scopes
        var requestedScopes = request.Scopes.ToArray();
        var enabledScopes = (await _resourceStore.FindEnabledScopesAsync(cancellationToken)).Select(x => x.Name)
            .Concat((await _resourceStore.FindEnabledIdentityResourcesAsync(cancellationToken)).Where(x => x.ShowInDiscoveryDocument).Select(x => x.Name))
            .ToHashSet(StringComparer.Ordinal);
        var allowedScopes = client.AllowedScopes.ToHashSet();
        foreach (var scope in requestedScopes)
        {
            if (!allowedScopes.Contains(scope) || !enabledScopes.Contains(scope))
            {
                return new()
                {
                    IsSuccess = false,
                    Error = "invalid_scope",
                    ErrorDescription = $"Scope '{scope}' is not allowed"
                };
            }
        }
        var effectiveRequestedScopes = requestedScopes.Length == 0 ? client.AllowedScopes.ToArray() : requestedScopes;
        var requestId = Guid.NewGuid().ToString("N");
        await _authorizationRequestContextService.StoreAsync(new AuthorizationRequestContext
        {
            RequestId = requestId,
            ClientId = client.ClientId,
            ClientName = client.ClientName,
            ClientUri = client.ClientUri,
            LogoUri = client.LogoUri,
            RedirectUri = request.RedirectUri,
            RequestedScopes = effectiveRequestedScopes,
            PendingConsentScopes = effectiveRequestedScopes,
            State = request.State,
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            Prompt = request.Prompt,
            LoginHint = request.LoginHint,
            IdentityProviderRestrictions = client.IdentityProviderRestrictions.ToArray(),
            MaxAge = request.MaxAge,
            RequiresConsent = client.RequireConsent,
            RememberConsentAllowed = client.AllowRememberConsent && _options.AllowRememberConsent,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(Math.Max(client.AuthorizationCodeLifetime > 0 ? client.AuthorizationCodeLifetime : _options.AuthorizationCodeLifetime, 300))
        }, cancellationToken);

        return new()
        {
            IsSuccess = true,
            RequestId = requestId,
            Client = client,
            NeedsConsent = client.RequireConsent,
            NeedsLogin = true // 由调用方判断用户是否已登录
        };
    }

    private static string[] ParsePromptValues(string? prompt) =>
        string.IsNullOrWhiteSpace(prompt)
            ? []
            : prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

    /// <inheritdoc />
    public async Task<ApprovedAuthorizationResult> ApproveAuthorizationRequestAsync(ApprovedAuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        var requestContext = await _authorizationRequestContextService.GetAsync(request.RequestId, cancellationToken);
        if (requestContext == null)
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "Authorization request context was not found or has expired"
            };
        }

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

        if (!string.Equals(requestContext.ClientId, request.ClientId, StringComparison.Ordinal) ||
            !string.Equals(requestContext.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            return new()
            {
                IsSuccess = false,
                Error = "invalid_request",
                ErrorDescription = "Authorization request context does not match the approval request"
            };
        }

        // 生成授权码
        var codeBytes = RandomNumberGenerator.GetBytes(32);
        var authorizationCode = Convert.ToBase64String(codeBytes)
                                       .TrimEnd('=')
                                       .Replace('+', '-')
                                       .Replace('/', '_');
        var scopes = request.Scopes.ToArray();

        await _grantStore.StoreAsync(new()
        {
            Key = authorizationCode,
            Type = "authorization_code",
            ClientId = client.ClientId,
            SubjectId = request.SubjectId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(client.AuthorizationCodeLifetime > 0 ? client.AuthorizationCodeLifetime : _options.AuthorizationCodeLifetime),
            Data = string.Empty,
            Properties = new Dictionary<string, string>
            {
                ["redirect_uri"] = request.RedirectUri,
                ["scope"] = string.Join(" ", scopes),
                ["nonce"] = request.Nonce ?? string.Empty,
                ["code_challenge"] = request.CodeChallenge ?? string.Empty,
                ["code_challenge_method"] = request.CodeChallengeMethod ?? "S256"
            }
        }, cancellationToken);

        // 存储 consent (如果需要)
        if (request.RememberConsent && _consentStore != null)
        {
            await _consentStore.StoreAsync(new()
            {
                SubjectId = request.SubjectId,
                ClientId = client.ClientId,
                Scopes = scopes,
                CreationTime = DateTime.UtcNow,
                ExpirationTime = DateTime.UtcNow.AddSeconds(_options.ConsentLifetime)
            }, cancellationToken);
        }

        await _authorizationRequestContextService.RemoveAsync(request.RequestId, cancellationToken);
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
        await _authorizationRequestContextService.RemoveAsync(requestId, cancellationToken);
    }

    /// <summary>
    /// 验证 redirect_uri，支持回环 IP 重定向 URI 的端口可变逻辑
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 规范要求精确字符串匹配；原生应用回环 IP 重定向 URI 可在请求时使用任意端口。
    /// </remarks>
    private static bool ValidateRedirectUri(IEnumerable<string> registeredUris, string requestedUri)
    {
        // 首先尝试精确匹配
        if (registeredUris.Any(uri => string.Equals(uri, requestedUri, StringComparison.Ordinal)))
        {
            return true;
        }

        if (IsLoopbackIpRedirectUri(requestedUri, out var requestedUriWithoutPort))
        {
            return registeredUris.Any(uri =>
                IsLoopbackIpRedirectUri(uri, out var registeredUriWithoutPort) &&
                string.Equals(registeredUriWithoutPort, requestedUriWithoutPort, StringComparison.Ordinal));
        }

        return false;
    }

    /// <summary>
    /// 检查 URI 是否为允许端口可变的回环 IP 重定向 URI
    /// </summary>
    private static bool IsLoopbackIpRedirectUri(string uri, out string uriWithoutPort)
    {
        uriWithoutPort = string.Empty;
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
            return false;

        if (parsedUri.Scheme != "http" ||
            !System.Net.IPAddress.TryParse(parsedUri.Host, out var address) ||
            !System.Net.IPAddress.IsLoopback(address))
        {
            return false;
        }

        var builder = new UriBuilder(parsedUri) { Port = -1 };
        uriWithoutPort = builder.Uri.AbsoluteUri;
        return true;
    }
}
