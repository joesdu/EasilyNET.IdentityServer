using System.Security.Cryptography;
using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// RFC 7591 动态客户端注册服务
/// </summary>
public sealed class DynamicClientRegistrationService : IDynamicClientRegistrationService
{
    private const string InvalidClientMetadata = "invalid_client_metadata";
    private readonly IClientStore _clientStore;
    private readonly ILogger<DynamicClientRegistrationService> _logger;
    private readonly IdentityServerOptions _options;
    private readonly IResourceStore _resourceStore;

    public DynamicClientRegistrationService(
        IClientStore clientStore,
        IResourceStore resourceStore,
        IOptions<IdentityServerOptions> options,
        ILogger<DynamicClientRegistrationService> logger)
    {
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<DynamicClientRegistrationResult> RegisterClientAsync(DynamicClientRegistrationRequest request, string? initialAccessToken, CancellationToken cancellationToken = default)
    {
        if (!_options.EnableDynamicClientRegistration)
        {
            return Failure(404, "unsupported_endpoint", "Dynamic client registration is disabled.");
        }

        var initialAccessTokenValidation = ValidateInitialAccessToken(initialAccessToken);
        if (!initialAccessTokenValidation.IsSuccess)
        {
            return initialAccessTokenValidation;
        }

        var validation = await ValidateRequestAsync(request, cancellationToken);
        if (!validation.IsSuccess)
        {
            return validation;
        }

        var authMethod = ResolveTokenEndpointAuthMethod(request);
        var issueClientSecret = authMethod is "client_secret_basic" or "client_secret_post";
        var rawClientSecret = issueClientSecret ? GenerateRandomHandle(32) : null;
        var scopes = ParseScope(request.Scope);
        var grantTypes = ResolveGrantTypes(request);
        var responseTypes = ResolveResponseTypes(request, grantTypes);
        var clientId = await GenerateUniqueClientIdAsync(cancellationToken);
        var properties = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["registration_client_name"] = request.ClientName ?? string.Empty
        };

        if (!string.IsNullOrWhiteSpace(request.PolicyUri))
        {
            properties["policy_uri"] = request.PolicyUri;
        }
        if (!string.IsNullOrWhiteSpace(request.TosUri))
        {
            properties["tos_uri"] = request.TosUri;
        }
        if (!string.IsNullOrWhiteSpace(request.SoftwareStatement))
        {
            properties["software_statement"] = request.SoftwareStatement;
        }

        var client = new Client
        {
            ClientId = clientId,
            ClientName = request.ClientName,
            ClientType = authMethod == "none" ? ClientType.Public : ClientType.Confidential,
            AllowedGrantTypes = grantTypes,
            AllowedResponseTypes = responseTypes,
            RedirectUris = request.RedirectUris,
            AllowedScopes = scopes,
            ClientSecrets = rawClientSecret == null
                ? []
                : [new Secret { Value = SecretHasher.HashSecret(rawClientSecret), Type = "SharedSecret", Description = "Dynamic client registration secret" }],
            RequireClientSecret = issueClientSecret,
            TokenEndpointAuthMethod = authMethod,
            Jwks = request.Jwks?.GetRawText(),
            JwksUri = request.JwksUri,
            TlsClientAuthSubjectDn = request.TlsClientAuthSubjectDn,
            TlsClientAuthThumbprint = request.TlsClientAuthThumbprint,
            RequireDpopProof = request.RequireDpopProof ?? false,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            Contacts = request.Contacts,
            PolicyUri = request.PolicyUri,
            TosUri = request.TosUri,
            RequirePkce = grantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal),
            RequireConsent = false,
            Enabled = true,
            Properties = properties
        };

        try
        {
            await _clientStore.CreateClientAsync(client, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist dynamically registered client {ClientId}", clientId);
            return Failure(500, "server_error", "Failed to persist dynamic client registration.");
        }

        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new DynamicClientRegistrationResult
        {
            IsSuccess = true,
            StatusCode = 201,
            Document = new DynamicClientRegistrationDocument
            {
                ClientId = clientId,
                ClientSecret = rawClientSecret,
                ClientIdIssuedAt = issuedAt,
                ClientSecretExpiresAt = rawClientSecret == null ? 0 : 0,
                RedirectUris = request.RedirectUris,
                GrantTypes = grantTypes.ToArray(),
                ResponseTypes = responseTypes.ToArray(),
                Scope = scopes.Length == 0 ? null : string.Join(" ", scopes),
                TokenEndpointAuthMethod = authMethod,
                ClientName = request.ClientName,
                ClientUri = request.ClientUri,
                LogoUri = request.LogoUri,
                Contacts = request.Contacts,
                PolicyUri = request.PolicyUri,
                TosUri = request.TosUri,
                JwksUri = request.JwksUri,
                Jwks = request.Jwks,
                TlsClientAuthSubjectDn = request.TlsClientAuthSubjectDn,
                TlsClientAuthThumbprint = request.TlsClientAuthThumbprint,
                RequireDpopProof = request.RequireDpopProof ?? false,
                SoftwareStatement = request.SoftwareStatement
            }
        };
    }

    private DynamicClientRegistrationResult ValidateInitialAccessToken(string? initialAccessToken)
    {
        if (!_options.RequireInitialAccessTokenForDynamicClientRegistration)
        {
            if (!string.IsNullOrWhiteSpace(_options.DynamicClientRegistrationInitialAccessToken) &&
                !string.IsNullOrWhiteSpace(initialAccessToken) &&
                !FixedTimeEquals(_options.DynamicClientRegistrationInitialAccessToken, initialAccessToken))
            {
                return Failure(401, "invalid_token", "The supplied initial access token is invalid.");
            }
            return SuccessPlaceholder();
        }

        if (string.IsNullOrWhiteSpace(initialAccessToken) ||
            string.IsNullOrWhiteSpace(_options.DynamicClientRegistrationInitialAccessToken) ||
            !FixedTimeEquals(_options.DynamicClientRegistrationInitialAccessToken, initialAccessToken))
        {
            return Failure(401, "invalid_token", "A valid initial access token is required.");
        }

        return SuccessPlaceholder();
    }

    private async Task<DynamicClientRegistrationResult> ValidateRequestAsync(DynamicClientRegistrationRequest request, CancellationToken cancellationToken)
    {
        var authMethod = ResolveTokenEndpointAuthMethod(request);
        var grantTypes = ResolveGrantTypes(request);
        var responseTypes = ResolveResponseTypes(request, grantTypes);

        if (!SupportedAuthMethods.Contains(authMethod, StringComparer.Ordinal))
        {
            return Failure(400, InvalidClientMetadata, $"Unsupported token_endpoint_auth_method '{authMethod}'.");
        }

        if (grantTypes.Count == 0)
        {
            return Failure(400, InvalidClientMetadata, "At least one grant type is required.");
        }

        foreach (var grantType in grantTypes)
        {
            if (!SupportedGrantTypes.Contains(grantType, StringComparer.Ordinal))
            {
                return Failure(400, InvalidClientMetadata, $"Unsupported grant type '{grantType}'.");
            }
        }

        if (grantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal) && request.RedirectUris.Length == 0)
        {
            return Failure(400, InvalidClientMetadata, "redirect_uris is required for authorization_code clients.");
        }

        foreach (var redirectUri in request.RedirectUris)
        {
            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
            {
                return Failure(400, InvalidClientMetadata, $"Invalid redirect_uri '{redirectUri}'.");
            }

            var isLoopback = uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase);
            if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !(isLoopback && uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
            {
                return Failure(400, InvalidClientMetadata, $"redirect_uri '{redirectUri}' must use https unless it is a loopback redirect.");
            }
        }

        if (grantTypes.Contains(GrantType.ClientCredentials, StringComparer.Ordinal) && authMethod == "none")
        {
            return Failure(400, InvalidClientMetadata, "client_credentials requires client authentication.");
        }

        if (authMethod == "private_key_jwt" && string.IsNullOrWhiteSpace(request.JwksUri) && request.Jwks is null)
        {
            return Failure(400, InvalidClientMetadata, "private_key_jwt clients must provide jwks or jwks_uri.");
        }

        if ((authMethod == "tls_client_auth" || authMethod == "self_signed_tls_client_auth") &&
            string.IsNullOrWhiteSpace(request.TlsClientAuthSubjectDn) &&
            string.IsNullOrWhiteSpace(request.TlsClientAuthThumbprint))
        {
            return Failure(400, InvalidClientMetadata, "mTLS clients must provide tls_client_auth_subject_dn or tls_client_auth_thumbprint.");
        }

        if (!string.IsNullOrWhiteSpace(request.JwksUri) && request.Jwks is not null)
        {
            return Failure(400, InvalidClientMetadata, "jwks and jwks_uri cannot both be supplied.");
        }

        foreach (var responseType in responseTypes)
        {
            if (!string.Equals(responseType, "code", StringComparison.Ordinal))
            {
                return Failure(400, InvalidClientMetadata, $"Unsupported response type '{responseType}'.");
            }
        }

        var allowedScopes = (await _resourceStore.FindEnabledScopesAsync(cancellationToken))
            .Select(scope => scope.Name)
            .Concat((await _resourceStore.FindEnabledIdentityResourcesAsync(cancellationToken)).Select(resource => resource.Name))
            .ToHashSet(StringComparer.Ordinal);

        foreach (var scope in ParseScope(request.Scope))
        {
            if (!allowedScopes.Contains(scope))
            {
                return Failure(400, InvalidClientMetadata, $"Unsupported scope '{scope}'.");
            }
        }

        return SuccessPlaceholder();
    }

    private async Task<string> GenerateUniqueClientIdAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var candidate = GenerateRandomHandle(24);
            if (await _clientStore.FindClientByIdAsync(candidate, cancellationToken) == null)
            {
                return candidate;
            }
        }
    }

    private static List<string> ResolveGrantTypes(DynamicClientRegistrationRequest request)
    {
        if (request.GrantTypes.Length > 0)
        {
            return request.GrantTypes
                .Select(NormalizeGrantType)
                .Distinct(StringComparer.Ordinal)
                .ToList();
        }

        return request.RedirectUris.Length > 0
            ? [GrantType.AuthorizationCode]
            : [GrantType.ClientCredentials];
    }

    private static List<string> ResolveResponseTypes(DynamicClientRegistrationRequest request, IReadOnlyCollection<string> grantTypes)
    {
        if (request.ResponseTypes.Length > 0)
        {
            return request.ResponseTypes.Distinct(StringComparer.Ordinal).ToList();
        }

        return grantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal) ? ["code"] : [];
    }

    private static string[] ParseScope(string? scope) =>
        string.IsNullOrWhiteSpace(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                   .Distinct(StringComparer.Ordinal)
                   .ToArray();

    private static string ResolveTokenEndpointAuthMethod(DynamicClientRegistrationRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod))
        {
            return request.TokenEndpointAuthMethod;
        }

        if (!string.IsNullOrWhiteSpace(request.JwksUri) || request.Jwks is not null)
        {
            return "private_key_jwt";
        }

        if (!string.IsNullOrWhiteSpace(request.TlsClientAuthSubjectDn) || !string.IsNullOrWhiteSpace(request.TlsClientAuthThumbprint))
        {
            return "tls_client_auth";
        }

        return request.RedirectUris.Length > 0 ? "none" : "client_secret_basic";
    }

    private static string GenerateRandomHandle(int size)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string NormalizeGrantType(string value) => value switch
    {
        "urn:ietf:params:oauth:grant-type:device_code" => GrantType.DeviceCode,
        _ => value
    };

    private static readonly string[] SupportedAuthMethods =
    [
        "none",
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth"
    ];

    private static readonly string[] SupportedGrantTypes =
    [
        GrantType.AuthorizationCode,
        GrantType.ClientCredentials,
        GrantType.RefreshToken,
        GrantType.DeviceCode
    ];

    private static bool FixedTimeEquals(string expected, string actual)
    {
        var left = System.Text.Encoding.UTF8.GetBytes(expected);
        var right = System.Text.Encoding.UTF8.GetBytes(actual);
        if (left.Length != right.Length)
        {
            var max = Math.Max(left.Length, right.Length);
            var paddedLeft = new byte[max];
            var paddedRight = new byte[max];
            Buffer.BlockCopy(left, 0, paddedLeft, 0, left.Length);
            Buffer.BlockCopy(right, 0, paddedRight, 0, right.Length);
            CryptographicOperations.FixedTimeEquals(paddedLeft, paddedRight);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static DynamicClientRegistrationResult Failure(int statusCode, string error, string description) =>
        new()
        {
            IsSuccess = false,
            StatusCode = statusCode,
            Error = error,
            ErrorDescription = description
        };

    private static DynamicClientRegistrationResult SuccessPlaceholder() =>
        new()
        {
            IsSuccess = true,
            StatusCode = 200
        };
}
