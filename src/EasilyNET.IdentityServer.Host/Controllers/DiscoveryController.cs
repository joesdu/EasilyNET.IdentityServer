using System.Security.Cryptography;
using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OAuth 2.0 Discovery Endpoint
/// </summary>
[ApiController]
public class DiscoveryController : ControllerBase
{
    private readonly IClientStore _clientStore;
    private readonly IdentityServerOptions _options;
    private readonly IResourceStore _resourceStore;
    private readonly ISigningService _signingService;

    public DiscoveryController(IdentityServerOptions options, IResourceStore resourceStore, IClientStore clientStore, ISigningService signingService)
    {
        _options = options;
        _resourceStore = resourceStore;
        _clientStore = clientStore;
        _signingService = signingService;
    }

    /// <summary>
    /// OpenID Connect Discovery
    /// </summary>
    [HttpGet("/.well-known/openid-configuration")]
    public async Task<IActionResult> GetConfiguration(CancellationToken cancellationToken)
    {
        var issuer = _options.Issuer.TrimEnd('/');
        var scopes = await _resourceStore.FindEnabledScopesAsync(cancellationToken);
        var identityResources = await _resourceStore.FindEnabledIdentityResourcesAsync(cancellationToken);
        var clients = await _clientStore.FindEnabledClientsAsync(cancellationToken);
        var tokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
        {
            "client_secret_basic",
            "client_secret_post"
        };
        if (clients.Any(x => x.ClientType == ClientType.Public || !x.RequireClientSecret))
        {
            tokenEndpointAuthMethods.Add("none");
        }
var scopeNames = scopes.Select(s => s.Name)
                              .Concat(identityResources.Select(r => r.Name))
                              .Distinct()
                              .ToList();

        // 动态生成 claims_supported (OIDC Discovery)
        // 查找所有已启用的 IdentityResources 并提取支持的声明
        var supportedClaims = identityResources
            .Where(r => r.ShowInDiscoveryDocument)
            .SelectMany(r => r.UserClaims)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // OIDC 标准声明
        var standardOidcClaims = new[] { "sub", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "address", "updated_at" };

        // 合并标准 OIDC 声明和配置的自定义声明
        var allClaims = supportedClaims.Any()
            ? standardOidcClaims.Concat(supportedClaims).Distinct(StringComparer.Ordinal).ToList()
            : standardOidcClaims.ToList();

        var discovery = new Dictionary<string, object>
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = $"{issuer}/connect/authorize",
            ["token_endpoint"] = $"{issuer}/connect/token",
            ["device_authorization_endpoint"] = $"{issuer}/connect/device_authorization",
            ["introspection_endpoint"] = $"{issuer}/connect/introspect",
            ["revocation_endpoint"] = $"{issuer}/connect/revocation",
            ["jwks_uri"] = $"{issuer}/.well-known/jwks",
            ["scopes_supported"] = scopeNames,
            ["response_types_supported"] = new[] { "code" },
            ["response_modes_supported"] = new[] { "query", "fragment", "form_post" },
            ["grant_types_supported"] = new[] { "authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code" },
            ["token_endpoint_auth_methods_supported"] = tokenEndpointAuthMethods.ToArray(),
            ["subject_types_supported"] = new[] { "public" },
            ["id_token_signing_alg_values_supported"] = new[] { "HS256", "RS256" },
            ["code_challenge_methods_supported"] = new[] { "S256" },
            ["claims_supported"] = allClaims,
            ["error_uri"] = "https://docs.example.com/errors" // 可选的错误URI
        };
        return Ok(discovery);
    }

    /// <summary>
    /// JSON Web Key Set (RFC 7517)
    /// </summary>
    [HttpGet("/.well-known/jwks")]
    public IActionResult GetJwks()
    {
        var rsa = _signingService.GetPublicKey();
        if (rsa == null)
        {
            return Ok(new { keys = Array.Empty<object>() });
        }
        var parameters = rsa.ExportParameters(false);
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = "RS256",
            ["kid"] = "rsa-key-1",
            ["n"] = Base64UrlEncode(parameters.Modulus!),
            ["e"] = Base64UrlEncode(parameters.Exponent!)
        };
        return Ok(new { keys = new[] { jwk } });
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
                     .TrimEnd('=')
                     .Replace('+', '-')
                     .Replace('/', '_');
    }
}
