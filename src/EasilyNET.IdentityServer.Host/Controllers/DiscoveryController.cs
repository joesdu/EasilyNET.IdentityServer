using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
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

    public DiscoveryController(IdentityServerOptions options, IResourceStore resourceStore, IClientStore clientStore)
    {
        _options = options;
        _resourceStore = resourceStore;
        _clientStore = clientStore;
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
            ["claims_supported"] = new[] { "sub", "name", "email", "picture", "iss", "aud", "exp", "iat", "jti" }
        };
        return Ok(discovery);
    }

    /// <summary>
    /// JSON Web Key Set
    /// </summary>
    [HttpGet("/.well-known/jwks")]
    public IActionResult GetJwks() =>
        // 开发环境使用对称密钥，不暴露 JWKS
        // 生产环境应返回 RSA/EC 公钥
        Ok(new { keys = Array.Empty<object>() });
}
