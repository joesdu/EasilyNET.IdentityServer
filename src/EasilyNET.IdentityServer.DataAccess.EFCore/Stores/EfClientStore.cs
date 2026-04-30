using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Stores;

/// <summary>
/// EF Core 客户端存储
/// </summary>
public class EfClientStore(IdentityServerDbContext db) : IClientStore
{
    public async Task CreateClientAsync(Client client, CancellationToken cancellationToken = default)
    {
        var entity = MapToEntity(client);
        db.Clients.Add(entity);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<Client?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.Clients
                             .AsNoTracking()
                             .Include(c => c.AllowedGrantTypes)
                             .Include(c => c.RedirectUris)
                             .Include(c => c.FrontChannelLogoutUris)
                             .Include(c => c.BackChannelLogoutUris)
                             .Include(c => c.AllowedScopes)
                             .Include(c => c.ClientSecrets)
                             .Include(c => c.AuthorizationPromptTypes)
                             .Include(c => c.Claims)
                             .Include(c => c.AllowedCorsOrigins)
                             .Include(c => c.IdentityProviderRestrictions)
                             .Include(c => c.Properties)
                             .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
        return entity == null ? null : MapToModel(entity);
    }

    public async Task<IEnumerable<Client>> FindEnabledClientsAsync(CancellationToken cancellationToken = default)
    {
        var entities = await db.Clients
                               .AsNoTracking()
                               .Include(c => c.AllowedGrantTypes)
                               .Include(c => c.RedirectUris)
                               .Include(c => c.FrontChannelLogoutUris)
                               .Include(c => c.BackChannelLogoutUris)
                               .Include(c => c.AllowedScopes)
                               .Include(c => c.ClientSecrets)
                               .Include(c => c.AuthorizationPromptTypes)
                               .Include(c => c.Claims)
                               .Include(c => c.AllowedCorsOrigins)
                               .Include(c => c.IdentityProviderRestrictions)
                               .Include(c => c.Properties)
                               .Where(c => c.Enabled)
                               .ToListAsync(cancellationToken);
        return entities.Select(MapToModel);
    }

    private static Client MapToModel(ClientEntity e) =>
        new()
        {
            ClientId = e.ClientId,
            ClientName = e.ClientName,
            Contacts = Split(e.Contacts),
            Description = e.Description,
            Enabled = e.Enabled,
            ClientType = (ClientType)e.ClientType,
            AllowedGrantTypes = e.AllowedGrantTypes.Select(g => g.GrantType).ToList(),
            AuthorizationPromptTypes = e.AuthorizationPromptTypes.Select(p => p.PromptType).ToList(),
            RedirectUris = e.RedirectUris.Select(r => r.RedirectUri).ToList(),
            FrontChannelLogoutUris = e.FrontChannelLogoutUris.Select(r => r.LogoutUri).ToList(),
            BackChannelLogoutUris = e.BackChannelLogoutUris.Select(r => r.LogoutUri).ToList(),
            AllowedScopes = e.AllowedScopes.Select(s => s.Scope).ToList(),
            ClientSecrets = e.ClientSecrets.Select(s => new Secret { Value = s.Value, Description = s.Description, Expiration = s.Expiration, Type = s.Type }).ToList(),
            Claims = e.Claims.Select(c => new ClientClaim { Type = c.Type, Value = c.Value }).ToList(),
            AllowedCorsOrigins = e.AllowedCorsOrigins.Select(o => o.Origin).ToList(),
            IdentityProviderRestrictions = e.IdentityProviderRestrictions.Select(r => r.IdentityProvider).ToList(),
            RequirePkce = e.RequirePkce,
            AllowPlainTextPkce = e.AllowPlainTextPkce,
            RequireClientSecret = e.RequireClientSecret,
            RequireConsent = e.RequireConsent,
            AllowRememberConsent = e.AllowRememberConsent,
            AccessTokenLifetime = e.AccessTokenLifetime,
            RefreshTokenLifetime = e.RefreshTokenLifetime,
            AuthorizationCodeLifetime = e.AuthorizationCodeLifetime,
            DeviceCodeLifetime = e.DeviceCodeLifetime,
            ClientUri = e.ClientUri,
            Jwks = e.Jwks,
            JwksUri = e.JwksUri,
            LogoUri = e.LogoUri,
            PolicyUri = e.PolicyUri,
            RequireDpopProof = e.RequireDpopProof,
            TokenEndpointAuthMethod = e.TokenEndpointAuthMethod,
            TlsClientAuthSubjectDn = e.TlsClientAuthSubjectDn,
            TlsClientAuthThumbprint = e.TlsClientAuthThumbprint,
            TosUri = e.TosUri,
            Properties = e.Properties.ToDictionary(p => p.Key, p => p.Value)
        };

    private static ClientEntity MapToEntity(Client client) =>
        new()
        {
            ClientId = client.ClientId,
            ClientName = client.ClientName,
            Contacts = Join(client.Contacts),
            Description = client.Description,
            Enabled = client.Enabled,
            ClientType = (int)client.ClientType,
            AllowedGrantTypes = client.AllowedGrantTypes.Select(grantType => new ClientGrantTypeEntity { GrantType = grantType }).ToList(),
            AuthorizationPromptTypes = client.AuthorizationPromptTypes.Select(promptType => new ClientAuthorizationPromptTypeEntity { PromptType = promptType }).ToList(),
            RedirectUris = client.RedirectUris.Select(uri => new ClientRedirectUriEntity { RedirectUri = uri }).ToList(),
            FrontChannelLogoutUris = client.FrontChannelLogoutUris.Select(uri => new ClientFrontChannelLogoutUriEntity { LogoutUri = uri }).ToList(),
            BackChannelLogoutUris = client.BackChannelLogoutUris.Select(uri => new ClientBackChannelLogoutUriEntity { LogoutUri = uri }).ToList(),
            AllowedScopes = client.AllowedScopes.Select(scope => new ClientScopeEntity { Scope = scope }).ToList(),
            ClientSecrets = client.ClientSecrets.Select(secret => new ClientSecretEntity
            {
                Value = secret.Value,
                Description = secret.Description,
                Expiration = secret.Expiration,
                Type = secret.Type
            }).ToList(),
            Claims = client.Claims.Select(claim => new ClientClaimEntity { Type = claim.Type, Value = claim.Value }).ToList(),
            AllowedCorsOrigins = client.AllowedCorsOrigins.Select(origin => new ClientCorsOriginEntity { Origin = origin }).ToList(),
            IdentityProviderRestrictions = client.IdentityProviderRestrictions.Select(restriction => new ClientIdentityProviderRestrictionEntity { IdentityProvider = restriction }).ToList(),
            RequirePkce = client.RequirePkce,
            AllowPlainTextPkce = client.AllowPlainTextPkce,
            RequireClientSecret = client.RequireClientSecret,
            RequireConsent = client.RequireConsent,
            AllowRememberConsent = client.AllowRememberConsent,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
            DeviceCodeLifetime = client.DeviceCodeLifetime,
            ClientUri = client.ClientUri,
            Jwks = client.Jwks,
            JwksUri = client.JwksUri,
            LogoUri = client.LogoUri,
            PolicyUri = client.PolicyUri,
            RequireDpopProof = client.RequireDpopProof,
            TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
            TlsClientAuthSubjectDn = client.TlsClientAuthSubjectDn,
            TlsClientAuthThumbprint = client.TlsClientAuthThumbprint,
            TosUri = client.TosUri,
            Properties = client.Properties.Select(property => new ClientPropertyEntity { Key = property.Key, Value = property.Value }).ToList()
        };

    private static IEnumerable<string> Split(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string? Join(IEnumerable<string> values)
    {
        var entries = values.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.Ordinal).ToArray();
        return entries.Length == 0 ? null : string.Join(';', entries);
    }
}