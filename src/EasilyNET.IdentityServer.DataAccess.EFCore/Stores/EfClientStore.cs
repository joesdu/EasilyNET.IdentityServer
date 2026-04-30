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
    public async Task<Client?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var entity = await db.Clients
                             .Include(c => c.AllowedGrantTypes)
                             .Include(c => c.RedirectUris)
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
                               .Include(c => c.AllowedGrantTypes)
                               .Include(c => c.RedirectUris)
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
            Description = e.Description,
            Enabled = e.Enabled,
            ClientType = (ClientType)e.ClientType,
            AllowedGrantTypes = e.AllowedGrantTypes.Select(g => g.GrantType).ToList(),
            AuthorizationPromptTypes = e.AuthorizationPromptTypes.Select(p => p.PromptType).ToList(),
            RedirectUris = e.RedirectUris.Select(r => r.RedirectUri).ToList(),
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
            LogoUri = e.LogoUri,
            Properties = e.Properties.ToDictionary(p => p.Key, p => p.Value)
        };
}