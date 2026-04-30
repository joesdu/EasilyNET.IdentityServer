using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Stores;

/// <summary>
/// EF Core 资源存储
/// </summary>
public class EfResourceStore(IdentityServerDbContext db) : IResourceStore
{
    public async Task<IEnumerable<ApiResource>> FindEnabledApiResourcesAsync(CancellationToken cancellationToken = default)
    {
        var entities = await db.ApiResources
                               .AsNoTracking()
                               .Include(r => r.Scopes).Include(r => r.UserClaims).Include(r => r.ApiSecrets).Include(r => r.Properties)
                               .Where(r => r.Enabled).ToListAsync(cancellationToken);
        return entities.Select(MapApiResource);
    }

    public async Task<IEnumerable<IdentityResource>> FindEnabledIdentityResourcesAsync(CancellationToken cancellationToken = default)
    {
        var entities = await db.IdentityResources
                               .AsNoTracking()
                               .Include(r => r.UserClaims).Include(r => r.Properties)
                               .Where(r => r.Enabled).ToListAsync(cancellationToken);
        return entities.Select(MapIdentityResource);
    }

    public async Task<IEnumerable<ApiResource>> FindApiResourcesByScopeAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        var entities = await db.ApiResources
                               .AsNoTracking()
                               .Include(r => r.Scopes).Include(r => r.UserClaims).Include(r => r.ApiSecrets).Include(r => r.Properties)
                               .Where(r => r.Enabled && r.Scopes.Any(s => names.Contains(s.Scope)))
                               .ToListAsync(cancellationToken);
        return entities.Select(MapApiResource);
    }

    public async Task<IEnumerable<ApiScope>> FindEnabledScopesAsync(CancellationToken cancellationToken = default)
    {
        var entities = await db.ApiScopes
                               .AsNoTracking()
                               .Include(s => s.UserClaims).Include(s => s.Properties)
                               .Where(s => s.Enabled).ToListAsync(cancellationToken);
        return entities.Select(MapApiScope);
    }

    public async Task<IEnumerable<ApiScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        var entities = await db.ApiScopes
                               .AsNoTracking()
                               .Include(s => s.UserClaims).Include(s => s.Properties)
                               .Where(s => s.Enabled && names.Contains(s.Name))
                               .ToListAsync(cancellationToken);
        return entities.Select(MapApiScope);
    }

    public async Task<Resources> GetAllResourcesAsync(CancellationToken cancellationToken = default)
    {
        var apiResources = await FindEnabledApiResourcesAsync(cancellationToken);
        var apiScopes = await FindEnabledScopesAsync(cancellationToken);
        var identityResources = await FindEnabledIdentityResourcesAsync(cancellationToken);
        return new()
        {
            ApiResources = apiResources.ToList(),
            ApiScopes = apiScopes.ToList(),
            IdentityResources = identityResources.ToList()
        };
    }

    private static ApiResource MapApiResource(ApiResourceEntity e) =>
        new()
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Description = e.Description,
            Enabled = e.Enabled,
            Scopes = e.Scopes.Select(s => s.Scope).ToList(),
            UserClaims = e.UserClaims.Select(c => c.Type).ToList(),
            ApiSecrets = e.ApiSecrets.Select(s => new Secret { Value = s.Value, Description = s.Description, Expiration = s.Expiration, Type = s.Type }).ToList(),
            Properties = e.Properties.ToDictionary(p => p.Key, p => p.Value)
        };

    private static ApiScope MapApiScope(ApiScopeEntity e) =>
        new()
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Description = e.Description,
            Enabled = e.Enabled,
            Required = e.Required,
            Emphasize = e.Emphasize,
            UserClaims = e.UserClaims.Select(c => c.Type).ToList(),
            Properties = e.Properties.ToDictionary(p => p.Key, p => p.Value)
        };

    private static IdentityResource MapIdentityResource(IdentityResourceEntity e) =>
        new()
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Description = e.Description,
            Enabled = e.Enabled,
            Required = e.Required,
            Emphasize = e.Emphasize,
            ShowInDiscoveryDocument = e.ShowInDiscoveryDocument,
            UserClaims = e.UserClaims.Select(c => c.Type).ToList(),
            Properties = e.Properties.ToDictionary(p => p.Key, p => p.Value)
        };
}