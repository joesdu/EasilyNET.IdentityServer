using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 授权作用域元数据服务
/// </summary>
public class AuthorizationScopeMetadataService(IResourceStore resourceStore) : IAuthorizationScopeMetadataService
{
    public async Task<IReadOnlyCollection<AuthorizationScopeDescriptor>> DescribeScopesAsync(
        IEnumerable<string> requestedScopes,
        IEnumerable<string>? selectedScopes = null,
        CancellationToken cancellationToken = default)
    {
        var requested = requestedScopes.Distinct(StringComparer.Ordinal).ToArray();
        var selected = (selectedScopes ?? requested).ToHashSet(StringComparer.Ordinal);

        var apiScopes = (await resourceStore.FindScopesByNameAsync(requested, cancellationToken))
            .ToDictionary(scope => scope.Name, StringComparer.Ordinal);
        var identityResources = (await resourceStore.FindEnabledIdentityResourcesAsync(cancellationToken))
            .Where(resource => requested.Contains(resource.Name, StringComparer.Ordinal))
            .ToDictionary(resource => resource.Name, StringComparer.Ordinal);

        var descriptors = new List<AuthorizationScopeDescriptor>(requested.Length);
        foreach (var scope in requested)
        {
            if (identityResources.TryGetValue(scope, out var identity))
            {
                descriptors.Add(new AuthorizationScopeDescriptor
                {
                    Name = identity.Name,
                    DisplayName = identity.DisplayName,
                    Description = identity.Description,
                    Required = identity.Required,
                    Emphasize = identity.Emphasize,
                    Selected = selected.Contains(identity.Name),
                    Type = "identity"
                });
                continue;
            }

            if (apiScopes.TryGetValue(scope, out var api))
            {
                descriptors.Add(new AuthorizationScopeDescriptor
                {
                    Name = api.Name,
                    DisplayName = api.DisplayName,
                    Description = api.Description,
                    Required = api.Required,
                    Emphasize = api.Emphasize,
                    Selected = selected.Contains(api.Name),
                    Type = "api"
                });
                continue;
            }

            descriptors.Add(new AuthorizationScopeDescriptor
            {
                Name = scope,
                DisplayName = scope,
                Description = null,
                Required = false,
                Emphasize = false,
                Selected = selected.Contains(scope),
                Type = "unknown"
            });
        }

        return descriptors;
    }
}