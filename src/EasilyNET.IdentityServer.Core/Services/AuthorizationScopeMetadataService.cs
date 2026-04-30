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
        var apiResourcesByScope = (await resourceStore.FindApiResourcesByScopeAsync(requested, cancellationToken))
            .SelectMany(resource => resource.Scopes.Select(scope => new { Scope = scope, Resource = resource }))
            .Where(pair => requested.Contains(pair.Scope, StringComparer.Ordinal))
            .GroupBy(pair => pair.Scope, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Select(pair => new AuthorizationScopeResourceDescriptor
                {
                    Name = pair.Resource.Name,
                    DisplayName = pair.Resource.DisplayName,
                    Description = pair.Resource.Description,
                    Properties = new Dictionary<string, string>(pair.Resource.Properties),
                    UserClaims = pair.Resource.UserClaims.Distinct(StringComparer.Ordinal).ToArray()
                }).ToArray(),
                StringComparer.Ordinal);
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
                    DisplayGroup = "Identity resources",
                    Description = identity.Description,
                    Required = identity.Required,
                    Emphasize = identity.Emphasize,
                    Properties = new Dictionary<string, string>(identity.Properties),
                    Resources =
                    [
                        new AuthorizationScopeResourceDescriptor
                        {
                            Name = identity.Name,
                            DisplayName = identity.DisplayName,
                            Description = identity.Description,
                            Properties = new Dictionary<string, string>(identity.Properties),
                            UserClaims = identity.UserClaims.Distinct(StringComparer.Ordinal).ToArray()
                        }
                    ],
                    UserClaims = identity.UserClaims.Distinct(StringComparer.Ordinal).ToArray(),
                    Selected = selected.Contains(identity.Name),
                    Type = "identity"
                });
                continue;
            }

            if (apiScopes.TryGetValue(scope, out var api))
            {
                var resources = apiResourcesByScope.GetValueOrDefault(scope) ?? [];
                var mergedClaims = api.UserClaims
                    .Concat(resources.SelectMany(resource => resource.UserClaims))
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                descriptors.Add(new AuthorizationScopeDescriptor
                {
                    Name = api.Name,
                    DisplayName = api.DisplayName,
                    DisplayGroup = resources.Length switch
                    {
                        0 => "API permissions",
                        1 => resources[0].DisplayName ?? resources[0].Name,
                        _ => "API permissions"
                    },
                    Description = api.Description,
                    Required = api.Required,
                    Emphasize = api.Emphasize,
                    Properties = new Dictionary<string, string>(api.Properties),
                    Resources = resources,
                    UserClaims = mergedClaims,
                    Selected = selected.Contains(api.Name),
                    Type = "api"
                });
                continue;
            }

            descriptors.Add(new AuthorizationScopeDescriptor
            {
                Name = scope,
                DisplayName = scope,
                DisplayGroup = "Other permissions",
                Description = null,
                Required = false,
                Emphasize = false,
                Properties = new Dictionary<string, string>(),
                Resources = [],
                UserClaims = [],
                Selected = selected.Contains(scope),
                Type = "unknown"
            });
        }

        return descriptors;
    }
}