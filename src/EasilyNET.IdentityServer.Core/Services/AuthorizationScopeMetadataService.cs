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
                var selectable = !identity.Required;
                descriptors.Add(new AuthorizationScopeDescriptor
                {
                    ConsentDescription = BuildConsentDescription(identity.DisplayName ?? identity.Name, identity.Description, identity.UserClaims, identity.Properties),
                    Name = identity.Name,
                    DisplayName = identity.DisplayName,
                    DisplayGroup = "Identity resources",
                    Description = identity.Description,
                    Required = identity.Required,
                    Emphasize = identity.Emphasize,
                    IsSelectable = selectable,
                    SelectionLockedReason = selectable ? null : "This scope is required by the identity protocol and cannot be deselected.",
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
                var mergedProperties = new Dictionary<string, string>(api.Properties, StringComparer.Ordinal);
                foreach (var resource in resources)
                {
                    foreach (var property in resource.Properties)
                    {
                        mergedProperties.TryAdd(property.Key, property.Value);
                    }
                }
                var selectable = !api.Required;
                var group = resources.Length switch
                {
                    0 => "API permissions",
                    1 => resources[0].DisplayName ?? resources[0].Name,
                    _ => "API permissions"
                };
                descriptors.Add(new AuthorizationScopeDescriptor
                {
                    ConsentDescription = BuildConsentDescription(api.DisplayName ?? api.Name, api.Description, mergedClaims, mergedProperties),
                    Name = api.Name,
                    DisplayName = api.DisplayName,
                    DisplayGroup = group,
                    Description = api.Description,
                    Required = api.Required,
                    Emphasize = api.Emphasize,
                    IsSelectable = selectable,
                    SelectionLockedReason = selectable ? null : "This API permission is required by the client and cannot be deselected.",
                    Properties = mergedProperties,
                    Resources = resources,
                    UserClaims = mergedClaims,
                    Selected = selected.Contains(api.Name),
                    Type = "api"
                });
                continue;
            }

            descriptors.Add(new AuthorizationScopeDescriptor
            {
                ConsentDescription = $"Grant access to '{scope}'.",
                Name = scope,
                DisplayName = scope,
                DisplayGroup = "Other permissions",
                Description = null,
                Required = false,
                Emphasize = false,
                IsSelectable = true,
                SelectionLockedReason = null,
                Properties = new Dictionary<string, string>(),
                Resources = [],
                UserClaims = [],
                Selected = selected.Contains(scope),
                Type = "unknown"
            });
        }

        return descriptors;
    }

    private static string BuildConsentDescription(string name, string? description, IEnumerable<string> claims, IDictionary<string, string> properties)
    {
        var claimList = claims.Distinct(StringComparer.Ordinal).ToArray();
        var audience = properties.TryGetValue("audience", out var audienceValue) ? audienceValue : null;

        var parts = new List<string> { description ?? $"Allow access to {name}." };
        if (claimList.Length > 0)
        {
            parts.Add($"Claims: {string.Join(", ", claimList)}.");
        }

        if (!string.IsNullOrWhiteSpace(audience))
        {
            parts.Add($"Audience: {audience}.");
        }

        return string.Join(" ", parts);
    }
}