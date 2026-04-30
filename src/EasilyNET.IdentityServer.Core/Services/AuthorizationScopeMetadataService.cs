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
                    ConsentWarnings = BuildConsentWarnings(identity.Required, identity.UserClaims, identity.Properties),
                    RiskLevel = DetermineRiskLevel("identity", identity.UserClaims, identity.Properties),
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
                    ConsentWarnings = BuildConsentWarnings(api.Required, mergedClaims, mergedProperties),
                    RiskLevel = DetermineRiskLevel("api", mergedClaims, mergedProperties),
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
                ConsentWarnings = [],
                RiskLevel = "low",
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

    private static string[] BuildConsentWarnings(bool required, IEnumerable<string> claims, IDictionary<string, string> properties)
    {
        var warnings = new List<string>();
        var normalizedClaims = claims.Distinct(StringComparer.Ordinal).ToArray();

        if (required)
        {
            warnings.Add("This permission is required and cannot be deselected.");
        }

        if (normalizedClaims.Any(static claim => string.Equals(claim, "role", StringComparison.OrdinalIgnoreCase)))
        {
            warnings.Add("This permission may expose role or authorization membership data.");
        }

        if (normalizedClaims.Any(IsPersonalClaim))
        {
            warnings.Add("This permission may expose personal profile information.");
        }

        if (properties.TryGetValue("audience", out var audience) && !string.IsNullOrWhiteSpace(audience))
        {
            warnings.Add($"Access tokens issued for this permission target resource audience '{audience}'.");
        }

        return warnings.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string DetermineRiskLevel(string scopeType, IEnumerable<string> claims, IDictionary<string, string> properties)
    {
        var normalizedClaims = claims.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (normalizedClaims.Any(static claim => string.Equals(claim, "role", StringComparison.OrdinalIgnoreCase)) ||
            normalizedClaims.Any(IsPersonalClaim) ||
            properties.ContainsKey("audience"))
        {
            return "high";
        }

        if (string.Equals(scopeType, "identity", StringComparison.OrdinalIgnoreCase) || normalizedClaims.Length > 0)
        {
            return "medium";
        }

        return "low";
    }

    private static bool IsPersonalClaim(string claim) =>
        string.Equals(claim, "email", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "phone_number", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "address", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "birthdate", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "profile", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "name", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(claim, "picture", StringComparison.OrdinalIgnoreCase);
}