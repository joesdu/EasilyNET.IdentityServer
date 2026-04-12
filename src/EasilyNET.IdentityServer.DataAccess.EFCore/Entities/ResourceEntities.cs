namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// API 资源实体
/// </summary>
public class ApiResourceEntity
{
    public int Id { get; set; }

    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public DateTime Created { get; set; } = DateTime.UtcNow;

    public DateTime? Updated { get; set; }

    public List<ApiResourceScopeEntity> Scopes { get; set; } = [];

    public List<ApiResourceClaimEntity> UserClaims { get; set; } = [];

    public List<ApiResourceSecretEntity> ApiSecrets { get; set; } = [];

    public List<ApiResourcePropertyEntity> Properties { get; set; } = [];
}

public class ApiResourceScopeEntity
{
    public int Id { get; set; }

    public required string Scope { get; set; }

    public int ApiResourceId { get; set; }

    public ApiResourceEntity ApiResource { get; set; } = null!;
}

public class ApiResourceClaimEntity
{
    public int Id { get; set; }

    public required string Type { get; set; }

    public int ApiResourceId { get; set; }

    public ApiResourceEntity ApiResource { get; set; } = null!;
}

public class ApiResourceSecretEntity
{
    public int Id { get; set; }

    public required string Value { get; set; }

    public string? Description { get; set; }

    public DateTime? Expiration { get; set; }

    public string Type { get; set; } = "SharedSecret";

    public int ApiResourceId { get; set; }

    public ApiResourceEntity ApiResource { get; set; } = null!;
}

public class ApiResourcePropertyEntity
{
    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }

    public int ApiResourceId { get; set; }

    public ApiResourceEntity ApiResource { get; set; } = null!;
}

/// <summary>
/// API 作用域实体
/// </summary>
public class ApiScopeEntity
{
    public int Id { get; set; }

    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public bool Required { get; set; }

    public bool Emphasize { get; set; }

    public List<ApiScopeClaimEntity> UserClaims { get; set; } = [];

    public List<ApiScopePropertyEntity> Properties { get; set; } = [];
}

public class ApiScopeClaimEntity
{
    public int Id { get; set; }

    public required string Type { get; set; }

    public int ApiScopeId { get; set; }

    public ApiScopeEntity ApiScope { get; set; } = null!;
}

public class ApiScopePropertyEntity
{
    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }

    public int ApiScopeId { get; set; }

    public ApiScopeEntity ApiScope { get; set; } = null!;
}

/// <summary>
/// Identity 资源实体
/// </summary>
public class IdentityResourceEntity
{
    public int Id { get; set; }

    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public bool Required { get; set; }

    public bool Emphasize { get; set; }

    public bool ShowInDiscoveryDocument { get; set; } = true;

    public List<IdentityResourceClaimEntity> UserClaims { get; set; } = [];

    public List<IdentityResourcePropertyEntity> Properties { get; set; } = [];
}

public class IdentityResourceClaimEntity
{
    public int Id { get; set; }

    public required string Type { get; set; }

    public int IdentityResourceId { get; set; }

    public IdentityResourceEntity IdentityResource { get; set; } = null!;
}

public class IdentityResourcePropertyEntity
{
    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }

    public int IdentityResourceId { get; set; }

    public IdentityResourceEntity IdentityResource { get; set; } = null!;
}