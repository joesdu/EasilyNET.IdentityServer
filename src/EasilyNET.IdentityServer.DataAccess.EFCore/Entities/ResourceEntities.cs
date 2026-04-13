namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// API 资源实体
/// </summary>
public class ApiResourceEntity
{
    public List<ApiResourceSecretEntity> ApiSecrets { get; set; } = [];

    public DateTime Created { get; set; } = DateTime.UtcNow;

    public string? Description { get; set; }

    public string? DisplayName { get; set; }

    public bool Enabled { get; set; } = true;

    public int Id { get; set; }

    public required string Name { get; set; }

    public List<ApiResourcePropertyEntity> Properties { get; set; } = [];

    public List<ApiResourceScopeEntity> Scopes { get; set; } = [];

    public DateTime? Updated { get; set; }

    public List<ApiResourceClaimEntity> UserClaims { get; set; } = [];
}

public class ApiResourceScopeEntity
{
    public ApiResourceEntity ApiResource { get; set; } = null!;

    public int ApiResourceId { get; set; }

    public int Id { get; set; }

    public required string Scope { get; set; }
}

public class ApiResourceClaimEntity
{
    public ApiResourceEntity ApiResource { get; set; } = null!;

    public int ApiResourceId { get; set; }

    public int Id { get; set; }

    public required string Type { get; set; }
}

public class ApiResourceSecretEntity
{
    public ApiResourceEntity ApiResource { get; set; } = null!;

    public int ApiResourceId { get; set; }

    public string? Description { get; set; }

    public DateTime? Expiration { get; set; }

    public int Id { get; set; }

    public string Type { get; set; } = "SharedSecret";

    public required string Value { get; set; }
}

public class ApiResourcePropertyEntity
{
    public ApiResourceEntity ApiResource { get; set; } = null!;

    public int ApiResourceId { get; set; }

    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }
}

/// <summary>
/// API 作用域实体
/// </summary>
public class ApiScopeEntity
{
    public string? Description { get; set; }

    public string? DisplayName { get; set; }

    public bool Emphasize { get; set; }

    public bool Enabled { get; set; } = true;

    public int Id { get; set; }

    public required string Name { get; set; }

    public List<ApiScopePropertyEntity> Properties { get; set; } = [];

    public bool Required { get; set; }

    public List<ApiScopeClaimEntity> UserClaims { get; set; } = [];
}

public class ApiScopeClaimEntity
{
    public ApiScopeEntity ApiScope { get; set; } = null!;

    public int ApiScopeId { get; set; }

    public int Id { get; set; }

    public required string Type { get; set; }
}

public class ApiScopePropertyEntity
{
    public ApiScopeEntity ApiScope { get; set; } = null!;

    public int ApiScopeId { get; set; }

    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }
}

/// <summary>
/// Identity 资源实体
/// </summary>
public class IdentityResourceEntity
{
    public string? Description { get; set; }

    public string? DisplayName { get; set; }

    public bool Emphasize { get; set; }

    public bool Enabled { get; set; } = true;

    public int Id { get; set; }

    public required string Name { get; set; }

    public List<IdentityResourcePropertyEntity> Properties { get; set; } = [];

    public bool Required { get; set; }

    public bool ShowInDiscoveryDocument { get; set; } = true;

    public List<IdentityResourceClaimEntity> UserClaims { get; set; } = [];
}

public class IdentityResourceClaimEntity
{
    public int Id { get; set; }

    public IdentityResourceEntity IdentityResource { get; set; } = null!;

    public int IdentityResourceId { get; set; }

    public required string Type { get; set; }
}

public class IdentityResourcePropertyEntity
{
    public int Id { get; set; }

    public IdentityResourceEntity IdentityResource { get; set; } = null!;

    public int IdentityResourceId { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }
}