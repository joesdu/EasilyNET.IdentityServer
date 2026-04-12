namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// 客户端实体
/// </summary>
public class ClientEntity
{
    public int Id { get; set; }

    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public int ClientType { get; set; }

    public bool RequirePkce { get; set; } = true;

    public bool AllowPlainTextPkce { get; set; }

    public bool RequireClientSecret { get; set; } = true;

    public bool RequireConsent { get; set; } = true;

    public bool AllowRememberConsent { get; set; } = true;

    public int AccessTokenLifetime { get; set; } = 3600;

    public int RefreshTokenLifetime { get; set; } = 86400;

    public int AuthorizationCodeLifetime { get; set; } = 300;

    public int DeviceCodeLifetime { get; set; } = 300;

    public string? ClientUri { get; set; }

    public string? LogoUri { get; set; }

    public string? UserCodeType { get; set; }

    public DateTime Created { get; set; } = DateTime.UtcNow;

    public DateTime? Updated { get; set; }

    public List<ClientGrantTypeEntity> AllowedGrantTypes { get; set; } = [];

    public List<ClientRedirectUriEntity> RedirectUris { get; set; } = [];

    public List<ClientScopeEntity> AllowedScopes { get; set; } = [];

    public List<ClientSecretEntity> ClientSecrets { get; set; } = [];

    public List<ClientClaimEntity> Claims { get; set; } = [];

    public List<ClientCorsOriginEntity> AllowedCorsOrigins { get; set; } = [];

    public List<ClientPropertyEntity> Properties { get; set; } = [];
}

public class ClientGrantTypeEntity
{
    public int Id { get; set; }

    public required string GrantType { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientRedirectUriEntity
{
    public int Id { get; set; }

    public required string RedirectUri { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientScopeEntity
{
    public int Id { get; set; }

    public required string Scope { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientSecretEntity
{
    public int Id { get; set; }

    public required string Value { get; set; }

    public string? Description { get; set; }

    public DateTime? Expiration { get; set; }

    public string Type { get; set; } = "SharedSecret";

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientClaimEntity
{
    public int Id { get; set; }

    public required string Type { get; set; }

    public required string Value { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientCorsOriginEntity
{
    public int Id { get; set; }

    public required string Origin { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}

public class ClientPropertyEntity
{
    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }

    public int ClientId { get; set; }

    public ClientEntity Client { get; set; } = null!;
}