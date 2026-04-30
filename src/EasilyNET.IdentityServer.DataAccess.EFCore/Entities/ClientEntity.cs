namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// 客户端实体
/// </summary>
public class ClientEntity
{
    public int AccessTokenLifetime { get; set; } = 3600;

    public List<ClientCorsOriginEntity> AllowedCorsOrigins { get; set; } = [];

    public List<ClientBackChannelLogoutUriEntity> BackChannelLogoutUris { get; set; } = [];

    public List<ClientGrantTypeEntity> AllowedGrantTypes { get; set; } = [];

    public List<ClientScopeEntity> AllowedScopes { get; set; } = [];

    public bool AllowPlainTextPkce { get; set; }

    public bool AllowRememberConsent { get; set; } = true;

    public int AuthorizationCodeLifetime { get; set; } = 300;

    public List<ClientAuthorizationPromptTypeEntity> AuthorizationPromptTypes { get; set; } = [];

    public List<ClientClaimEntity> Claims { get; set; } = [];

    public string? Contacts { get; set; }

    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public List<ClientSecretEntity> ClientSecrets { get; set; } = [];

    public int ClientType { get; set; }

    public string? ClientUri { get; set; }

    public string? Jwks { get; set; }

    public string? JwksUri { get; set; }

    public DateTime Created { get; set; } = DateTime.UtcNow;

    public string? Description { get; set; }

    public int DeviceCodeLifetime { get; set; } = 300;

    public bool Enabled { get; set; } = true;

    public int Id { get; set; }

    public List<ClientIdentityProviderRestrictionEntity> IdentityProviderRestrictions { get; set; } = [];

    public List<ClientFrontChannelLogoutUriEntity> FrontChannelLogoutUris { get; set; } = [];

    public string? LogoUri { get; set; }

    public string? PolicyUri { get; set; }

    public List<ClientPropertyEntity> Properties { get; set; } = [];

    public bool RequireDpopProof { get; set; }

    public List<ClientRedirectUriEntity> RedirectUris { get; set; } = [];

    public int RefreshTokenLifetime { get; set; } = 86400;

    public bool RequireClientSecret { get; set; } = true;

    public string TokenEndpointAuthMethod { get; set; } = "client_secret_basic";

    public bool RequireConsent { get; set; } = true;

    public bool RequirePkce { get; set; } = true;

    public string? TlsClientAuthSubjectDn { get; set; }

    public string? TlsClientAuthThumbprint { get; set; }

    public string? TosUri { get; set; }

    public DateTime? Updated { get; set; }

    public string? UserCodeType { get; set; }
}

public class ClientGrantTypeEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public required string GrantType { get; set; }

    public int Id { get; set; }
}

public class ClientRedirectUriEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string RedirectUri { get; set; }
}

public class ClientFrontChannelLogoutUriEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string LogoutUri { get; set; }
}

public class ClientBackChannelLogoutUriEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string LogoutUri { get; set; }
}

public class ClientScopeEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string Scope { get; set; }
}

public class ClientSecretEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public string? Description { get; set; }

    public DateTime? Expiration { get; set; }

    public int Id { get; set; }

    public string Type { get; set; } = "SharedSecret";

    public required string Value { get; set; }
}

public class ClientClaimEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string Type { get; set; }

    public required string Value { get; set; }
}

public class ClientAuthorizationPromptTypeEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string PromptType { get; set; }
}

public class ClientCorsOriginEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string Origin { get; set; }
}

public class ClientIdentityProviderRestrictionEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string IdentityProvider { get; set; }
}

public class ClientPropertyEntity
{
    public ClientEntity Client { get; set; } = null!;

    public int ClientId { get; set; }

    public int Id { get; set; }

    public required string Key { get; set; }

    public required string Value { get; set; }
}