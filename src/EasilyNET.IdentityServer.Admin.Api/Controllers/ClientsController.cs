using EasilyNET.IdentityServer.DataAccess.EFCore;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace EasilyNET.IdentityServer.Admin.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClientsController(IdentityServerDbContext db) : ControllerBase
{
    private static readonly string[] SupportedPromptTypes = ["none", "login", "consent", "select_account"];

    [HttpGet]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var clients = await db.Clients
                              .Include(c => c.AllowedGrantTypes)
                              .Include(c => c.AllowedScopes)
                              .Include(c => c.RedirectUris)
                              .Include(c => c.AllowedCorsOrigins)
                              .Include(c => c.AuthorizationPromptTypes)
                              .Include(c => c.IdentityProviderRestrictions)
                              .Select(c => new
                              {
                                  c.Id,
                                  c.ClientId,
                                  c.ClientName,
                                  c.Description,
                                  c.Enabled,
                                  c.ClientType,
                                  c.RequirePkce,
                                  c.RequireClientSecret,
                                  c.RequireConsent,
                                  c.AllowPlainTextPkce,
                                  c.AllowRememberConsent,
                                  c.DeviceCodeLifetime,
                                  c.ClientUri,
                                  c.LogoUri,
                                  c.AccessTokenLifetime,
                                  c.RefreshTokenLifetime,
                                  AllowedGrantTypes = c.AllowedGrantTypes.Select(g => g.GrantType),
                                  AuthorizationPromptTypes = c.AuthorizationPromptTypes.Select(p => p.PromptType),
                                  AllowedScopes = c.AllowedScopes.Select(s => s.Scope),
                                  RedirectUris = c.RedirectUris.Select(r => r.RedirectUri),
                                  AllowedCorsOrigins = c.AllowedCorsOrigins.Select(o => o.Origin),
                                  IdentityProviderRestrictions = c.IdentityProviderRestrictions.Select(r => r.IdentityProvider)
                              })
                              .ToListAsync(ct);
        return Ok(clients);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id, CancellationToken ct)
    {
        var client = await db.Clients
                             .Include(c => c.AllowedGrantTypes).Include(c => c.AllowedScopes)
                             .Include(c => c.RedirectUris).Include(c => c.ClientSecrets)
                             .Include(c => c.AuthorizationPromptTypes)
                             .Include(c => c.Claims).Include(c => c.AllowedCorsOrigins).Include(c => c.IdentityProviderRestrictions).Include(c => c.Properties)
                             .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (client == null)
        {
            return NotFound();
        }
        return Ok(new
        {
            client.Id,
            client.ClientId,
            client.ClientName,
            client.Description,
            client.Enabled,
            client.ClientType,
            client.RequirePkce,
            client.RequireClientSecret,
            client.RequireConsent,
            client.AllowPlainTextPkce,
            client.AllowRememberConsent,
            client.DeviceCodeLifetime,
            client.ClientUri,
            client.LogoUri,
            client.AccessTokenLifetime,
            client.RefreshTokenLifetime,
            client.AuthorizationCodeLifetime,
            AllowedGrantTypes = client.AllowedGrantTypes.Select(g => g.GrantType),
            AuthorizationPromptTypes = client.AuthorizationPromptTypes.Select(p => p.PromptType),
            AllowedScopes = client.AllowedScopes.Select(s => s.Scope),
            RedirectUris = client.RedirectUris.Select(r => r.RedirectUri),
            AllowedCorsOrigins = client.AllowedCorsOrigins.Select(o => o.Origin),
            IdentityProviderRestrictions = client.IdentityProviderRestrictions.Select(r => r.IdentityProvider)
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateClientRequest request, CancellationToken ct)
    {
        var validationProblem = await ValidateCreateRequestAsync(request, ct);
        if (validationProblem != null)
        {
            return validationProblem;
        }

        var entity = new ClientEntity
        {
            ClientId = request.ClientId,
            ClientName = request.ClientName,
            Description = request.Description,
            Enabled = request.Enabled,
            ClientType = request.ClientType,
            RequirePkce = request.RequirePkce,
            RequireClientSecret = request.RequireClientSecret,
            RequireConsent = request.RequireConsent,
            AllowPlainTextPkce = request.AllowPlainTextPkce,
            AllowRememberConsent = request.AllowRememberConsent,
            AccessTokenLifetime = request.AccessTokenLifetime,
            RefreshTokenLifetime = request.RefreshTokenLifetime,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
            DeviceCodeLifetime = request.DeviceCodeLifetime,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            AllowedGrantTypes = request.AllowedGrantTypes.Select(g => new ClientGrantTypeEntity { GrantType = g }).ToList(),
            AuthorizationPromptTypes = request.AuthorizationPromptTypes.Select(prompt => new ClientAuthorizationPromptTypeEntity { PromptType = prompt }).ToList(),
            AllowedScopes = request.AllowedScopes.Select(s => new ClientScopeEntity { Scope = s }).ToList(),
            RedirectUris = request.RedirectUris.Select(r => new ClientRedirectUriEntity { RedirectUri = r }).ToList(),
            AllowedCorsOrigins = request.AllowedCorsOrigins.Select(o => new ClientCorsOriginEntity { Origin = o }).ToList(),
            IdentityProviderRestrictions = request.IdentityProviderRestrictions.Select(idp => new ClientIdentityProviderRestrictionEntity { IdentityProvider = idp }).ToList(),
            ClientSecrets = BuildSecretEntities(request.ClientSecrets)
        };
        db.Clients.Add(entity);
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(Get), new { id = entity.Id }, new { entity.Id, entity.ClientId });
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateClientRequest request, CancellationToken ct)
    {
        var entity = await db.Clients
                             .Include(c => c.AllowedGrantTypes).Include(c => c.AllowedScopes)
                             .Include(c => c.RedirectUris).Include(c => c.ClientSecrets)
                             .Include(c => c.AuthorizationPromptTypes)
                             .Include(c => c.AllowedCorsOrigins).Include(c => c.IdentityProviderRestrictions)
                             .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (entity == null)
        {
            return NotFound();
        }

        var validationProblem = await ValidateUpdateRequestAsync(entity, request, ct);
        if (validationProblem != null)
        {
            return validationProblem;
        }

        entity.ClientName = request.ClientName;
        entity.Description = request.Description;
        entity.Enabled = request.Enabled;
        entity.ClientType = request.ClientType;
        entity.RequirePkce = request.RequirePkce;
        entity.RequireClientSecret = request.RequireClientSecret;
        entity.RequireConsent = request.RequireConsent;
        entity.AllowPlainTextPkce = request.AllowPlainTextPkce;
        entity.AllowRememberConsent = request.AllowRememberConsent;
        entity.AccessTokenLifetime = request.AccessTokenLifetime;
        entity.RefreshTokenLifetime = request.RefreshTokenLifetime;
        entity.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime;
        entity.DeviceCodeLifetime = request.DeviceCodeLifetime;
        entity.ClientUri = request.ClientUri;
        entity.LogoUri = request.LogoUri;
        entity.Updated = DateTime.UtcNow;

        // 替换子集合
        entity.AllowedGrantTypes.Clear();
        entity.AllowedGrantTypes.AddRange(request.AllowedGrantTypes.Select(g => new ClientGrantTypeEntity { GrantType = g }));
        entity.AuthorizationPromptTypes.Clear();
        entity.AuthorizationPromptTypes.AddRange(request.AuthorizationPromptTypes.Select(prompt => new ClientAuthorizationPromptTypeEntity { PromptType = prompt }));
        entity.AllowedScopes.Clear();
        entity.AllowedScopes.AddRange(request.AllowedScopes.Select(s => new ClientScopeEntity { Scope = s }));
        entity.RedirectUris.Clear();
        entity.RedirectUris.AddRange(request.RedirectUris.Select(r => new ClientRedirectUriEntity { RedirectUri = r }));
        entity.AllowedCorsOrigins.Clear();
        entity.AllowedCorsOrigins.AddRange(request.AllowedCorsOrigins.Select(o => new ClientCorsOriginEntity { Origin = o }));
        entity.IdentityProviderRestrictions.Clear();
        entity.IdentityProviderRestrictions.AddRange(request.IdentityProviderRestrictions.Select(idp => new ClientIdentityProviderRestrictionEntity { IdentityProvider = idp }));
        if (request.ClientSecrets.Count > 0)
        {
            entity.ClientSecrets.Clear();
            entity.ClientSecrets.AddRange(BuildSecretEntities(request.ClientSecrets));
        }
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var entity = await db.Clients.FindAsync([id], ct);
        if (entity == null)
        {
            return NotFound();
        }
        db.Clients.Remove(entity);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private async Task<ObjectResult?> ValidateCreateRequestAsync(CreateClientRequest request, CancellationToken ct)
    {
        if (await db.Clients.AnyAsync(c => c.ClientId == request.ClientId, ct))
        {
            return ConflictProblem($"Client '{request.ClientId}' already exists.");
        }

        return await ValidateClientConfigurationAsync(request.ClientId, request.ClientType, request.RequireClientSecret, request.AllowedGrantTypes,
            request.AuthorizationPromptTypes, request.AllowedScopes, request.RedirectUris, request.AllowedCorsOrigins, request.IdentityProviderRestrictions, request.ClientSecrets, ct);
    }

    private Task<ObjectResult?> ValidateUpdateRequestAsync(ClientEntity entity, UpdateClientRequest request, CancellationToken ct) =>
        ValidateClientConfigurationAsync(entity.ClientId, request.ClientType, request.RequireClientSecret, request.AllowedGrantTypes,
            request.AuthorizationPromptTypes, request.AllowedScopes, request.RedirectUris, request.AllowedCorsOrigins, request.IdentityProviderRestrictions, request.ClientSecrets, ct);

    private async Task<ObjectResult?> ValidateClientConfigurationAsync(
        string clientId,
        int clientType,
        bool requireClientSecret,
        IEnumerable<string> allowedGrantTypes,
        IEnumerable<string> authorizationPromptTypes,
        IEnumerable<string> allowedScopes,
        IEnumerable<string> redirectUris,
        IEnumerable<string> allowedCorsOrigins,
        IEnumerable<string> identityProviderRestrictions,
        IEnumerable<SecretInput> clientSecrets,
        CancellationToken ct)
    {
        var normalizedGrantTypes = allowedGrantTypes.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var normalizedAuthorizationPromptTypes = authorizationPromptTypes.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var normalizedScopes = allowedScopes.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var normalizedRedirectUris = redirectUris.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var normalizedCorsOrigins = allowedCorsOrigins.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var normalizedIdentityProviderRestrictions = identityProviderRestrictions.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToArray();
        var clientTypeValue = Enum.IsDefined(typeof(EasilyNET.IdentityServer.Abstractions.Models.ClientType), clientType)
            ? (EasilyNET.IdentityServer.Abstractions.Models.ClientType)clientType
            : (EasilyNET.IdentityServer.Abstractions.Models.ClientType?)null;

        if (clientTypeValue == null)
        {
            return ValidationProblem("client_type", "Client type is invalid.");
        }

        if (clientTypeValue == EasilyNET.IdentityServer.Abstractions.Models.ClientType.Public && requireClientSecret)
        {
            return ValidationProblem("require_client_secret", "Public clients must not require a client secret.");
        }

        if (normalizedGrantTypes.Contains("client_credentials", StringComparer.Ordinal) &&
            clientTypeValue != EasilyNET.IdentityServer.Abstractions.Models.ClientType.Confidential)
        {
            return ValidationProblem("allowed_grant_types", "client_credentials grant requires a confidential client.");
        }

        if (clientTypeValue == EasilyNET.IdentityServer.Abstractions.Models.ClientType.Confidential && requireClientSecret &&
            normalizedGrantTypes.Any() && !clientSecrets.Any() && await db.Clients.AllAsync(c => c.ClientId != clientId, ct))
        {
            return ValidationProblem("client_secrets", "Confidential clients that require secrets must provide at least one client secret.");
        }

        if (normalizedGrantTypes.Contains("authorization_code", StringComparer.Ordinal) && normalizedRedirectUris.Length == 0)
        {
            return ValidationProblem("redirect_uris", "authorization_code clients must register at least one redirect URI.");
        }

        foreach (var redirectUri in normalizedRedirectUris)
        {
            if (!IsValidRedirectUri(redirectUri))
            {
                return ValidationProblem("redirect_uris", $"Redirect URI '{redirectUri}' is invalid.");
            }
        }

        foreach (var corsOrigin in normalizedCorsOrigins)
        {
            if (!IsValidCorsOrigin(corsOrigin))
            {
                return ValidationProblem("allowed_cors_origins", $"CORS origin '{corsOrigin}' is invalid.");
            }
        }

        foreach (var identityProvider in normalizedIdentityProviderRestrictions)
        {
            if (identityProvider.Any(char.IsWhiteSpace))
            {
                return ValidationProblem("identity_provider_restrictions", $"Identity provider '{identityProvider}' must not contain whitespace.");
            }
        }

        var unsupportedPromptTypes = normalizedAuthorizationPromptTypes.Where(prompt => !SupportedPromptTypes.Contains(prompt, StringComparer.Ordinal)).ToArray();
        if (unsupportedPromptTypes.Length > 0)
        {
            return ValidationProblem("authorization_prompt_types", $"Unsupported prompt types: {string.Join(", ", unsupportedPromptTypes)}.");
        }

        var knownScopes = await db.ApiScopes.Select(x => x.Name)
            .Concat(db.IdentityResources.Select(x => x.Name))
            .ToListAsync(ct);
        var knownScopeSet = knownScopes.ToHashSet(StringComparer.Ordinal);
        var unknownScopes = normalizedScopes.Where(scope => !knownScopeSet.Contains(scope)).ToArray();
        if (unknownScopes.Length > 0)
        {
            return ValidationProblem("allowed_scopes", $"Unknown scopes: {string.Join(", ", unknownScopes)}.");
        }

        return null;
    }

    private static bool IsValidRedirectUri(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var parsedUri))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(parsedUri.Fragment))
        {
            return false;
        }

        return string.Equals(parsedUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(parsedUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidCorsOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var parsedOrigin))
        {
            return false;
        }

        return string.IsNullOrEmpty(parsedOrigin.PathAndQuery.Trim('/')) &&
               string.IsNullOrEmpty(parsedOrigin.Fragment) &&
               (string.Equals(parsedOrigin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parsedOrigin.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
    }

    private static List<ClientSecretEntity> BuildSecretEntities(IEnumerable<SecretInput> secrets) =>
        secrets.Where(secret => !string.IsNullOrWhiteSpace(secret.Value))
            .Select(secret => new ClientSecretEntity
            {
                Value = HashSecret(secret.Value),
                Description = secret.Description,
                Type = "SharedSecret"
            })
            .ToList();

    private static string HashSecret(string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hash);
    }

    private ObjectResult ValidationProblem(string field, string message) =>
        BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
        {
            [field] = [message]
        }));

    private ObjectResult ConflictProblem(string message) =>
        Conflict(new ProblemDetails
        {
            Title = "Client configuration conflict",
            Detail = message,
            Status = StatusCodes.Status409Conflict
        });
}

public class CreateClientRequest
{
    public int AccessTokenLifetime { get; set; } = 3600;

    public bool AllowPlainTextPkce { get; set; }

    public bool AllowRememberConsent { get; set; } = true;

    public List<string> AllowedGrantTypes { get; set; } = [];

    public List<string> AuthorizationPromptTypes { get; set; } = [];

    public List<string> IdentityProviderRestrictions { get; set; } = [];

    public List<string> AllowedCorsOrigins { get; set; } = [];

    public List<string> AllowedScopes { get; set; } = [];

    public int AuthorizationCodeLifetime { get; set; } = 300;

    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public List<SecretInput> ClientSecrets { get; set; } = [];

    public int ClientType { get; set; }

    public string? ClientUri { get; set; }

    public int DeviceCodeLifetime { get; set; } = 300;

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public List<string> RedirectUris { get; set; } = [];

    public string? LogoUri { get; set; }

    public int RefreshTokenLifetime { get; set; } = 86400;

    public bool RequireClientSecret { get; set; } = true;

    public bool RequireConsent { get; set; }

    public bool RequirePkce { get; set; } = true;
}

public class UpdateClientRequest
{
    public int AccessTokenLifetime { get; set; } = 3600;

    public bool AllowPlainTextPkce { get; set; }

    public bool AllowRememberConsent { get; set; } = true;

    public List<string> AllowedGrantTypes { get; set; } = [];

    public List<string> AuthorizationPromptTypes { get; set; } = [];

    public List<string> IdentityProviderRestrictions { get; set; } = [];

    public List<string> AllowedCorsOrigins { get; set; } = [];

    public List<string> AllowedScopes { get; set; } = [];

    public int AuthorizationCodeLifetime { get; set; } = 300;

    public string? ClientName { get; set; }

    public List<SecretInput> ClientSecrets { get; set; } = [];

    public int ClientType { get; set; }

    public string? ClientUri { get; set; }

    public int DeviceCodeLifetime { get; set; } = 300;

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public List<string> RedirectUris { get; set; } = [];

    public string? LogoUri { get; set; }

    public int RefreshTokenLifetime { get; set; } = 86400;

    public bool RequireClientSecret { get; set; } = true;

    public bool RequireConsent { get; set; }

    public bool RequirePkce { get; set; } = true;
}

public class SecretInput
{
    public string? Description { get; set; }

    public string? Type { get; set; }

    public required string Value { get; set; }
}