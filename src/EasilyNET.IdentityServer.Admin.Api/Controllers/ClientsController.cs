using EasilyNET.IdentityServer.DataAccess.EFCore;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.Admin.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClientsController(IdentityServerDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var clients = await db.Clients
                              .Include(c => c.AllowedGrantTypes)
                              .Include(c => c.AllowedScopes)
                              .Include(c => c.RedirectUris)
                              .Select(c => new
                              {
                                  c.Id, c.ClientId, c.ClientName, c.Description, c.Enabled, c.ClientType,
                                  c.RequirePkce, c.RequireClientSecret, c.RequireConsent,
                                  c.AccessTokenLifetime, c.RefreshTokenLifetime,
                                  AllowedGrantTypes = c.AllowedGrantTypes.Select(g => g.GrantType),
                                  AllowedScopes = c.AllowedScopes.Select(s => s.Scope),
                                  RedirectUris = c.RedirectUris.Select(r => r.RedirectUri)
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
                             .Include(c => c.Claims).Include(c => c.AllowedCorsOrigins).Include(c => c.Properties)
                             .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (client == null)
        {
            return NotFound();
        }
        return Ok(client);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateClientRequest request, CancellationToken ct)
    {
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
            AccessTokenLifetime = request.AccessTokenLifetime,
            RefreshTokenLifetime = request.RefreshTokenLifetime,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
            AllowedGrantTypes = request.AllowedGrantTypes.Select(g => new ClientGrantTypeEntity { GrantType = g }).ToList(),
            AllowedScopes = request.AllowedScopes.Select(s => new ClientScopeEntity { Scope = s }).ToList(),
            RedirectUris = request.RedirectUris.Select(r => new ClientRedirectUriEntity { RedirectUri = r }).ToList(),
            ClientSecrets = request.ClientSecrets.Select(s => new ClientSecretEntity { Value = s.Value, Description = s.Description, Type = s.Type ?? "SharedSecret" }).ToList()
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
                             .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (entity == null)
        {
            return NotFound();
        }
        entity.ClientName = request.ClientName;
        entity.Description = request.Description;
        entity.Enabled = request.Enabled;
        entity.ClientType = request.ClientType;
        entity.RequirePkce = request.RequirePkce;
        entity.RequireClientSecret = request.RequireClientSecret;
        entity.RequireConsent = request.RequireConsent;
        entity.AccessTokenLifetime = request.AccessTokenLifetime;
        entity.RefreshTokenLifetime = request.RefreshTokenLifetime;
        entity.Updated = DateTime.UtcNow;

        // 替换子集合
        entity.AllowedGrantTypes.Clear();
        entity.AllowedGrantTypes.AddRange(request.AllowedGrantTypes.Select(g => new ClientGrantTypeEntity { GrantType = g }));
        entity.AllowedScopes.Clear();
        entity.AllowedScopes.AddRange(request.AllowedScopes.Select(s => new ClientScopeEntity { Scope = s }));
        entity.RedirectUris.Clear();
        entity.RedirectUris.AddRange(request.RedirectUris.Select(r => new ClientRedirectUriEntity { RedirectUri = r }));
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
}

public class CreateClientRequest
{
    public required string ClientId { get; set; }

    public string? ClientName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public int ClientType { get; set; }

    public bool RequirePkce { get; set; } = true;

    public bool RequireClientSecret { get; set; } = true;

    public bool RequireConsent { get; set; }

    public int AccessTokenLifetime { get; set; } = 3600;

    public int RefreshTokenLifetime { get; set; } = 86400;

    public int AuthorizationCodeLifetime { get; set; } = 300;

    public List<string> AllowedGrantTypes { get; set; } = [];

    public List<string> AllowedScopes { get; set; } = [];

    public List<string> RedirectUris { get; set; } = [];

    public List<SecretInput> ClientSecrets { get; set; } = [];
}

public class UpdateClientRequest
{
    public string? ClientName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public int ClientType { get; set; }

    public bool RequirePkce { get; set; } = true;

    public bool RequireClientSecret { get; set; } = true;

    public bool RequireConsent { get; set; }

    public int AccessTokenLifetime { get; set; } = 3600;

    public int RefreshTokenLifetime { get; set; } = 86400;

    public List<string> AllowedGrantTypes { get; set; } = [];

    public List<string> AllowedScopes { get; set; } = [];

    public List<string> RedirectUris { get; set; } = [];
}

public class SecretInput
{
    public required string Value { get; set; }

    public string? Description { get; set; }

    public string? Type { get; set; }
}