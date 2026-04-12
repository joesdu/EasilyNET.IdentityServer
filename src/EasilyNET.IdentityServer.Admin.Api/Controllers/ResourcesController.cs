using EasilyNET.IdentityServer.DataAccess.EFCore;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.Admin.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApiResourcesController(IdentityServerDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var resources = await db.ApiResources
                                .Include(r => r.Scopes).Include(r => r.UserClaims)
                                .Select(r => new { r.Id, r.Name, r.DisplayName, r.Description, r.Enabled, Scopes = r.Scopes.Select(s => s.Scope), UserClaims = r.UserClaims.Select(c => c.Type) })
                                .ToListAsync(ct);
        return Ok(resources);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id, CancellationToken ct)
    {
        var resource = await db.ApiResources.Include(r => r.Scopes).Include(r => r.UserClaims).Include(r => r.ApiSecrets).Include(r => r.Properties)
                               .FirstOrDefaultAsync(r => r.Id == id, ct);
        if (resource == null)
        {
            return NotFound();
        }
        return Ok(resource);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateApiResourceRequest request, CancellationToken ct)
    {
        var entity = new ApiResourceEntity
        {
            Name = request.Name, DisplayName = request.DisplayName, Description = request.Description, Enabled = request.Enabled,
            Scopes = request.Scopes.Select(s => new ApiResourceScopeEntity { Scope = s }).ToList(),
            UserClaims = request.UserClaims.Select(c => new ApiResourceClaimEntity { Type = c }).ToList()
        };
        db.ApiResources.Add(entity);
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(Get), new { id = entity.Id }, new { entity.Id, entity.Name });
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] CreateApiResourceRequest request, CancellationToken ct)
    {
        var entity = await db.ApiResources.Include(r => r.Scopes).Include(r => r.UserClaims).FirstOrDefaultAsync(r => r.Id == id, ct);
        if (entity == null)
        {
            return NotFound();
        }
        entity.DisplayName = request.DisplayName;
        entity.Description = request.Description;
        entity.Enabled = request.Enabled;
        entity.Updated = DateTime.UtcNow;
        entity.Scopes.Clear();
        entity.Scopes.AddRange(request.Scopes.Select(s => new ApiResourceScopeEntity { Scope = s }));
        entity.UserClaims.Clear();
        entity.UserClaims.AddRange(request.UserClaims.Select(c => new ApiResourceClaimEntity { Type = c }));
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var entity = await db.ApiResources.FindAsync([id], ct);
        if (entity == null)
        {
            return NotFound();
        }
        db.ApiResources.Remove(entity);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}

public class CreateApiResourceRequest
{
    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public List<string> Scopes { get; set; } = [];

    public List<string> UserClaims { get; set; } = [];
}

[ApiController]
[Route("api/[controller]")]
public class ApiScopesController(IdentityServerDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var scopes = await db.ApiScopes.Include(s => s.UserClaims)
                             .Select(s => new { s.Id, s.Name, s.DisplayName, s.Description, s.Enabled, UserClaims = s.UserClaims.Select(c => c.Type) })
                             .ToListAsync(ct);
        return Ok(scopes);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateApiScopeRequest request, CancellationToken ct)
    {
        var entity = new ApiScopeEntity
        {
            Name = request.Name, DisplayName = request.DisplayName, Description = request.Description, Enabled = request.Enabled,
            Required = request.Required, Emphasize = request.Emphasize,
            UserClaims = request.UserClaims.Select(c => new ApiScopeClaimEntity { Type = c }).ToList()
        };
        db.ApiScopes.Add(entity);
        await db.SaveChangesAsync(ct);
        return Ok(new { entity.Id, entity.Name });
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var entity = await db.ApiScopes.FindAsync([id], ct);
        if (entity == null)
        {
            return NotFound();
        }
        db.ApiScopes.Remove(entity);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}

public class CreateApiScopeRequest
{
    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public bool Required { get; set; }

    public bool Emphasize { get; set; }

    public List<string> UserClaims { get; set; } = [];
}

[ApiController]
[Route("api/[controller]")]
public class IdentityResourcesController(IdentityServerDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var resources = await db.IdentityResources.Include(r => r.UserClaims)
                                .Select(r => new { r.Id, r.Name, r.DisplayName, r.Description, r.Enabled, r.Required, UserClaims = r.UserClaims.Select(c => c.Type) })
                                .ToListAsync(ct);
        return Ok(resources);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateIdentityResourceRequest request, CancellationToken ct)
    {
        var entity = new IdentityResourceEntity
        {
            Name = request.Name, DisplayName = request.DisplayName, Description = request.Description, Enabled = request.Enabled,
            Required = request.Required, Emphasize = request.Emphasize, ShowInDiscoveryDocument = request.ShowInDiscoveryDocument,
            UserClaims = request.UserClaims.Select(c => new IdentityResourceClaimEntity { Type = c }).ToList()
        };
        db.IdentityResources.Add(entity);
        await db.SaveChangesAsync(ct);
        return Ok(new { entity.Id, entity.Name });
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var entity = await db.IdentityResources.FindAsync([id], ct);
        if (entity == null)
        {
            return NotFound();
        }
        db.IdentityResources.Remove(entity);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}

public class CreateIdentityResourceRequest
{
    public required string Name { get; set; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public bool Required { get; set; }

    public bool Emphasize { get; set; }

    public bool ShowInDiscoveryDocument { get; set; } = true;

    public List<string> UserClaims { get; set; } = [];
}