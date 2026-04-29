using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.Abstractions;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Stores;

/// <summary>
/// EF Core 签名密钥存储
/// </summary>
public class EfSigningKeyStore : ISigningKeyStore
{
    private readonly IIdentityServerDbContext _context;

    public EfSigningKeyStore(IIdentityServerDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<SigningKey>> GetAllKeysAsync(CancellationToken cancellationToken = default)
    {
        var entities = await _context.SigningKeys
            .AsNoTracking()
            .OrderByDescending(k => k.CreatedAt)
            .ToListAsync(cancellationToken);

        return entities.Select(ToModel);
    }

    public async Task<SigningKey?> GetActiveKeyAsync(CancellationToken cancellationToken = default)
    {
        var entity = await _context.SigningKeys
            .AsNoTracking()
            .Where(k => !k.DisabledAt.HasValue)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        return entity == null ? null : ToModel(entity);
    }

    public async Task StoreKeyAsync(SigningKey key, CancellationToken cancellationToken = default)
    {
        var entity = ToEntity(key);
        _context.SigningKeys.Add(entity);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task DisableKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        var entity = await _context.SigningKeys
            .FirstOrDefaultAsync(k => k.KeyId == keyId, cancellationToken);

        if (entity != null)
        {
            entity.DisabledAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RemoveExpiredKeysAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        var keysToRemove = await _context.SigningKeys
            .Where(k => k.DisabledAt.HasValue && k.DisabledAt.Value < cutoff)
            .ToListAsync(cancellationToken);

        _context.SigningKeys.RemoveRange(keysToRemove);
        await _context.SaveChangesAsync(cancellationToken);
    }

    private static SigningKey ToModel(SigningKeyEntity entity)
    {
        return new SigningKey
        {
            KeyId = entity.KeyId,
            Algorithm = entity.Algorithm,
            CreatedAt = entity.CreatedAt,
            DisabledAt = entity.DisabledAt,
            PrivateKey = entity.PrivateKey,
            Modulus = entity.Modulus,
            Exponent = entity.Exponent,
            Usage = entity.Usage
        };
    }

    private static SigningKeyEntity ToEntity(SigningKey model)
    {
        return new SigningKeyEntity
        {
            KeyId = model.KeyId,
            Algorithm = model.Algorithm,
            CreatedAt = model.CreatedAt,
            DisabledAt = model.DisabledAt,
            PrivateKey = model.PrivateKey,
            Modulus = model.Modulus,
            Exponent = model.Exponent,
            Usage = model.Usage
        };
    }
}
