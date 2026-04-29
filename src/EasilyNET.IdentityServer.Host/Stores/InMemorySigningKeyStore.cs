using System.Collections.Concurrent;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;

namespace EasilyNET.IdentityServer.Host.Stores;

/// <summary>
/// 内存签名密钥存储（开发环境使用）
/// </summary>
public class InMemorySigningKeyStore : ISigningKeyStore
{
    private readonly ConcurrentDictionary<string, SigningKey> _keys = new();
    private readonly object _lock = new();

    public Task<IEnumerable<SigningKey>> GetAllKeysAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return Task.FromResult(_keys.Values.AsEnumerable());
        }
    }

    public Task<SigningKey?> GetActiveKeyAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var activeKey = _keys.Values
                .Where(k => !k.IsDisabled)
                .OrderByDescending(k => k.CreatedAt)
                .FirstOrDefault();
            return Task.FromResult(activeKey);
        }
    }

    public Task StoreKeyAsync(SigningKey key, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _keys[key.KeyId] = key;
        }
        return Task.CompletedTask;
    }

    public Task DisableKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_keys.TryGetValue(keyId, out var key))
            {
                var disabledKey = new SigningKey
                {
                    KeyId = key.KeyId,
                    Algorithm = key.Algorithm,
                    CreatedAt = key.CreatedAt,
                    PrivateKey = key.PrivateKey,
                    Modulus = key.Modulus,
                    Exponent = key.Exponent,
                    DisabledAt = DateTime.UtcNow
                };
                _keys[keyId] = disabledKey;
            }
        }
        return Task.CompletedTask;
    }

    public Task RemoveExpiredKeysAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var keysToRemove = _keys.Values
                .Where(k => k.IsDisabled && k.DisabledAt.HasValue && k.DisabledAt.Value < cutoff)
                .Select(k => k.KeyId)
                .ToList();

            foreach (var keyId in keysToRemove)
            {
                _keys.TryRemove(keyId, out _);
            }
        }
        return Task.CompletedTask;
    }
}
