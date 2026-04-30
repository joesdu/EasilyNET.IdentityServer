using System.Security.Cryptography;
using System.Text;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 持久化签名服务 - 使用数据库存储密钥
/// </summary>
public class PersistentSigningService : ISigningService, IDisposable
{
    private readonly IdentityServerOptions _options;
    private readonly ILogger<PersistentSigningService> _logger;
    private readonly ISigningKeyStore _keyStore;
    private readonly Timer _rotationTimer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private RSA? _lastPublicKey;
    private bool _disposed;

    public PersistentSigningService(
        ISigningKeyStore keyStore,
        IOptions<IdentityServerOptions> options,
        ILogger<PersistentSigningService> logger)
    {
        _keyStore = keyStore;
        _options = options.Value;
        _logger = logger;

        // Timer dueTime must stay within Int32.MaxValue milliseconds.
        var rotationInterval = TimeSpan.FromDays(30);
        _rotationTimer = new Timer(
            async _ => await RotateKeysAsync(),
            null,
            rotationInterval,
            rotationInterval);

        // 启动时确保有活动密钥
        _ = EnsureActiveKeyExistsAsync();
    }

    /// <inheritdoc />
    public async Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var key = await _keyStore.GetActiveKeyAsync(cancellationToken);
            if (key == null)
            {
                _logger.LogWarning("No active signing key found, creating new one");
                key = await CreateNewKeyAsync(cancellationToken);
            }

            return ConvertToResult(key);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IEnumerable<SigningKeyResult>> GetAllSigningKeysAsync(CancellationToken cancellationToken = default)
    {
        var keys = await _keyStore.GetAllKeysAsync(cancellationToken);
        return keys.Where(k => !k.IsDisabled).Select(ConvertToResult);
    }

    /// <inheritdoc />
    public async Task RotateKeysAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Starting key rotation");

            // 禁用当前活动密钥
            var currentKey = await _keyStore.GetActiveKeyAsync(cancellationToken);
            if (currentKey != null)
            {
                await _keyStore.DisableKeyAsync(currentKey.KeyId, cancellationToken);
                _logger.LogInformation("Disabled key {KeyId}", currentKey.KeyId);
            }

            // 创建新密钥
            var newKey = await CreateNewKeyAsync(cancellationToken);
            _logger.LogInformation("Created new key {KeyId}", newKey.KeyId);

            // 清理过期密钥（保留最近5个）
            await CleanupOldKeysAsync(cancellationToken);

            _logger.LogInformation("Key rotation completed");
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<SigningKey> CreateNewKeyAsync(CancellationToken cancellationToken)
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);

        var keyId = Guid.NewGuid().ToString("N")[..16];
        var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
        var privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);

        // 这里应该加密存储私钥，简化示例使用明文
        // 生产环境应使用：var encryptedPrivateKey = EncryptPrivateKey(privateKeyBase64);

        var signingKey = new SigningKey
        {
            KeyId = keyId,
            Algorithm = "RS256",
            CreatedAt = DateTime.UtcNow,
            PrivateKey = privateKeyBase64,
            Modulus = Convert.ToBase64String(parameters.Modulus!),
            Exponent = Convert.ToBase64String(parameters.Exponent!),
            Usage = "sig"
        };

        await _keyStore.StoreKeyAsync(signingKey, cancellationToken);
        return signingKey;
    }

    private SigningKeyResult ConvertToResult(SigningKey key)
    {
        var rsa = RSA.Create();
        var privateKeyBytes = Convert.FromBase64String(key.PrivateKey);
        rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

        var rsaKey = new RsaSecurityKey(rsa.ExportParameters(true))
        {
            KeyId = key.KeyId
        };
        var publicKey = RSA.Create();
        publicKey.ImportParameters(rsa.ExportParameters(false));
        var previousPublicKey = Interlocked.Exchange(ref _lastPublicKey, publicKey);
        previousPublicKey?.Dispose();

        return new SigningKeyResult
        {
            KeyId = key.KeyId,
            Algorithm = key.Algorithm,
            Key = rsaKey,
            Credentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256),
            IsDisabled = key.IsDisabled
        };
    }

    private async Task CleanupOldKeysAsync(CancellationToken cancellationToken)
    {
        var keys = (await _keyStore.GetAllKeysAsync(cancellationToken))
            .Where(k => k.IsDisabled)
            .OrderByDescending(k => k.DisabledAt)
            .Skip(5) // 保留最近5个禁用密钥
            .ToList();

        foreach (var key in keys)
        {
            // 删除超过90天的旧密钥
            if (key.DisabledAt.HasValue &&
                key.DisabledAt.Value < DateTime.UtcNow.AddDays(-90))
            {
                await _keyStore.RemoveExpiredKeysAsync(key.DisabledAt.Value, cancellationToken);
                _logger.LogInformation("Removed old key {KeyId}", key.KeyId);
            }
        }
    }

    private async Task EnsureActiveKeyExistsAsync()
    {
        try
        {
            var activeKey = await _keyStore.GetActiveKeyAsync();
            if (activeKey == null)
            {
                _logger.LogInformation("No active key found on startup, creating initial key");
                await CreateNewKeyAsync(CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ensure active key exists");
        }
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _rotationTimer?.Dispose();
        _lock?.Dispose();
        _lastPublicKey?.Dispose();
    }

    /// <inheritdoc />
    public RSA? GetPublicKey()
    {
        if (_lastPublicKey == null)
        {
            return null;
        }

        var publicParameters = _lastPublicKey.ExportParameters(false);
        var copy = RSA.Create();
        copy.ImportParameters(publicParameters);
        return copy;
    }
}
