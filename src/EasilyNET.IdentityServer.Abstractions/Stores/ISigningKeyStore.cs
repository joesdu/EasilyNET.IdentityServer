using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 签名密钥存储接口
/// </summary>
public interface ISigningKeyStore
{
    /// <summary>
    /// 获取所有有效密钥
    /// </summary>
    Task<IEnumerable<SigningKey>> GetAllKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取当前活动密钥
    /// </summary>
    Task<SigningKey?> GetActiveKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 存储密钥
    /// </summary>
    Task StoreKeyAsync(SigningKey key, CancellationToken cancellationToken = default);

    /// <summary>
    /// 禁用密钥
    /// </summary>
    Task DisableKeyAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 删除过期密钥
    /// </summary>
    Task RemoveExpiredKeysAsync(DateTime cutoff, CancellationToken cancellationToken = default);
}
