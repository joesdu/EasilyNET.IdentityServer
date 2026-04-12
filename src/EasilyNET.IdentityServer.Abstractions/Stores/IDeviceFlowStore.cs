using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 设备流代码存储接口
/// </summary>
public interface IDeviceFlowStore
{
    /// <summary>
    /// 存储设备代码
    /// </summary>
    Task StoreAsync(DeviceCodeData deviceCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据设备代码查找
    /// </summary>
    Task<DeviceCodeData?> FindByDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据用户代码查找
    /// </summary>
    Task<DeviceCodeData?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// 消费者代码
    /// </summary>
    Task ConsumeDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// 移除设备代码
    /// </summary>
    Task RemoveAsync(string deviceCode, CancellationToken cancellationToken = default);
}

/// <summary>
/// 用户 Consent 存储接口
/// </summary>
public interface IUserConsentStore
{
    /// <summary>
    /// 存储用户 Consent
    /// </summary>
    Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取用户 Consent
    /// </summary>
    Task<UserConsent?> GetAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 移除用户 Consent
    /// </summary>
    Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 移除主题下的所有 Consent
    /// </summary>
    Task RemoveAllAsync(string subjectId, CancellationToken cancellationToken = default);
}