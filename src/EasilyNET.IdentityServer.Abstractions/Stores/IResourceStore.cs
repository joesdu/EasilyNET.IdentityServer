using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 资源存储接口
/// </summary>
public interface IResourceStore
{
    /// <summary>
    /// 查找所有启用的 API 资源
    /// </summary>
    Task<IEnumerable<ApiResource>> FindEnabledApiResourcesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 查找所有启用的 Identity 资源
    /// </summary>
    Task<IEnumerable<IdentityResource>> FindEnabledIdentityResourcesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据作用域名称查找 API 资源
    /// </summary>
    Task<IEnumerable<ApiResource>> FindApiResourcesByScopeAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default);

    /// <summary>
    /// 查找所有启用的 API 作用域
    /// </summary>
    Task<IEnumerable<ApiScope>> FindEnabledScopesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据作用域名称查找 API 作用域
    /// </summary>
    Task<IEnumerable<ApiScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default);

    /// <summary>
    /// 获取所有资源
    /// </summary>
    Task<Resources> GetAllResourcesAsync(CancellationToken cancellationToken = default);
}