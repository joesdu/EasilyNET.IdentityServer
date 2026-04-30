using EasilyNET.IdentityServer.Abstractions.Models;

namespace EasilyNET.IdentityServer.Abstractions.Stores;

/// <summary>
/// 客户端存储接口
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// 创建客户端
    /// </summary>
    Task CreateClientAsync(Client client, CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据客户端Id查找客户端
    /// </summary>
    Task<Client?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// 查找所有启用的客户端
    /// </summary>
    Task<IEnumerable<Client>> FindEnabledClientsAsync(CancellationToken cancellationToken = default);
}