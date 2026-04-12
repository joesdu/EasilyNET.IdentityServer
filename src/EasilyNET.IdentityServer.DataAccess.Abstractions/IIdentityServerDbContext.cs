namespace EasilyNET.IdentityServer.DataAccess.Abstractions;

/// <summary>
/// IdentityServer 数据库上下文接口
/// </summary>
public interface IIdentityServerDbContext
{
    /// <summary>
    /// 保存更改
    /// </summary>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}