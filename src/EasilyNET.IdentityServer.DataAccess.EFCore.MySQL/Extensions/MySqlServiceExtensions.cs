using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.MySQL.Extensions;

/// <summary>
/// MySQL 数据访问层 DI 扩展
/// </summary>
public static class MySqlServiceExtensions
{
    /// <summary>
    /// 使用 MySQL
    /// </summary>
    public static IServiceCollection AddIdentityServerMySql(this IServiceCollection services, string connectionString, ServerVersion serverVersion)
    {
        services.AddDbContext<IdentityServerDbContext>(options => options.UseMySql(connectionString, serverVersion));
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IResourceStore, EfResourceStore>();
        services.AddScoped<IPersistedGrantStore, EfPersistedGrantStore>();
        services.AddScoped<IDeviceFlowStore, EfDeviceFlowStore>();
        services.AddScoped<IUserConsentStore, EfUserConsentStore>();
        services.AddScoped<ISigningKeyStore, EfSigningKeyStore>();
        services.AddScoped<IAuditLogStore, EfAuditLogStore>();
        return services;
    }
}
