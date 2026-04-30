using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Sqlite.Extensions;

/// <summary>
/// SQLite 数据访问层 DI 扩展
/// </summary>
public static class SqliteServiceExtensions
{
    /// <summary>
    /// 使用 SQLite
    /// </summary>
    public static IServiceCollection AddIdentityServerSqlite(this IServiceCollection services, string connectionString)
    {
        services.AddDbContext<IdentityServerDbContext>(options => options.UseSqlite(connectionString));
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
