using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.PostgreSQL.Extensions;

/// <summary>
/// PostgreSQL 数据访问层 DI 扩展
/// </summary>
public static class PostgreSqlServiceExtensions
{
    /// <summary>
    /// 使用 PostgreSQL
    /// </summary>
    public static IServiceCollection AddIdentityServerPostgreSql(this IServiceCollection services, string connectionString)
    {
        services.AddDbContext<IdentityServerDbContext>(options => options.UseNpgsql(connectionString));
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IResourceStore, EfResourceStore>();
        services.AddScoped<IPersistedGrantStore, EfPersistedGrantStore>();
        services.AddScoped<IDeviceFlowStore, EfDeviceFlowStore>();
        services.AddScoped<IUserConsentStore, EfUserConsentStore>();
        return services;
    }
}