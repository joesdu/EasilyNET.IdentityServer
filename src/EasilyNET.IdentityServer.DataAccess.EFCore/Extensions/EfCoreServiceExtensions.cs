using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.DataAccess.EFCore.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EasilyNET.IdentityServer.DataAccess.EFCore.Extensions;

/// <summary>
/// EF Core 数据访问层 DI 扩展
/// </summary>
public static class EfCoreServiceExtensions
{
    /// <summary>
    /// 添加 EF Core 数据存储 (通用，需自行配置 DbContext)
    /// </summary>
    public static IServiceCollection AddIdentityServerEfCore(this IServiceCollection services, Action<DbContextOptionsBuilder> configureDb)
    {
        services.AddDbContext<IdentityServerDbContext>(configureDb);
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IResourceStore, EfResourceStore>();
        services.AddScoped<IPersistedGrantStore, EfPersistedGrantStore>();
        services.AddScoped<IDeviceFlowStore, EfDeviceFlowStore>();
        services.AddScoped<IUserConsentStore, EfUserConsentStore>();
        return services;
    }
}