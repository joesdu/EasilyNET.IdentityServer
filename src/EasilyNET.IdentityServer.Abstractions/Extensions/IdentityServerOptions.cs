using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Abstractions.Extensions;

/// <summary>
/// IdentityServer 服务扩展方法
/// </summary>
public static class IdentityServerServiceExtensions
{
    /// <summary>
    /// 添加 IdentityServer 核心服务
    /// </summary>
    public static IServiceCollection AddIdentityServerCore(this IServiceCollection services) =>
        // 注册核心服务 - 由 Core 项目实现
        services;
}

/// <summary>
/// 服务集合扩展
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 添加所有 IdentityServer 服务
    /// </summary>
    public static IServiceCollection AddIdentityServer(this IServiceCollection services, Action<IdentityServerOptions>? configure = null)
    {
        var options = new IdentityServerOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton(Options.Create(options));

        // 添加核心服务
        services.AddIdentityServerCore();
        return services;
    }
}

/// <summary>
/// IdentityServer 配置选项
/// </summary>
public class IdentityServerOptions
{
    /// <summary>
    /// 绝对刷新令牌生命周期（秒）
    /// </summary>
    public int AbsoluteRefreshTokenLifetime { get; set; } = 2592000; // 30天

    /// <summary>
    /// 访问令牌生命周期（秒）
    /// </summary>
    public int AccessTokenLifetime { get; set; } = 3600;

    /// <summary>
    /// 是否允许纯文本 PKCE
    /// </summary>
    public bool AllowPlainTextPkce { get; set; } = false;

    /// <summary>
    /// 是否允许刷新令牌重用
    /// </summary>
    public bool AllowRefreshTokenReuse { get; set; } = false;

    /// <summary>
    /// 是否允许 Remember Consent
    /// </summary>
    public bool AllowRememberConsent { get; set; } = true;

    /// <summary>
    /// 授权码生命周期（秒）
    /// </summary>
    public int AuthorizationCodeLifetime { get; set; } = 300;

    /// <summary>
    /// 用户Consent持久化超时（秒）
    /// </summary>
    public int ConsentLifetime { get; set; } = 30 * 86400; // 30天

    /// <summary>
    /// 设备代码生命周期（秒）
    /// </summary>
    public int DeviceCodeLifetime { get; set; } = 300;

    /// <summary>
    /// 是否启用绝对刷新令牌过期
    /// </summary>
    public bool EnableAbsoluteRefreshTokenLifetime { get; set; } = true;

    /// <summary>
    /// 颁发者名称
    /// </summary>
    public string Issuer { get; set; } = "https://identityserver.example.com";

    /// <summary>
    /// 对外暴露的授权交互入口路径（同域稳定入口）
    /// </summary>
    public string InteractionPageEntryPath { get; set; } = "/connect/authorize/interaction/page";

    /// <summary>
    /// 最终前端授权交互页面地址，可为绝对 URL 或相对路径
    /// </summary>
    public string InteractionPagePath { get; set; } = "/authorize/interaction";

    /// <summary>
    /// 允许的访问令牌签名算法
    /// </summary>
    public ICollection<string> AllowedAccessTokenSigningAlgorithms { get; set; } = new[] { "RS256", "RS384", "RS512" };

    /// <summary>
    /// 允许的 Identity Token 签名算法
    /// </summary>
    public ICollection<string> AllowedIdentityTokenSigningAlgorithms { get; set; } = new[] { "RS256", "RS384", "RS512" };

    /// <summary>
    /// 刷新令牌生命周期（秒）
    /// </summary>
    public int RefreshTokenLifetime { get; set; } = 86400;

    /// <summary>
    /// 是否需要Consent
    /// </summary>
    public bool RequireConsent { get; set; } = true;

    /// <summary>
    /// 是否需要 PKCE
    /// </summary>
    public bool RequirePkce { get; set; } = true;
}