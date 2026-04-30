using System.Globalization;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;
using EasilyNET.IdentityServer.Host.Middleware;
using EasilyNET.IdentityServer.Host.Stores;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

var builder = WebApplication.CreateBuilder(args);

// 添加Serilog配置
builder.Host.UseSerilog((hbc, lc) =>
{
    var logLevel = hbc.HostingEnvironment.IsDevelopment() ? LogEventLevel.Information : LogEventLevel.Error;
    lc.ReadFrom.Configuration(hbc.Configuration)
      .MinimumLevel.Override("Microsoft", logLevel)
      .MinimumLevel.Override("System", logLevel)
      // 添加下面这行来过滤掉 Microsoft.Extensions.Resilience 的日志
      .MinimumLevel.Override("Polly", LogEventLevel.Warning)
      .MinimumLevel.Override("Microsoft.AspNetCore", logLevel)
      .MinimumLevel.Override("Microsoft.AspNetCore.Cors.Infrastructure.CorsService", logLevel)
      .MinimumLevel.Override("Microsoft.AspNetCore.Mvc", logLevel)
      .MinimumLevel.Override("Microsoft.AspNetCore.Hosting", logLevel)
      .Enrich.FromLogContext()
      .WriteTo.Async(wt =>
      {
          wt.Console(theme: AnsiConsoleTheme.Code);
          if (hbc.HostingEnvironment.IsDevelopment())
          {
              wt.Debug();
          }
          if (hbc.HostingEnvironment.IsProduction())
          {
              wt.Map(le => (le.Timestamp.DateTime, le.Level), (key, log) =>
                  log.Async(o => o.File(Path.Combine(AppContext.BaseDirectory, "logs", key.Level.ToString(), ".log"),
                      shared: true, formatProvider: CultureInfo.CurrentCulture,
                      retainedFileTimeLimit: TimeSpan.FromDays(7), rollingInterval: RollingInterval.Day)));
          }
      });
});

// 配置 IdentityServer
builder.Services.AddIdentityServer(options =>
{
    options.Issuer = "https://localhost:7020";
    options.AccessTokenLifetime = 3600;
    options.RefreshTokenLifetime = 86400;
    options.AuthorizationCodeLifetime = 300;
    options.RequirePkce = true;
    options.RequireConsent = false;
});

// 注册数据存储服务 (使用内存存储作为开发环境)
builder.Services.AddSingleton<IClientStore, InMemoryClientStore>();
builder.Services.AddSingleton<IResourceStore, InMemoryResourceStore>();
builder.Services.AddSingleton<IPersistedGrantStore, InMemoryPersistedGrantStore>();
builder.Services.AddSingleton<IDeviceFlowStore, InMemoryDeviceFlowStore>();
builder.Services.AddSingleton<IUserConsentStore, InMemoryUserConsentStore>();
builder.Services.AddSingleton<IAuthorizationAccountService, InMemoryAuthorizationAccountService>();
builder.Services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
builder.Services.AddSingleton<IAuditLogStore, InMemoryAuditLogStore>();

// 注册核心服务
builder.Services.AddSingleton<ISerializationService, SerializationService>();
builder.Services.AddSingleton<IAuthorizationRequestContextService, AuthorizationRequestContextService>();
builder.Services.AddSingleton<IAuthorizationScopeMetadataService, AuthorizationScopeMetadataService>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IJwtClientAuthenticationValidator, JwtClientAuthenticationValidator>();
builder.Services.AddSingleton<IMtlsClientAuthenticationValidator, MtlsClientAuthenticationValidator>();
builder.Services.AddSingleton<IDPoPService, DPoPService>();
builder.Services.AddSingleton<IClientAuthenticationService, ClientAuthenticationService>();
builder.Services.AddSingleton<IAuthorizationService, AuthorizationService>();
builder.Services.AddSingleton<IAuditService, AuditService>();
builder.Services.AddSingleton<IDynamicClientRegistrationService, DynamicClientRegistrationService>();

builder.Services.AddHttpClient();

// 注册 JWT 客户端认证验证器 (RFC 7523)
builder.Services.AddSingleton<JwtClientAuthenticationValidator>();

// 注册 HttpClient 用于获取远程 JWKS
builder.Services.AddHttpClient("JwksClient").ConfigureHttpClient(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

// 注册 HttpContextAccessor（审计服务和速率限制服务需要）
builder.Services.AddHttpContextAccessor();

// 注册速率限制服务
builder.Services.AddRateLimiting(options =>
{
    options.Enabled = true;
    options.IncludeHeaders = true;

    // 可以根据环境调整限制
    if (builder.Environment.IsDevelopment())
    {
        // 开发环境放宽限制
        options.IpLimits.ForEach(l => l.MaxRequests *= 2);
        options.ClientLimits.ForEach(l => l.MaxRequests *= 2);
    }
});

// 注册签名服务 - 使用持久化版本（生产环境）
// 如需使用内存版本（开发环境），将 PersistentSigningService 改为 DefaultSigningService
builder.Services.AddSingleton<ISigningService, PersistentSigningService>();

// 注册数据库清理后台服务（持久化存储启用后将自动执行过期清理）
builder.Services.AddHostedService<DatabaseCleanupService>();

// 注册 Token 响应生成器
builder.Services.AddTransient<ITokenResponseGenerator, DefaultTokenResponseGenerator>();

// 添加控制器
builder.Services.AddControllers();

// 添加 Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();
var app = builder.Build();

// 配置中间件
app.UseSerilogRequestLogging();
app.UseForwardedClientCertificate();

app.Use(async (context, next) =>
{
    if (!app.Environment.IsDevelopment() &&
        IsOAuthEndpoint(context.Request.Path) &&
        !context.Request.IsHttps)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = "HTTPS is required for OAuth endpoints" });
        return;
    }

    await next();
});

app.Use(async (context, next) =>
{
    var origin = context.Request.Headers.Origin.ToString();
    if (string.IsNullOrEmpty(origin) || !IsCorsEnabledOAuthEndpoint(context.Request.Path))
    {
        await next();
        return;
    }

    var clientStore = context.RequestServices.GetRequiredService<IClientStore>();
    var clients = await clientStore.FindEnabledClientsAsync(context.RequestAborted);
    var allowed = clients.Any(client => client.AllowedCorsOrigins.Any(allowedOrigin => string.Equals(allowedOrigin, origin, StringComparison.Ordinal)));
    if (allowed)
    {
        context.Response.Headers.AccessControlAllowOrigin = origin;
        context.Response.Headers.Vary = "Origin";
        context.Response.Headers.AccessControlAllowHeaders = "Content-Type, Authorization";
        context.Response.Headers.AccessControlAllowMethods = "POST, GET, OPTIONS";
    }

    if (HttpMethods.IsOptions(context.Request.Method))
    {
        context.Response.StatusCode = allowed ? StatusCodes.Status204NoContent : StatusCodes.Status403Forbidden;
        return;
    }

    await next();
});

// 速率限制中间件（必须在审计日志之前，以便在限制时也能记录）
app.UseRateLimiting();

// 审计日志中间件
app.UseAuditLogging();

// 安全响应头中间件 (RFC 7033 - WebFinger, 安全最佳实践)
app.Use(async (context, next) =>
{
    // 点击劫持保护
    context.Response.Headers["X-Frame-Options"] = "DENY";

    // 内容安全策略
    context.Response.Headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'self'; default-src 'self'";

    // 防止 MIME 类型 sniffing
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";

    // XSS 保护
    context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";

    // 引用来源策略
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

    // 权限策略
    context.Response.Headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), interest-cohort=()";

    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// 健康检查端点
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));
app.Run();

static bool IsOAuthEndpoint(PathString path) => path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase);

static bool IsCorsEnabledOAuthEndpoint(PathString path) =>
    path.StartsWithSegments("/connect/token", StringComparison.OrdinalIgnoreCase) ||
    path.StartsWithSegments("/connect/userinfo", StringComparison.OrdinalIgnoreCase) ||
    path.StartsWithSegments("/connect/revocation", StringComparison.OrdinalIgnoreCase) ||
    path.StartsWithSegments("/connect/introspect", StringComparison.OrdinalIgnoreCase) ||
    path.StartsWithSegments("/connect/device_authorization", StringComparison.OrdinalIgnoreCase);

/// <summary>
/// Entry point for WebApplicationFactory in integration tests
/// </summary>
public partial class Program;
