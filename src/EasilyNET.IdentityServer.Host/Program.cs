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
builder.Services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
builder.Services.AddSingleton<IAuditLogStore, InMemoryAuditLogStore>();

// 注册核心服务
builder.Services.AddSingleton<ISerializationService, SerializationService>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IClientAuthenticationService, ClientAuthenticationService>();
builder.Services.AddSingleton<IAuthorizationService, AuthorizationService>();
builder.Services.AddSingleton<IAuditService, AuditService>();

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

// 注册数据库清理服务 (仅在使用 EF Core/MongoDB 存储时需要,内存存储不需要)
builder.Services.AddSingleton<DatabaseCleanupService>();

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

/// <summary>
/// Entry point for WebApplicationFactory in integration tests
/// </summary>
public partial class Program;