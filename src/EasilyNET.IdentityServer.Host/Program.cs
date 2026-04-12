using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;
using EasilyNET.IdentityServer.Host.Stores;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// 配置 Serilog
Log.Logger = new LoggerConfiguration()
             .ReadFrom.Configuration(builder.Configuration)
             .CreateLogger();
builder.Host.UseSerilog();

// 配置 IdentityServer
builder.Services.AddIdentityServer(options =>
{
    options.Issuer = "https://localhost:5001";
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

// 注册核心服务
builder.Services.AddSingleton<ISerializationService, SerializationService>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddSingleton<IClientAuthenticationService, ClientAuthenticationService>();
builder.Services.AddSingleton<IAuthorizationService, AuthorizationService>();
builder.Services.AddSingleton<ISigningService, DefaultSigningService>();

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