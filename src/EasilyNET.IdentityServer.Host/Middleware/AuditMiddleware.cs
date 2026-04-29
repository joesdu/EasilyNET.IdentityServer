using EasilyNET.IdentityServer.Abstractions.Services;

namespace EasilyNET.IdentityServer.Host.Middleware;

/// <summary>
/// 审计中间件
/// </summary>
public class AuditMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditMiddleware> _logger;

    public AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IAuditService auditService)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";

        // 只记录 OAuth 相关端点
        if (ShouldAudit(path))
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var originalBodyStream = context.Response.Body;

            try
            {
                await _next(context);
                stopwatch.Stop();

                // 记录成功的请求
                await LogAuditEventAsync(context, auditService, true, null, stopwatch.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                await LogAuditEventAsync(context, auditService, false, ex.Message, stopwatch.ElapsedMilliseconds);
                throw;
            }
        }
        else
        {
            await _next(context);
        }
    }

    private static bool ShouldAudit(string path)
    {
        return path.Contains("/connect/token") ||
               path.Contains("/connect/authorize") ||
               path.Contains("/connect/introspect") ||
               path.Contains("/connect/revocation") ||
               path.Contains("/connect/device");
    }

    private async Task LogAuditEventAsync(HttpContext context, IAuditService auditService, bool success, string? error, long durationMs)
    {
        try
        {
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            var clientId = GetClientId(context);
            var ipAddress = GetClientIpAddress(context);

            if (path.Contains("/connect/token"))
            {
                // Token 端点日志在控制器中记录，这里只记录请求到达
                _logger.LogDebug("Token endpoint request from {ClientId} at {IpAddress} - {Status} in {DurationMs}ms",
                    clientId, ipAddress, success ? "Success" : "Failed", durationMs);
            }
            else if (path.Contains("/connect/authorize"))
            {
                _logger.LogDebug("Authorization endpoint request from {ClientId} at {IpAddress} - {Status} in {DurationMs}ms",
                    clientId, ipAddress, success ? "Success" : "Failed", durationMs);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log audit event");
        }
    }

    private static string? GetClientId(HttpContext context)
    {
        // 尝试从表单或查询参数获取 client_id
        if (context.Request.HasFormContentType)
        {
            return context.Request.Form["client_id"].FirstOrDefault();
        }
        return context.Request.Query["client_id"].FirstOrDefault();
    }

    private static string? GetClientIpAddress(HttpContext context)
    {
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }
        return context.Connection.RemoteIpAddress?.ToString();
    }
}

/// <summary>
/// 审计中间件扩展方法
/// </summary>
public static class AuditMiddlewareExtensions
{
    public static IApplicationBuilder UseAuditLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AuditMiddleware>();
    }
}
