using System.Net;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Core.Services;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Host.Middleware;

/// <summary>
/// 速率限制中间件
/// </summary>
public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitMiddleware> _logger;
    private readonly RateLimitOptions _options;

    public RateLimitMiddleware(
        RequestDelegate next,
        ILogger<RateLimitMiddleware> logger,
        IOptions<RateLimitOptions> options)
    {
        _next = next;
        _logger = logger;
        _options = options.Value;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IRateLimitService rateLimitService)
    {
        if (!_options.Enabled)
        {
            await _next(context);
            return;
        }

        var path = context.Request.Path.Value ?? "";

        // 只限制 OAuth 端点
        if (!IsOAuthEndpoint(path))
        {
            await _next(context);
            return;
        }

        // 获取限制类型
        var limitType = GetLimitTypeFromPath(path);

        // 获取客户端 IP
        var clientIp = GetClientIpAddress(context);

        // 获取客户端 ID（从查询参数或表单）
        var clientId = await GetClientIdAsync(context);

        // 检查是否在白名单中
        var rateLimitSvc = (RateLimitService)rateLimitService;
        if (rateLimitSvc.IsIpWhitelisted(clientIp) ||
            (!string.IsNullOrEmpty(clientId) && rateLimitSvc.IsClientWhitelisted(clientId)))
        {
            await _next(context);
            return;
        }

        // 检查 IP 级别限制
        var ipAllowed = await rateLimitService.IsAllowedAsync(clientIp, limitType);
        if (!ipAllowed)
        {
            await RejectRequestAsync(context, rateLimitService, clientIp, limitType, "IP");
            return;
        }

        // 检查客户端级别限制
        if (!string.IsNullOrEmpty(clientId))
        {
            var clientAllowed = await rateLimitService.IsAllowedAsync(clientId, limitType);
            if (!clientAllowed)
            {
                await RejectRequestAsync(context, rateLimitService, clientId, limitType, "Client");
                return;
            }
        }

        // 记录请求
        await rateLimitService.RecordRequestAsync(clientIp, limitType);
        if (!string.IsNullOrEmpty(clientId))
        {
            await rateLimitService.RecordRequestAsync(clientId, limitType);
        }

        // 添加响应头
        if (_options.IncludeHeaders)
        {
            await AddRateLimitHeadersAsync(context, rateLimitService, clientIp, clientId, limitType);
        }

        await _next(context);
    }

    private bool IsOAuthEndpoint(string path)
    {
        return path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith("/.well-known/", StringComparison.OrdinalIgnoreCase);
    }

    private RateLimitType GetLimitTypeFromPath(string path)
    {
        if (path.Contains("/connect/token", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.TokenEndpoint;
        if (path.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.AuthorizeEndpoint;
        if (path.Contains("/connect/device_authorization", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.DeviceAuthorizationEndpoint;
        if (path.Contains("/connect/device_verify", StringComparison.OrdinalIgnoreCase))
            return RateLimitType.VerifyEndpoint;

        return RateLimitType.General;
    }

    private async Task<string> GetClientIdAsync(HttpContext context)
    {
        // 从查询参数获取
        if (context.Request.Query.TryGetValue("client_id", out var queryClientId))
        {
            return queryClientId.ToString();
        }

        // 从表单获取（POST 请求）
        if (context.Request.Method == "POST" &&
            context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            if (form.TryGetValue("client_id", out var formClientId))
            {
                return formClientId.ToString();
            }
        }

        // 从 Authorization header 获取（Basic Auth）
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var credentials = authHeader.Substring("Basic ".Length).Trim();
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(credentials));
                var separatorIndex = decoded.IndexOf(':');
                if (separatorIndex > 0)
                {
                    return decoded.Substring(0, separatorIndex);
                }
            }
            catch
            {
                // 忽略解码错误
            }
        }

        return string.Empty;
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        // 先检查 X-Forwarded-For 头（用于代理场景）
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            // 取第一个 IP（最原始的客户 IP）
            var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > 0)
            {
                return ips[0].Trim();
            }
        }

        // 检查 X-Real-IP 头
        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        // 使用远程 IP 地址
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private async Task RejectRequestAsync(
        HttpContext context,
        IRateLimitService rateLimitService,
        string key,
        RateLimitType limitType,
        string limitLevel)
    {
        var resetTime = await rateLimitService.GetResetTimeAsync(key, limitType);
        var retryAfter = (int)(resetTime - DateTimeOffset.UtcNow).TotalSeconds;

        _logger.LogWarning("Rate limit exceeded for {LimitLevel}: {Key}, Path: {Path}",
            limitLevel, key, context.Request.Path);

        context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
        context.Response.Headers["Retry-After"] = Math.Max(1, retryAfter).ToString();

        if (_options.IncludeHeaders)
        {
            context.Response.Headers["X-RateLimit-Limit"] = "0";
            context.Response.Headers["X-RateLimit-Remaining"] = "0";
            context.Response.Headers["X-RateLimit-Reset"] = resetTime.ToUnixTimeSeconds().ToString();
        }

        var errorResponse = new
        {
            error = "rate_limit_exceeded",
            error_description = $"Rate limit exceeded. Please try again after {retryAfter} seconds.",
            retry_after = Math.Max(1, retryAfter)
        };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(errorResponse);
    }

    private async Task AddRateLimitHeadersAsync(
        HttpContext context,
        IRateLimitService rateLimitService,
        string clientIp,
        string clientId,
        RateLimitType limitType)
    {
        // 使用最严格的限制
        var remaining = await rateLimitService.GetRemainingRequestsAsync(clientIp, limitType);
        var limit = _options.IpLimits.FirstOrDefault(r =>
            r.EndpointPattern.Equals(context.Request.Path.Value, StringComparison.OrdinalIgnoreCase))?.MaxRequests ?? 100;

        if (!string.IsNullOrEmpty(clientId))
        {
            var clientRemaining = await rateLimitService.GetRemainingRequestsAsync(clientId, limitType);
            remaining = Math.Min(remaining, clientRemaining);
        }

        var resetTime = await rateLimitService.GetResetTimeAsync(clientIp, limitType);

        context.Response.OnStarting(() =>
        {
            context.Response.Headers["X-RateLimit-Limit"] = limit.ToString();
            context.Response.Headers["X-RateLimit-Remaining"] = Math.Max(0, remaining - 1).ToString();
            context.Response.Headers["X-RateLimit-Reset"] = resetTime.ToUnixTimeSeconds().ToString();
            return Task.CompletedTask;
        });
    }
}

/// <summary>
/// 速率限制中间件扩展
/// </summary>
public static class RateLimitMiddlewareExtensions
{
    /// <summary>
    /// 添加速率限制服务
    /// </summary>
    public static IServiceCollection AddRateLimiting(
        this IServiceCollection services,
        Action<RateLimitOptions>? configureOptions = null)
    {
        services.Configure<RateLimitOptions>(options =>
        {
            configureOptions?.Invoke(options);
        });

        services.AddSingleton<IRateLimitService, RateLimitService>();

        return services;
    }

    /// <summary>
    /// 使用速率限制中间件
    /// </summary>
    public static IApplicationBuilder UseRateLimiting(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RateLimitMiddleware>();
    }
}
