using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OpenID Connect UserInfo Endpoint (RFC 6750 + OIDC Core)
/// </summary>
[ApiController]
public class UserInfoController : ControllerBase
{
    private readonly IAuditService _auditService;
    private readonly ILogger<UserInfoController> _logger;
    private readonly ITokenService _tokenService;

    public UserInfoController(
        ITokenService tokenService,
        IAuditService auditService,
        ILogger<UserInfoController> logger)
    {
        _tokenService = tokenService;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// UserInfo 端点 - 返回当前 Access Token 对应的用户声明
    /// </summary>
    [HttpGet("/connect/userinfo")]
    [HttpPost("/connect/userinfo")]
    public async Task<IActionResult> GetUserInfo(CancellationToken cancellationToken)
    {
        // 从 Authorization header 提取 access token
        var accessToken = ExtractAccessToken();
        if (string.IsNullOrEmpty(accessToken))
        {
            return Unauthorized(new { error = "invalid_token", error_description = "Access token is required" });
        }

        // 验证 access token
        var validationResult = await _tokenService.ValidateAccessTokenAsync(accessToken, cancellationToken);
        if (!validationResult.IsValid)
        {
            return Unauthorized(new { error = "invalid_token", error_description = validationResult.ErrorDescription });
        }

        // 确保 token 包含 openid scope
        if (validationResult.Scopes == null || !validationResult.Scopes.Contains("openid"))
        {
            return Forbidden(new { error = "insufficient_scope", error_description = "Token does not include openid scope" });
        }

        if (string.IsNullOrEmpty(validationResult.SubjectId))
        {
            return Unauthorized(new { error = "invalid_token", error_description = "Token does not contain a subject identifier" });
        }

        var subjectId = validationResult.SubjectId;

        // 构建 UserInfo 响应
        var claims = new Dictionary<string, object>();

        // sub (subject) - 必需
        claims["sub"] = subjectId;

        // 根据 scope 返回相应的 claims
        if (validationResult.Scopes.Contains("profile"))
        {
            claims["name"] = "Test User"; // 实际应从用户存储获取
            claims["preferred_username"] = subjectId;
        }

        if (validationResult.Scopes.Contains("email"))
        {
            claims["email"] = $"{subjectId}@example.com"; // 实际应从用户存储获取
            claims["email_verified"] = true;
        }

        // 添加 scope 信息
        claims["scope"] = string.Join(" ", validationResult.Scopes);

        // 记录审计日志
        await _auditService.LogEventAsync(new AuditEvent
        {
            EventType = AuditEventTypes.TokenIntrospected,
            ClientId = validationResult.ClientId,
            SubjectId = validationResult.SubjectId,
            Success = true,
            IpAddress = GetClientIpAddress(),
            UserAgent = Request.Headers.UserAgent.FirstOrDefault(),
            RequestPath = Request.Path
        }, cancellationToken);

        // 返回 UserInfo 响应（默认 JSON）
        return Ok(claims);
    }

    /// <summary>
    /// 从请求中提取 Access Token
    /// </summary>
    private string? ExtractAccessToken()
    {
        // 1. 优先从 Authorization header 提取 Bearer token
        var authHeader = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader["Bearer ".Length..].Trim();
        }

        // 2. 尝试从表单 body 提取（POST 请求）
        if (Request.HasFormContentType)
        {
            return Request.Form["access_token"].FirstOrDefault();
        }

        // 3. RFC 6750 / OAuth 2.1: 不接受 URI query 中的 access_token
        return null;
    }

    private string? GetClientIpAddress()
    {
        var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }
        return HttpContext.Connection.RemoteIpAddress?.ToString();
    }

    private IActionResult Forbidden(object value)
    {
        Response.StatusCode = 403;
        return new JsonResult(value);
    }
}
