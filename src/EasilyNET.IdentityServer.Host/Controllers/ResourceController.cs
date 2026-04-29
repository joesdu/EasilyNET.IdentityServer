using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// 资源服务器令牌验证端点 (RFC 6750)
/// 当资源服务器验证 Bearer Token 失败时，返回 WWW-Authenticate 头
/// </summary>
[ApiController]
public class ResourceController : ControllerBase
{
    private readonly ITokenService _tokenService;

    public ResourceController(ITokenService tokenService)
    {
        _tokenService = tokenService;
    }

    /// <summary>
    /// 验证访问令牌
    /// </summary>
    [HttpPost("/connect/verify")]
    public async Task<IActionResult> VerifyToken(CancellationToken cancellationToken)
    {
        var authHeader = Request.Headers.Authorization.ToString();

        // RFC 6750 Section 2.1: Bearer Token in Authorization Header
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader["Bearer ".Length..].Trim();
            return await ValidateTokenAsync(token, "Bearer", cancellationToken);
        }

        // RFC 6750 Section 2.2: Form-Encoded Body (不推荐)
        var form = await Request.ReadFormAsync(cancellationToken);
        if (form.TryGetValue("access_token", out var formToken) && !string.IsNullOrEmpty(formToken.ToString()))
        {
            return await ValidateTokenAsync(formToken.ToString(), "Bearer", cancellationToken);
        }

        // RFC 6750 Section 2.3: URI Query Parameter (不推荐，仅在绝对必要时使用)
        var queryToken = Request.Query["access_token"].ToString();
        if (!string.IsNullOrEmpty(queryToken))
        {
            // URI 查询参数方式必须有 TLS，且资源服务器必须支持
            return await ValidateTokenAsync(queryToken, "Bearer", cancellationToken);
        }

        // 无令牌 - 返回 401 并包含 WWW-Authenticate 头
        return UnauthorizedWithWwwAuthenticate("missing_token", "The request lacks a valid bearer token", "Bearer");
    }

    /// <summary>
    /// 验证令牌并返回结果
    /// </summary>
    private async Task<IActionResult> ValidateTokenAsync(string token, string scheme, CancellationToken cancellationToken)
    {
        var result = await _tokenService.ValidateAccessTokenAsync(token, cancellationToken);

        if (!result.IsValid)
        {
            return UnauthorizedWithWwwAuthenticate(
                result.Error ?? "invalid_token",
                result.ErrorDescription ?? "Token validation failed",
                scheme);
        }

        return Ok(new
        {
            active = true,
            client_id = result.ClientId,
            sub = result.SubjectId,
            scope = result.Scopes != null ? string.Join(" ", result.Scopes) : null,
            exp = result.ExpirationTime.HasValue
                      ? new DateTimeOffset(result.ExpirationTime.Value).ToUnixTimeSeconds()
                      : (long?)null,
            token_type = "Bearer"
        });
    }

    /// <summary>
    /// 返回 401 响应并包含 WWW-Authenticate 头 (RFC 6750 Section 3)
    /// </summary>
    /// <param name="error">错误码</param>
    /// <param name="errorDescription">错误描述</param>
    /// <param name="scheme">认证方案 (通常是 Bearer)</param>
    private IActionResult UnauthorizedWithWwwAuthenticate(string error, string errorDescription, string scheme)
    {
        // RFC 6750 Section 3: WWW-Authenticate 头格式
        // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token is invalid"
        var realm = "EasilyNET.IdentityServer";
        var wwwAuthenticate = $"{scheme} realm=\"{realm}\", error=\"{error}\", error_description=\"{errorDescription}\"";

        Response.Headers.WWWAuthenticate = wwwAuthenticate;

        return Unauthorized(new
        {
            error,
            error_description = errorDescription
        });
    }
}