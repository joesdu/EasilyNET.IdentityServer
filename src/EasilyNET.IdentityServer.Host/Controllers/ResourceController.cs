using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Host.Infrastructure;
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
        var (scheme, headerToken) = OAuthRequestHelpers.ExtractAccessToken(Request);
        if (string.Equals(scheme, "Bearer", StringComparison.Ordinal) && Request.HasFormContentType)
        {
            headerToken = !string.IsNullOrWhiteSpace(headerToken) ? headerToken : null;
        }

        string? formToken = null;
        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync(cancellationToken);
            formToken = form.TryGetValue("access_token", out var postedToken) && !string.IsNullOrWhiteSpace(postedToken.ToString())
                ? postedToken.ToString()
                : null;
        }

        var queryToken = Request.Query["access_token"].ToString();
        var suppliedCount = CountSuppliedTokenMethods(headerToken, formToken, queryToken);
        if (suppliedCount > 1)
        {
            return BadRequestWithWwwAuthenticate("invalid_request", "Access token must be transmitted using exactly one method", "Bearer");
        }

        if (!string.IsNullOrWhiteSpace(queryToken))
        {
            return BadRequestWithWwwAuthenticate("invalid_request", "Access token must not be transmitted in the URI query string", "Bearer");
        }

        // RFC 6750 Section 2.1: Bearer Token in Authorization Header
        if (!string.IsNullOrWhiteSpace(headerToken))
        {
            return await ValidateTokenAsync(headerToken, scheme ?? "Bearer", cancellationToken);
        }

        // RFC 6750 Section 2.2: Form-Encoded Body (不推荐)
        if (!string.IsNullOrWhiteSpace(formToken))
        {
            return await ValidateTokenAsync(formToken, "Bearer", cancellationToken);
        }

        // 无令牌 - 返回 401 并包含 WWW-Authenticate 头
        return UnauthorizedWithWwwAuthenticate("missing_token", "The request lacks a valid bearer token", "Bearer");
    }

    /// <summary>
    /// 验证令牌并返回结果
    /// </summary>
    private async Task<IActionResult> ValidateTokenAsync(string token, string scheme, CancellationToken cancellationToken)
    {
        var result = await _tokenService.ValidateAccessTokenAsync(token, new AccessTokenValidationContext
        {
            DPoPProof = Request.Headers["DPoP"].FirstOrDefault(),
            HttpMethod = Request.Method,
            Htu = OAuthRequestHelpers.BuildAbsoluteEndpointUri(Request)
        }, cancellationToken);

        if (!result.IsValid)
        {
            return UnauthorizedWithWwwAuthenticate(
                result.Error ?? "invalid_token",
                result.ErrorDescription ?? "Token validation failed",
                scheme);
        }
        if (string.Equals(result.TokenType, "DPoP", StringComparison.Ordinal) && !string.Equals(scheme, "DPoP", StringComparison.Ordinal))
        {
            return UnauthorizedWithWwwAuthenticate("invalid_token", "A DPoP-bound token must use the DPoP authorization scheme", "DPoP");
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
            token_type = result.TokenType
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

    private IActionResult BadRequestWithWwwAuthenticate(string error, string errorDescription, string scheme)
    {
        var realm = "EasilyNET.IdentityServer";
        Response.Headers.WWWAuthenticate = $"{scheme} realm=\"{realm}\", error=\"{error}\", error_description=\"{errorDescription}\"";
        return BadRequest(new
        {
            error,
            error_description = errorDescription
        });
    }

    private static int CountSuppliedTokenMethods(params string?[] values) =>
        values.Count(value => !string.IsNullOrWhiteSpace(value));
}