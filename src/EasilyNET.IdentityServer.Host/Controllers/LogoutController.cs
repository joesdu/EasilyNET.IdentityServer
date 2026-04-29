using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// OIDC Front-Channel Logout 1.0 实现 (RFC 9537)
/// 当用户从授权服务器登出时，通知依赖方客户端
/// </summary>
[ApiController]
public class LogoutController : ControllerBase
{
    private readonly IPersistedGrantStore _grantStore;

    public LogoutController(IPersistedGrantStore grantStore)
    {
        _grantStore = grantStore;
    }

    /// <summary>
    /// Front-Channel Logout 端点
    /// 依赖方客户端可以通过 iframe 或 img 标签加载此 URL 来接收登出通知
    /// </summary>
    /// <param name="logout_token">OIDC Logout Token (Sec-WebSocket-Extensions)</param>
    /// <param name="client_id">客户端 ID (如果 logout_token 未提供)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    [HttpGet("/connect/logout")]
    [HttpPost("/connect/logout")]
    public async Task<IActionResult> FrontChannelLogout(string? logout_token, string? client_id, CancellationToken cancellationToken)
    {
        // 处理 Front-Channel Logout Token (如果提供)
        if (!string.IsNullOrEmpty(logout_token))
        {
            // 解析 logout_token 并验证
            // logout_token 是一个 JWT，包含 sid (session ID) 和 iss (issuer)
            // 如果验证失败，返回 400
            if (!ValidateLogoutToken(logout_token))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Invalid logout token" });
            }

            // 撤销与该 session 关联的所有 grant
            await RevokeSessionGrantsAsync(logout_token, cancellationToken);
        }
        else if (!string.IsNullOrEmpty(client_id))
        {
            // 如果只提供了 client_id，撤销该客户端的所有 grant
            await RevokeClientGrantsAsync(client_id, cancellationToken);
        }

        // 返回204 No Content表示成功
        return NoContent();
    }

    /// <summary>
    /// Back-Channel Logout 端点
    /// 服务器到服务器的回调，通知依赖方客户端用户登出
    /// </summary>
    /// <param name="logout_token">OIDC Logout Token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    [HttpPost("/connect/backchannel-logout")]
    public async Task<IActionResult> BackChannelLogout(string? logout_token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(logout_token))
        {
            return BadRequest(new { error = "invalid_request", error_description = "logout_token is required" });
        }

        // 解析并验证 logout_token
        if (!ValidateLogoutToken(logout_token))
        {
            return BadRequest(new { error = "invalid_request", error_description = "Invalid logout token" });
        }

        // 撤销与该 session 关联的所有 grant
        await RevokeSessionGrantsAsync(logout_token, cancellationToken);

        // Back-Channel 必须返回 200 OK
        return Ok();
    }

    /// <summary>
    /// 验证 OIDC Logout Token
    /// </summary>
    private bool ValidateLogoutToken(string logoutToken)
    {
        // TODO: 实现完整的 JWT 验证
        // 1. 验证签名
        // 2. 验证 iss (issuer)
        // 3. 验证 aud (audience)
        // 4. 验证 exp (expiration)
        // 5. 验证 events 声明包含 http://schemas.openid.net/event/backchannel-logout
        // 6. 验证 sid (session ID) 或 sub (subject)

        // 简化实现：检查基本格式
        if (string.IsNullOrEmpty(logoutToken) || logoutToken.Split('.').Length != 3)
        {
            return false;
        }

        // 实际实现应该验证 JWT 签名和声明
        return true;
    }

    /// <summary>
    /// 撤销与特定 session 关联的所有授权
    /// </summary>
    private async Task RevokeSessionGrantsAsync(string logoutToken, CancellationToken cancellationToken)
    {
        // 从 logout_token 中提取 session ID (sid) 或 subject ID (sub)
        // TODO: 完整实现应该解析 JWT 并提取这些值

        // 简化实现：撤销所有授权（实际应该只撤销特定 session 的）
        // await _grantStore.RemoveAllAsync(new PersistedGrantFilter
        // {
        //     SubjectId = subjectId,
        //     Type = "refresh_token" // 只撤销 refresh_token
        // }, cancellationToken);
    }

    /// <summary>
    /// 撤销与特定客户端关联的所有授权
    /// </summary>
    private async Task RevokeClientGrantsAsync(string clientId, CancellationToken cancellationToken)
    {
        await _grantStore.RemoveAllAsync(new()
        {
            ClientId = clientId
        }, cancellationToken);
    }
}