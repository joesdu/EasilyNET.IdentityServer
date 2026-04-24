using System.Text;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// Token Introspection Endpoint (RFC 7662)
/// </summary>
[ApiController]
public class IntrospectionController : ControllerBase
{
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ITokenService _tokenService;

    public IntrospectionController(ITokenService tokenService, IClientAuthenticationService clientAuthenticationService)
    {
        _tokenService = tokenService;
        _clientAuthenticationService = clientAuthenticationService;
    }

    /// <summary>
    /// Token 内省端点
    /// </summary>
    [HttpPost("/connect/introspect")]
    public async Task<IActionResult> Introspect(CancellationToken cancellationToken)
    {
        var form = await Request.ReadFormAsync(cancellationToken);
        var authResult = await AuthenticateClientAsync(form, cancellationToken);
        if (!authResult.IsSuccess)
        {
            return Unauthorized(new { error = "invalid_client" });
        }
        var token = form["token"].ToString();
        if (string.IsNullOrEmpty(token))
        {
            return Ok(new { active = false });
        }
        var result = await _tokenService.ValidateAccessTokenAsync(token, cancellationToken);
        if (!result.IsValid)
        {
            return Ok(new { active = false });
        }

        // RFC 7662: 客户端只能内省属于自己的 token
        var requestingClient = authResult.Client!;
        if (result.ClientId != requestingClient.ClientId)
        {
            // 如果请求的客户端与 token 的客户端不匹配,返回 inactive
            return Ok(new { active = false });
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

    private Task<ClientAuthenticationResult> AuthenticateClientAsync(IFormCollection form, CancellationToken cancellationToken)
    {
        var (clientId, clientSecret) = ExtractClientCredentials(form);
        if (string.IsNullOrEmpty(clientId))
        {
            return Task.FromResult(new ClientAuthenticationResult { IsSuccess = false });
        }
        return _clientAuthenticationService.AuthenticateClientAsync(new()
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            GrantType = GrantType.ClientCredentials
        }, cancellationToken);
    }

    private (string? clientId, string? clientSecret) ExtractClientCredentials(IFormCollection form)
    {
        var authHeader = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var encoded = authHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':', 2);
            if (parts.Length == 2)
            {
                return (Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1]));
            }
        }
        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }
}

/// <summary>
/// Token Revocation Endpoint (RFC 7009)
/// </summary>
[ApiController]
public class RevocationController : ControllerBase
{
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly IPersistedGrantStore _grantStore;
    private readonly ITokenService _tokenService;

    public RevocationController(ITokenService tokenService, IPersistedGrantStore grantStore, IClientAuthenticationService clientAuthenticationService)
    {
        _tokenService = tokenService;
        _grantStore = grantStore;
        _clientAuthenticationService = clientAuthenticationService;
    }

    /// <summary>
    /// Token 撤销端点
    /// </summary>
    [HttpPost("/connect/revocation")]
    public async Task<IActionResult> Revoke(CancellationToken cancellationToken)
    {
        var form = await Request.ReadFormAsync(cancellationToken);
        var authResult = await AuthenticateClientAsync(form, cancellationToken);
        if (!authResult.IsSuccess)
        {
            return Unauthorized(new { error = "invalid_client" });
        }
        var clientId = authResult.Client!.ClientId;
        var token = form["token"].ToString();
        var tokenTypeHint = form["token_type_hint"].ToString();
        if (string.IsNullOrEmpty(token))
        {
            return BadRequest(new { error = "invalid_request", error_description = "token is required" });
        }

        // 尝试撤销 refresh token
        if (string.IsNullOrEmpty(tokenTypeHint) || tokenTypeHint == "refresh_token")
        {
            var grant = await _grantStore.GetAsync(token, cancellationToken);
            if (grant != null && grant.ClientId == clientId)
            {
                await _grantStore.RemoveAsync(token, cancellationToken);
                return Ok();
            }
        }

        // 尝试撤销 access token
        if (string.IsNullOrEmpty(tokenTypeHint) || tokenTypeHint == "access_token")
        {
            await _tokenService.RevokeAsync(token, cancellationToken);
        }

        // RFC 7009: 即使 token 无效也返回 200
        return Ok();
    }

    private Task<ClientAuthenticationResult> AuthenticateClientAsync(IFormCollection form, CancellationToken cancellationToken)
    {
        var (clientId, clientSecret) = ExtractClientCredentials(form);
        if (string.IsNullOrEmpty(clientId))
        {
            return Task.FromResult(new ClientAuthenticationResult { IsSuccess = false });
        }
        return _clientAuthenticationService.AuthenticateClientAsync(new()
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            GrantType = GrantType.ClientCredentials
        }, cancellationToken);
    }

    private (string? clientId, string? clientSecret) ExtractClientCredentials(IFormCollection form)
    {
        var authHeader = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var encoded = authHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':', 2);
            if (parts.Length == 2)
            {
                return (Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1]));
            }
        }
        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }
}
