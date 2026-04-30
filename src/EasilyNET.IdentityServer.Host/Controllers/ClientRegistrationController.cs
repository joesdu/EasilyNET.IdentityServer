using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Host.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// RFC 7591 动态客户端注册端点
/// </summary>
[ApiController]
public sealed class ClientRegistrationController : ControllerBase
{
    private readonly IDynamicClientRegistrationService _dynamicClientRegistrationService;
    private readonly IdentityServerOptions _options;

    public ClientRegistrationController(IDynamicClientRegistrationService dynamicClientRegistrationService, IdentityServerOptions options)
    {
        _dynamicClientRegistrationService = dynamicClientRegistrationService;
        _options = options;
    }

    /// <summary>
    /// 注册客户端
    /// </summary>
    [HttpPost("/connect/register")]
    public async Task<IActionResult> Register([FromBody] DynamicClientRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (!_options.EnableDynamicClientRegistration)
        {
            return NotFound();
        }

        var initialAccessToken = OAuthRequestHelpers.ExtractBearerToken(Request);
        var result = await _dynamicClientRegistrationService.RegisterClientAsync(request, initialAccessToken, cancellationToken);
        if (!result.IsSuccess)
        {
            return StatusCode(result.StatusCode, new
            {
                error = result.Error,
                error_description = result.ErrorDescription
            });
        }

        Response.Headers.Location = $"{_options.Issuer.TrimEnd('/')}/connect/register";
        return StatusCode(StatusCodes.Status201Created, result.Document);
    }
}
