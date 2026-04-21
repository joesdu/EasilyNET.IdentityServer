using System.Security.Cryptography;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using Microsoft.AspNetCore.Mvc;

namespace EasilyNET.IdentityServer.Host.Controllers;

/// <summary>
/// RFC 8628 - OAuth 2.0 Device Authorization Grant
/// </summary>
[ApiController]
public class DeviceAuthorizationController : ControllerBase
{
    internal const int DefaultPollingIntervalSeconds = 5;
    internal const int SlowDownStepSeconds = 5;

    private readonly IClientStore _clientStore;
    private readonly IDeviceFlowStore _deviceFlowStore;
    private readonly IdentityServerOptions _options;

    public DeviceAuthorizationController(
        IClientStore clientStore,
        IDeviceFlowStore deviceFlowStore,
        IdentityServerOptions options)
    {
        _clientStore = clientStore;
        _deviceFlowStore = deviceFlowStore;
        _options = options;
    }

    /// <summary>
    /// Device Authorization Endpoint (RFC 8628 Section 3.1)
    /// </summary>
    [HttpPost("/connect/device_authorization")]
    public async Task<IActionResult> DeviceAuthorization(CancellationToken ct)
    {
        var form = await Request.ReadFormAsync(ct);
        var clientId = form["client_id"].ToString();
        if (string.IsNullOrEmpty(clientId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }
        var client = await _clientStore.FindClientByIdAsync(clientId, ct);
        if (client == null || !client.Enabled)
        {
            return BadRequest(new { error = "invalid_client", error_description = "Unknown or disabled client" });
        }
        if (!client.AllowedGrantTypes.Contains(GrantType.DeviceCode))
        {
            return BadRequest(new { error = "unauthorized_client", error_description = "Client is not authorized for device_code grant" });
        }

        // Validate requested scopes
        var scope = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scope)
                                  ? client.AllowedScopes.ToArray()
                                  : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var allowedSet = client.AllowedScopes.ToHashSet();
        foreach (var s in requestedScopes)
        {
            if (!allowedSet.Contains(s))
            {
                return BadRequest(new { error = "invalid_scope", error_description = $"Scope '{s}' is not allowed" });
            }
        }

        // Generate codes
        var deviceCode = GenerateCode(32);
        var userCode = GenerateUserCode();
        var lifetime = client.DeviceCodeLifetime > 0 ? client.DeviceCodeLifetime : _options.DeviceCodeLifetime;
        var deviceCodeData = new DeviceCodeData
        {
            Code = deviceCode,
            UserCode = userCode,
            ClientId = clientId,
            CreationTime = DateTime.UtcNow,
            ExpirationTime = DateTime.UtcNow.AddSeconds(lifetime),
            Data = string.Join(" ", requestedScopes),
            Properties = new Dictionary<string, string>
            {
                ["scope"] = string.Join(" ", requestedScopes),
                ["interval_seconds"] = DefaultPollingIntervalSeconds.ToString(),
            }
        };
        await _deviceFlowStore.StoreAsync(deviceCodeData, ct);
        var issuer = _options.Issuer.TrimEnd('/');
        return Ok(new
        {
            device_code = deviceCode,
            user_code = userCode,
            verification_uri = $"{issuer}/device",
            verification_uri_complete = $"{issuer}/device?user_code={userCode}",
            expires_in = lifetime,
            interval = DefaultPollingIntervalSeconds
        });
    }

    /// <summary>
    /// User code verification endpoint (simplified - in production this would be a UI page)
    /// </summary>
    [HttpPost("/connect/device_verify")]
    public async Task<IActionResult> VerifyUserCode(CancellationToken ct)
    {
        var form = await Request.ReadFormAsync(ct);
        var userCode = form["user_code"].ToString();
        var subjectId = form["subject_id"].ToString();
        if (string.IsNullOrEmpty(userCode) || string.IsNullOrEmpty(subjectId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "user_code and subject_id are required" });
        }
        var deviceCode = await _deviceFlowStore.FindByUserCodeAsync(userCode, ct);
        if (deviceCode == null)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Invalid user code" });
        }
        if (deviceCode.ExpirationTime < DateTime.UtcNow)
        {
            return BadRequest(new { error = "expired_token", error_description = "User code has expired" });
        }

        // Authorize the device by updating with subject ID
        var authorized = new DeviceCodeData
        {
            Code = deviceCode.Code,
            UserCode = deviceCode.UserCode,
            SubjectId = subjectId,
            ClientId = deviceCode.ClientId,
            Description = deviceCode.Description,
            CreationTime = deviceCode.CreationTime,
            ExpirationTime = deviceCode.ExpirationTime,
            Data = deviceCode.Data,
            Properties = deviceCode.Properties
        };

        // Remove old and store authorized version
        await _deviceFlowStore.RemoveAsync(deviceCode.Code, ct);
        await _deviceFlowStore.StoreAsync(authorized, ct);
        return Ok(new { message = "Device authorized successfully" });
    }

    private static string GenerateCode(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        return Convert.ToBase64String(bytes)
                      .TrimEnd('=')
                      .Replace('+', '-')
                      .Replace('/', '_');
    }

    private static string GenerateUserCode()
    {
        // RFC 8628 recommends 8-character user-friendly codes
        const string chars = "BCDFGHJKLMNPQRSTVWXZ";
        Span<char> code = stackalloc char[8];
        var bytes = RandomNumberGenerator.GetBytes(8);
        for (var i = 0; i < 8; i++)
        {
            code[i] = chars[bytes[i] % chars.Length];
        }
        return $"{new string(code[..4])}-{new string(code[4..])}";
    }
}
