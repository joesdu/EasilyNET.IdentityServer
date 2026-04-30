using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// private_key_jwt 客户端认证验证器
/// </summary>
public sealed class JwtClientAuthenticationValidator : IJwtClientAuthenticationValidator
{
    private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwtClientAuthenticationValidator> _logger;
    private readonly IdentityServerOptions _options;

    public JwtClientAuthenticationValidator(
        IHttpClientFactory httpClientFactory,
        IOptions<IdentityServerOptions> options,
        ILogger<JwtClientAuthenticationValidator> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<ClientAuthenticationValidationResult> ValidateAsync(Client client, ClientAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        if (!_options.EnablePrivateKeyJwtClientAuthentication)
        {
            return Fail("unauthorized_client", "private_key_jwt authentication is disabled.");
        }

        if (!string.Equals(request.ClientAssertionType, JwtBearerAssertionType, StringComparison.Ordinal))
        {
            return Fail("invalid_client", "Unsupported client_assertion_type.");
        }

        if (string.IsNullOrWhiteSpace(request.ClientAssertion))
        {
            return Fail("invalid_client", "client_assertion is required for private_key_jwt authentication.");
        }

        if (string.IsNullOrWhiteSpace(request.RequestedEndpoint))
        {
            return Fail("invalid_client", "The requested endpoint is required for audience validation.");
        }

        var signingKeys = await ResolveSigningKeysAsync(client, cancellationToken);
        if (signingKeys.Count == 0)
        {
            return Fail("invalid_client", "No signing keys are registered for this client.");
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(request.ClientAssertion, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = true,
                ValidIssuer = client.ClientId,
                ValidateAudience = true,
                ValidAudiences = [request.RequestedEndpoint],
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                ValidAlgorithms = _options.AllowedClientAssertionSigningAlgorithms
            }, out _);

            var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ??
                          principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var jwtId = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (!string.Equals(subject, client.ClientId, StringComparison.Ordinal))
            {
                return Fail("invalid_client", "client_assertion sub must match client_id.");
            }

            if (string.IsNullOrWhiteSpace(jwtId))
            {
                return Fail("invalid_client", "client_assertion must contain jti.");
            }

            return new ClientAuthenticationValidationResult { IsSuccess = true };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to validate private_key_jwt assertion for client {ClientId}", client.ClientId);
            return Fail("invalid_client", "Invalid private_key_jwt client assertion.");
        }
    }

    private async Task<IReadOnlyCollection<SecurityKey>> ResolveSigningKeysAsync(Client client, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(client.Jwks))
        {
            return new JsonWebKeySet(client.Jwks).GetSigningKeys().ToArray();
        }

        if (string.IsNullOrWhiteSpace(client.JwksUri))
        {
            return Array.Empty<SecurityKey>();
        }

        var httpClient = _httpClientFactory.CreateClient(nameof(JwtClientAuthenticationValidator));
        var jwks = await httpClient.GetStringAsync(client.JwksUri, cancellationToken);
        return new JsonWebKeySet(jwks).GetSigningKeys().ToArray();
    }

    private static ClientAuthenticationValidationResult Fail(string error, string description) =>
        new()
        {
            IsSuccess = false,
            Error = error,
            ErrorDescription = description
        };
}
