using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// RFC 9449 DPoP 服务
/// </summary>
public sealed class DPoPService : IDPoPService, IDisposable
{
    private readonly Timer _cleanupTimer;
    private readonly ILogger<DPoPService> _logger;
    private readonly IdentityServerOptions _options;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _usedProofs = new(StringComparer.Ordinal);
    private bool _disposed;

    public DPoPService(IOptions<IdentityServerOptions> options, ILogger<DPoPService> logger)
    {
        _options = options.Value;
        _logger = logger;
        _cleanupTimer = new Timer(_ => CleanupExpiredProofs(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public Task<DPoPProofValidationResult> ValidateTokenRequestAsync(string proof, DPoPProofValidationContext context, CancellationToken cancellationToken = default) =>
        ValidateProofAsync(proof, context, null, null);

    public Task<DPoPProofValidationResult> ValidateResourceRequestAsync(string proof, string accessToken, string expectedJkt, DPoPProofValidationContext context, CancellationToken cancellationToken = default) =>
        ValidateProofAsync(proof, context, accessToken, expectedJkt);

    private Task<DPoPProofValidationResult> ValidateProofAsync(string proof, DPoPProofValidationContext context, string? accessToken, string? expectedJkt)
    {
        if (!_options.EnableDpop)
        {
            return Task.FromResult(Fail("use_dpop_proof", "DPoP is disabled."));
        }

        if (string.IsNullOrWhiteSpace(proof))
        {
            return Task.FromResult(Fail("use_dpop_proof", "A DPoP proof JWT is required."));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        JwtSecurityToken jwt;
        try
        {
            jwt = tokenHandler.ReadJwtToken(proof);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to parse DPoP proof JWT");
            return Task.FromResult(Fail("invalid_dpop_proof", "The DPoP proof is malformed."));
        }

        if (!TryGetHeaderValue(jwt, "typ", out var type) || !string.Equals(type, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof typ header must be 'dpop+jwt'."));
        }

        if (string.IsNullOrWhiteSpace(jwt.Header.Alg) || string.Equals(jwt.Header.Alg, SecurityAlgorithms.None, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof must be signed with a supported asymmetric algorithm."));
        }

        if (!_options.AllowedDpopSigningAlgorithms.Contains(jwt.Header.Alg, StringComparer.Ordinal))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", $"DPoP signing algorithm '{jwt.Header.Alg}' is not allowed."));
        }

        if (!TryGetJsonWebKey(jwt, out var jsonWebKey))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof must include a public jwk header."));
        }

        try
        {
            tokenHandler.ValidateToken(proof, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = jsonWebKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireSignedTokens = true,
                ValidAlgorithms = _options.AllowedDpopSigningAlgorithms
            }, out _);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to validate DPoP proof signature");
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof signature validation failed."));
        }

        var claims = jwt.Claims.ToDictionary(claim => claim.Type, claim => claim.Value, StringComparer.Ordinal);
        if (!claims.TryGetValue("htm", out var htm) || !string.Equals(htm, context.HttpMethod, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof htm claim does not match the HTTP method."));
        }

        if (!claims.TryGetValue("htu", out var htu) || !string.Equals(NormalizeUri(htu), NormalizeUri(context.Htu), StringComparison.Ordinal))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof htu claim does not match the target URI."));
        }

        if (!claims.TryGetValue(JwtRegisteredClaimNames.Jti, out var jti) || string.IsNullOrWhiteSpace(jti))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof must include jti."));
        }

        if (!claims.TryGetValue(JwtRegisteredClaimNames.Iat, out var iatValue) || !long.TryParse(iatValue, out var iatUnix))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof must include a valid iat claim."));
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatUnix);
        var now = DateTimeOffset.UtcNow;
        if (issuedAt < now.AddSeconds(-_options.DpopProofLifetimeSeconds) || issuedAt > now.AddSeconds(5))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof is outside the acceptable time window."));
        }

        if (!_usedProofs.TryAdd(jti, issuedAt))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof replay detected."));
        }

        var jkt = Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
        if (!string.IsNullOrWhiteSpace(expectedJkt) && !string.Equals(expectedJkt, jkt, StringComparison.Ordinal))
        {
            return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof key thumbprint does not match the bound access token."));
        }

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            if (!claims.TryGetValue("ath", out var ath))
            {
                return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof must include ath for resource requests."));
            }

            var computedAth = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!string.Equals(ath, computedAth, StringComparison.Ordinal))
            {
                return Task.FromResult(Fail("invalid_dpop_proof", "DPoP proof ath does not match the presented access token."));
            }
        }

        return Task.FromResult(new DPoPProofValidationResult
        {
            IsSuccess = true,
            Jkt = jkt
        });
    }

    private static bool TryGetHeaderValue(JwtSecurityToken jwt, string key, out string? value)
    {
        if (jwt.Header.TryGetValue(key, out var raw))
        {
            value = raw?.ToString();
            return !string.IsNullOrWhiteSpace(value);
        }

        value = null;
        return false;
    }

    private static bool TryGetJsonWebKey(JwtSecurityToken jwt, out JsonWebKey jsonWebKey)
    {
        if (jwt.Header.TryGetValue("jwk", out var rawJwk))
        {
            var json = rawJwk switch
            {
                string text => text,
                JsonElement element => element.GetRawText(),
                _ => JsonSerializer.Serialize(rawJwk)
            };

            jsonWebKey = new JsonWebKey(json);
            return true;
        }

        jsonWebKey = null!;
        return false;
    }

    private static string NormalizeUri(string value)
    {
        var uri = new Uri(value, UriKind.Absolute);
        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty,
            Host = uri.Host.ToLowerInvariant(),
            Scheme = uri.Scheme.ToLowerInvariant()
        };
        return builder.Uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
    }

    private static DPoPProofValidationResult Fail(string error, string description) =>
        new()
        {
            IsSuccess = false,
            Error = error,
            ErrorDescription = description
        };

    private void CleanupExpiredProofs()
    {
        try
        {
            var cutoff = DateTimeOffset.UtcNow.AddSeconds(-_options.DpopProofLifetimeSeconds);
            foreach (var entry in _usedProofs.Where(item => item.Value < cutoff).ToArray())
            {
                _usedProofs.TryRemove(entry.Key, out _);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to clean up expired DPoP proofs");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer.Dispose();
    }
}
