using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EasilyNET.IdentityServer.Host.Middleware;
using Microsoft.AspNetCore.Http.Extensions;

namespace EasilyNET.IdentityServer.Host.Infrastructure;

internal static class OAuthRequestHelpers
{
    public static string BuildAbsoluteEndpointUri(HttpRequest request)
    {
        var uri = new Uri(request.GetDisplayUrl());
        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri.GetLeftPart(UriPartial.Path);
    }

    public static (string? ClientId, string? ClientSecret) ExtractClientCredentials(HttpRequest request, IFormCollection form)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var encoded = authHeader["Basic ".Length..].Trim();
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var parts = decoded.Split(':', 2);
                if (parts.Length == 2)
                {
                    return (Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1]));
                }
            }
            catch
            {
                return (null, null);
            }
        }

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }

    public static string? ResolveClientId(IFormCollection form)
    {
        var clientId = form["client_id"].ToString();
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            return clientId;
        }

        var assertion = form["client_assertion"].ToString();
        if (string.IsNullOrWhiteSpace(assertion))
        {
            return null;
        }

        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(assertion);
            return jwt.Subject ?? jwt.Issuer;
        }
        catch
        {
            return null;
        }
    }

    public static string? ExtractBearerToken(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.ToString();
        return !string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authHeader["Bearer ".Length..].Trim()
            : null;
    }

    public static (string? Scheme, string? AccessToken) ExtractAccessToken(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authHeader))
        {
            if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return ("Bearer", authHeader["Bearer ".Length..].Trim());
            }

            if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            {
                return ("DPoP", authHeader["DPoP ".Length..].Trim());
            }
        }

        return (null, null);
    }

    public static X509Certificate2? GetClientCertificate(HttpContext httpContext) =>
        httpContext.Items.TryGetValue(ClientCertificateForwardingMiddleware.ClientCertificateItemKey, out var certificate) && certificate is X509Certificate2 x509
            ? x509
            : httpContext.Connection.ClientCertificate;
}
