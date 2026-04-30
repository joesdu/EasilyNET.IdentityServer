using System.Security.Cryptography.X509Certificates;

namespace EasilyNET.IdentityServer.Host.Middleware;

/// <summary>
/// 从反向代理头部提取客户端证书
/// </summary>
public sealed class ClientCertificateForwardingMiddleware
{
    public const string ClientCertificateItemKey = "__forwarded_client_certificate";
    private readonly RequestDelegate _next;

    public ClientCertificateForwardingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var certificate = context.Connection.ClientCertificate ?? TryReadForwardedCertificate(context.Request);
        if (certificate != null)
        {
            context.Items[ClientCertificateItemKey] = certificate;
        }

        await _next(context);
    }

    private static X509Certificate2? TryReadForwardedCertificate(HttpRequest request)
    {
        foreach (var headerName in new[] { "X-ARR-ClientCert", "X-SSL-CERT", "X-Client-Cert" })
        {
            var rawValue = request.Headers[headerName].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(rawValue))
            {
                continue;
            }

            try
            {
                var normalized = Uri.UnescapeDataString(rawValue)
                    .Replace("-----BEGIN CERTIFICATE-----", string.Empty, StringComparison.Ordinal)
                    .Replace("-----END CERTIFICATE-----", string.Empty, StringComparison.Ordinal)
                    .Replace("\r", string.Empty, StringComparison.Ordinal)
                    .Replace("\n", string.Empty, StringComparison.Ordinal)
                    .Trim();

                return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(normalized));
            }
            catch
            {
                // ignore malformed forwarded certificate headers
            }
        }

        return null;
    }
}

/// <summary>
/// 客户端证书中间件扩展
/// </summary>
public static class ClientCertificateForwardingMiddlewareExtensions
{
    public static IApplicationBuilder UseForwardedClientCertificate(this IApplicationBuilder app) =>
        app.UseMiddleware<ClientCertificateForwardingMiddleware>();
}
