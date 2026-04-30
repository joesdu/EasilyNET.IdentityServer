using System.Security.Cryptography.X509Certificates;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.Extensions.Options;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// mTLS 客户端认证验证器
/// </summary>
public sealed class MtlsClientAuthenticationValidator : IMtlsClientAuthenticationValidator
{
    private readonly IdentityServerOptions _options;

    public MtlsClientAuthenticationValidator(IOptions<IdentityServerOptions> options)
    {
        _options = options.Value;
    }

    public Task<ClientAuthenticationValidationResult> ValidateAsync(Client client, ClientAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        if (!_options.EnableMutualTlsClientAuthentication)
        {
            return Task.FromResult(Fail("unauthorized_client", "Mutual TLS client authentication is disabled."));
        }

        var certificate = request.ClientCertificate;
        if (certificate == null)
        {
            return Task.FromResult(Fail("invalid_client", "A client certificate is required."));
        }

        if (string.IsNullOrWhiteSpace(client.TlsClientAuthSubjectDn) && string.IsNullOrWhiteSpace(client.TlsClientAuthThumbprint))
        {
            return Task.FromResult(Fail("invalid_client", "The client does not have a registered certificate binding."));
        }

        if (!string.IsNullOrWhiteSpace(client.TlsClientAuthSubjectDn) &&
            !string.Equals(GetSubjectDistinguishedName(certificate), client.TlsClientAuthSubjectDn, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Fail("invalid_client", "The client certificate subject does not match the registered subject DN."));
        }

        if (!string.IsNullOrWhiteSpace(client.TlsClientAuthThumbprint) &&
            !string.Equals(NormalizeThumbprint(certificate.Thumbprint), NormalizeThumbprint(client.TlsClientAuthThumbprint), StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(Fail("invalid_client", "The client certificate thumbprint does not match the registered thumbprint."));
        }

        return Task.FromResult(new ClientAuthenticationValidationResult { IsSuccess = true });
    }

    private static string GetSubjectDistinguishedName(X509Certificate2 certificate) =>
        certificate.SubjectName.Name ?? certificate.Subject;

    private static string NormalizeThumbprint(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    private static ClientAuthenticationValidationResult Fail(string error, string description) =>
        new()
        {
            IsSuccess = false,
            Error = error,
            ErrorDescription = description
        };
}
