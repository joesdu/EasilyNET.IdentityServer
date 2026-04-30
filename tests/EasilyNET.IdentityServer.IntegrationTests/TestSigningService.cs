using System.Security.Cryptography;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.IdentityModel.Tokens;

namespace EasilyNET.IdentityServer.IntegrationTests;

internal sealed class TestSigningService : ISigningService, IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly SigningKeyResult _key;

    public TestSigningService()
    {
        var rsaKey = new RsaSecurityKey(_rsa)
        {
            KeyId = "test-rsa-key"
        };
        _key = new()
        {
            Key = rsaKey,
            Credentials = new(rsaKey, SecurityAlgorithms.RsaSha256),
            KeyId = rsaKey.KeyId,
            Algorithm = SecurityAlgorithms.RsaSha256
        };
    }

    public Task<SigningKeyResult> GetSigningKeyAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_key);

    public Task<IEnumerable<SigningKeyResult>> GetAllSigningKeysAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IEnumerable<SigningKeyResult>>(new[] { _key });

    public Task RotateKeysAsync(CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public RSA? GetPublicKey() => _rsa;

    public void Dispose() => _rsa.Dispose();
}
