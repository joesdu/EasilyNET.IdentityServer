using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Claim = System.Security.Claims.Claim;

namespace EasilyNET.IdentityServer.IntegrationTests;

[TestClass]
public class AdvancedOAuthFeaturesTests
{
    private HttpClient _client = null!;

    [TestInitialize]
    public void Setup()
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Development");
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<ISigningService>();
                    services.AddSingleton<ISigningService, TestSigningService>();
                });
            });
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    [TestMethod]
    public async Task Discovery_Advertises_AdvancedOAuthFeatures()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();

        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = json.RootElement;
        Assert.AreEqual("/connect/register", new Uri(root.GetProperty("registration_endpoint").GetString()!).AbsolutePath);

        var methods = root.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(x => x.GetString()).ToArray();
        CollectionAssert.Contains(methods, "private_key_jwt");
        CollectionAssert.Contains(methods, "tls_client_auth");
        CollectionAssert.Contains(methods, "self_signed_tls_client_auth");

        var dpopAlgorithms = root.GetProperty("dpop_signing_alg_values_supported").EnumerateArray().Select(x => x.GetString()).ToArray();
        CollectionAssert.Contains(dpopAlgorithms, "RS256");
    }

    [TestMethod]
    public async Task DynamicRegistration_PrivateKeyJwt_Client_Can_Get_AccessToken()
    {
        using var rsa = RSA.Create(2048);
        var registrationResponse = await RegisterClientAsync(new
        {
            client_name = "jwt-client",
            token_endpoint_auth_method = "private_key_jwt",
            grant_types = new[] { "client_credentials" },
            scope = "api1",
            jwks = new
            {
                keys = new[] { CreatePublicJwk(rsa) }
            }
        });

        var clientId = registrationResponse.RootElement.GetProperty("client_id").GetString()!;
        var tokenEndpoint = BuildAbsoluteUri("/connect/token");
        var clientAssertion = CreateClientAssertion(clientId, tokenEndpoint, rsa);

        var tokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["scope"] = "api1",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = clientAssertion
        }));

        var body = await tokenResponse.Content.ReadAsStringAsync();
        Assert.IsTrue(tokenResponse.IsSuccessStatusCode, body);
        using var tokenJson = JsonDocument.Parse(body);
        Assert.IsFalse(string.IsNullOrWhiteSpace(tokenJson.RootElement.GetProperty("access_token").GetString()));
    }

    [TestMethod]
    public async Task DynamicRegistration_Mtls_Client_Can_Get_AccessToken_With_ForwardedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=mtls-client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));

        var registrationResponse = await RegisterClientAsync(new
        {
            client_name = "mtls-client",
            token_endpoint_auth_method = "tls_client_auth",
            grant_types = new[] { "client_credentials" },
            scope = "api1",
            tls_client_auth_subject_dn = certificate.Subject
        });

        var clientId = registrationResponse.RootElement.GetProperty("client_id").GetString()!;
        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["scope"] = "api1"
            })
        };
        request.Headers.Add("X-ARR-ClientCert", Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));

        var tokenResponse = await _client.SendAsync(request);
        var body = await tokenResponse.Content.ReadAsStringAsync();
        Assert.IsTrue(tokenResponse.IsSuccessStatusCode, body);
    }

    [TestMethod]
    public async Task DynamicRegistration_DPoP_Client_Receives_And_Uses_DPoP_Bound_AccessToken()
    {
        var registrationResponse = await RegisterClientAsync(new
        {
            client_name = "dpop-client",
            token_endpoint_auth_method = "client_secret_post",
            grant_types = new[] { "client_credentials" },
            scope = "api1",
            require_dpop_proof = true
        });

        var clientId = registrationResponse.RootElement.GetProperty("client_id").GetString()!;
        var clientSecret = registrationResponse.RootElement.GetProperty("client_secret").GetString()!;

        using var dpopKey = RSA.Create(2048);
        var tokenEndpoint = BuildAbsoluteUri("/connect/token");
        var tokenProof = CreateDpopProof(dpopKey, tokenEndpoint, HttpMethod.Post.Method);
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = "api1"
            })
        };
        tokenRequest.Headers.Add("DPoP", tokenProof);

        var tokenResponse = await _client.SendAsync(tokenRequest);
        var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
        Assert.IsTrue(tokenResponse.IsSuccessStatusCode, tokenBody);

        using var tokenJson = JsonDocument.Parse(tokenBody);
        var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;
        Assert.AreEqual("DPoP", tokenJson.RootElement.GetProperty("token_type").GetString());

        var verifyEndpoint = BuildAbsoluteUri("/connect/verify");
        var resourceProof = CreateDpopProof(dpopKey, verifyEndpoint, HttpMethod.Post.Method, accessToken);
        using var resourceRequest = new HttpRequestMessage(HttpMethod.Post, "/connect/verify");
        resourceRequest.Headers.Authorization = new("DPoP", accessToken);
        resourceRequest.Headers.Add("DPoP", resourceProof);

        var verifyResponse = await _client.SendAsync(resourceRequest);
        var verifyBody = await verifyResponse.Content.ReadAsStringAsync();
        Assert.IsTrue(verifyResponse.IsSuccessStatusCode, verifyBody);
        using var verifyJson = JsonDocument.Parse(verifyBody);
        Assert.AreEqual("DPoP", verifyJson.RootElement.GetProperty("token_type").GetString());
    }

    private async Task<JsonDocument> RegisterClientAsync(object payload)
    {
        var response = await _client.PostAsync("/connect/register", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, response.StatusCode, body);
        return JsonDocument.Parse(body);
    }

    private Uri BuildAbsoluteUri(string relativePath) =>
        new(_client.BaseAddress!, relativePath.TrimStart('/'));

    private static string CreateClientAssertion(string clientId, Uri audience, RSA privateKey)
    {
        var credentials = new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSha256);
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            issuer: clientId,
            audience: audience.ToString(),
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            },
            notBefore: now.AddMinutes(-1),
            expires: now.AddMinutes(5),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string CreateDpopProof(RSA privateKey, Uri htu, string httpMethod, string? accessToken = null)
    {
        var publicJwk = CreatePublicJwk(privateKey);
        var header = new JwtHeader(new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSha256))
        {
            ["typ"] = "dpop+jwt",
            ["jwk"] = new Dictionary<string, object?>(publicJwk)
        };

        var claims = new List<Claim>
        {
            new("htm", httpMethod),
            new("htu", htu.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            claims.Add(new("ath", Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)))));
        }

        var jwt = new JwtSecurityToken(header, new JwtPayload(claims: claims.ToArray()));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static Dictionary<string, object?> CreatePublicJwk(RSA rsa)
    {
        var parameters = rsa.ExportParameters(false);
        return new Dictionary<string, object?>
        {
            ["kty"] = "RSA",
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent!),
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus!),
            ["alg"] = "RS256",
            ["use"] = "sig"
        };
    }
}
