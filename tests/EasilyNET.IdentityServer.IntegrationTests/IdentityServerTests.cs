using System.Net;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace EasilyNET.IdentityServer.IntegrationTests;

/// <summary>
/// IdentityServer Integration Tests
/// </summary>
[TestClass]
public class IdentityServerTests
{
    private HttpClient _client = null!;

    /// <summary>
    /// Initialize test environment
    /// </summary>
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

    private static HttpRequestMessage PostForm(string url, Dictionary<string, string> form, string? basicAuth = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new FormUrlEncodedContent(form)
        };
        if (basicAuth != null)
        {
            request.Headers.Authorization = new("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(basicAuth)));
        }
        return request;
    }

    private static string CreateCodeVerifier() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    private static string CreateCodeChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static Uri GetAuthorizationResponseUri(HttpResponseMessage response)
    {
        if (response.Headers.Location is not null)
        {
            return response.Headers.Location;
        }
        Assert.IsNotNull(response.RequestMessage?.RequestUri);
        return response.RequestMessage!.RequestUri!;
    }

    #region Revocation

    /// <summary>
    /// Test revocation endpoint with valid token returns 200
    /// </summary>
    [TestMethod]
    public async Task Revocation_ValidToken_Returns200()
    {
        // Get a token first
        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "secret",
            ["scope"] = "api1"
        }));
        tokenResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;

        // Revoke using Basic auth
        var response = await _client.SendAsync(PostForm("/connect/revocation", new()
        {
            ["token"] = accessToken
        }, "console:secret"));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Test revocation with invalid client secret returns unauthorized
    /// </summary>
    [TestMethod]
    public async Task Revocation_InvalidClientSecret_ReturnsUnauthorized()
    {
        var response = await _client.SendAsync(PostForm("/connect/revocation", new()
        {
            ["token"] = "any-token"
        }, "console:wrong-secret"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region Health

    /// <summary>
    /// Test health endpoint returns healthy status
    /// </summary>
    [TestMethod]
    public async Task Health_ReturnsOk()
    {
        var response = await _client.GetAsync("/health");
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.AreEqual("healthy", json.RootElement.GetProperty("status").GetString());
    }

    #endregion

    #region Discovery

    /// <summary>
    /// Test discovery endpoint returns expected endpoints
    /// </summary>
    [TestMethod]
    public async Task Discovery_ReturnsExpectedEndpoints()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = json.RootElement;
        Assert.IsTrue(root.TryGetProperty("issuer", out _));
        Assert.IsTrue(root.TryGetProperty("token_endpoint", out _));
        Assert.IsTrue(root.TryGetProperty("authorization_endpoint", out _));
        Assert.IsTrue(root.TryGetProperty("device_authorization_endpoint", out _));
        Assert.IsTrue(root.TryGetProperty("introspection_endpoint", out _));
        Assert.IsTrue(root.TryGetProperty("revocation_endpoint", out _));
        Assert.IsTrue(root.TryGetProperty("jwks_uri", out _));
        var grantTypes = root.GetProperty("grant_types_supported");
        var grants = grantTypes.EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.IsTrue(grants.Contains("authorization_code"));
        Assert.IsTrue(grants.Contains("client_credentials"));
        Assert.IsTrue(grants.Contains("refresh_token"));
        Assert.IsTrue(grants.Contains("urn:ietf:params:oauth:grant-type:device_code"));
        var authMethods = root.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.IsTrue(authMethods.Contains("none"));
    }

    /// <summary>
    /// Test JWKS endpoint returns keys array
    /// </summary>
    [TestMethod]
    public async Task Jwks_ReturnsKeysArray()
    {
        var response = await _client.GetAsync("/.well-known/jwks");
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.IsTrue(json.RootElement.TryGetProperty("keys", out var keys));
        Assert.AreEqual(JsonValueKind.Array, keys.ValueKind);
    }

    #endregion

    #region Client Credentials

    /// <summary>
    /// Test client credentials flow with valid client returns access token
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_ValidClient_ReturnsAccessToken()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "secret",
            ["scope"] = "api1"
        }));

        // Read body for diagnostics on failure
        var body = await response.Content.ReadAsStringAsync();
        Assert.IsTrue(response.IsSuccessStatusCode, $"Expected 2xx but got {(int)response.StatusCode}: {body}");
        var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        Assert.IsTrue(root.TryGetProperty("access_token", out var at));
        Assert.IsFalse(string.IsNullOrEmpty(at.GetString()));
        Assert.AreEqual("Bearer", root.GetProperty("token_type").GetString());
        Assert.IsTrue(root.GetProperty("expires_in").GetInt32() > 0);
    }

    /// <summary>
    /// Test client credentials flow with basic auth returns access token
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_BasicAuth_ReturnsAccessToken()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = "api1"
        }, "console:secret"));
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.IsTrue(json.RootElement.TryGetProperty("access_token", out _));
    }

    /// <summary>
    /// Test client credentials with invalid secret returns unauthorized
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_InvalidSecret_ReturnsUnauthorized()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "wrong-secret"
        }));
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Test client credentials with invalid scope returns bad request
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_InvalidScope_ReturnsBadRequest()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "secret",
            ["scope"] = "nonexistent-scope"
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Test client credentials with unknown client returns unauthorized
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_UnknownClient_ReturnsUnauthorized()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "unknown",
            ["client_secret"] = "secret"
        }));
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region Token Endpoint Validation

    /// <summary>
    /// Test token endpoint with missing grant type returns bad request
    /// </summary>
    [TestMethod]
    public async Task Token_MissingGrantType_ReturnsBadRequest()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["client_id"] = "console",
            ["client_secret"] = "secret"
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Test token endpoint with unsupported grant type returns error
    /// </summary>
    [TestMethod]
    public async Task Token_UnsupportedGrantType_ReturnsError()
    {
        var response = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "implicit",
            ["client_id"] = "console",
            ["client_secret"] = "secret"
        }));
        Assert.IsTrue(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized);
    }

    #endregion

    #region Authorization Code

    /// <summary>
    /// Test authorization code full flow returns access and refresh token
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCode_FullFlow_ReturnsAccessAndRefreshToken()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var authorizeResponse = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20profile%20api1&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");

        var location = GetAuthorizationResponseUri(authorizeResponse);
        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        var code = query["code"];
        Assert.IsFalse(string.IsNullOrEmpty(code));
        Assert.AreEqual("https://localhost:7020", query["iss"]);

        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["code"] = code!,
            ["redirect_uri"] = "https://localhost:5002/signin-oidc",
            ["code_verifier"] = verifier
        }));

        tokenResponse.EnsureSuccessStatusCode();
        Assert.AreEqual("no-store", tokenResponse.Headers.CacheControl?.ToString());
        var json = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        Assert.IsTrue(json.RootElement.TryGetProperty("access_token", out _));
        Assert.IsTrue(json.RootElement.TryGetProperty("refresh_token", out var refreshToken));
        Assert.IsFalse(string.IsNullOrEmpty(refreshToken.GetString()));
    }

    /// <summary>
    /// Test authorization code flow with missing state is allowed
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCode_MissingState_IsAllowed()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var response = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=spa&redirect_uri={Uri.EscapeDataString("http://localhost:3000/callback")}&scope=openid%20profile%20api1&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");

        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(response).Query);
        Assert.IsFalse(string.IsNullOrEmpty(query["code"]));
        Assert.IsNull(query["state"]);
        Assert.AreEqual("https://localhost:7020", query["iss"]);
    }

    /// <summary>
    /// Test authorization code with wrong verifier returns invalid grant
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCode_WithWrongVerifier_ReturnsInvalidGrant()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var authorizeResponse = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20profile%20api1&state=abc&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");
        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(authorizeResponse).Query);

        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["code"] = query["code"]!,
            ["redirect_uri"] = "https://localhost:5002/signin-oidc",
            ["code_verifier"] = "wrong-verifier"
        }));

        Assert.AreEqual(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("invalid_grant", body.RootElement.GetProperty("error").GetString());
    }

    /// <summary>
    /// Test authorization with invalid scope redirects with issuer and error
    /// </summary>
    [TestMethod]
    public async Task Authorization_InvalidScope_RedirectsWithIssuerAndError()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var response = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20missing&state=bad-scope&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");

        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(response).Query);
        Assert.AreEqual("invalid_scope", query["error"]);
        Assert.AreEqual("bad-scope", query["state"]);
        Assert.AreEqual("https://localhost:7020", query["iss"]);
    }

    /// <summary>
    /// Test refresh token rotation and old token becomes invalid
    /// </summary>
    [TestMethod]
    public async Task RefreshToken_RotatesAndOldTokenBecomesInvalid()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var authorizeResponse = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20profile%20api1&state=xyz&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");
        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(authorizeResponse).Query);

        var exchangeResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["code"] = query["code"]!,
            ["redirect_uri"] = "https://localhost:5002/signin-oidc",
            ["code_verifier"] = verifier
        }));
        exchangeResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await exchangeResponse.Content.ReadAsStreamAsync());
        var refreshToken = tokenJson.RootElement.GetProperty("refresh_token").GetString()!;

        var refreshResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["refresh_token"] = refreshToken
        }));
        refreshResponse.EnsureSuccessStatusCode();
        var refreshedJson = await JsonDocument.ParseAsync(await refreshResponse.Content.ReadAsStreamAsync());
        var rotatedRefreshToken = refreshedJson.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.AreNotEqual(refreshToken, rotatedRefreshToken);

        var oldRefreshResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["refresh_token"] = refreshToken
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, oldRefreshResponse.StatusCode);
    }

    /// <summary>
    /// Test refresh token can request narrower scope
    /// </summary>
    [TestMethod]
    public async Task RefreshToken_CanRequestNarrowerScope()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var authorizeResponse = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20profile%20api1&state=narrow&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");
        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(authorizeResponse).Query);

        var exchangeResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["code"] = query["code"]!,
            ["redirect_uri"] = "https://localhost:5002/signin-oidc",
            ["code_verifier"] = verifier
        }));
        exchangeResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await exchangeResponse.Content.ReadAsStreamAsync());
        var refreshToken = tokenJson.RootElement.GetProperty("refresh_token").GetString()!;

        var refreshResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["refresh_token"] = refreshToken,
            ["scope"] = "openid api1"
        }));

        refreshResponse.EnsureSuccessStatusCode();
        var refreshedJson = await JsonDocument.ParseAsync(await refreshResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("openid api1", refreshedJson.RootElement.GetProperty("scope").GetString());
    }

    /// <summary>
    /// Test refresh token cannot expand scope
    /// </summary>
    [TestMethod]
    public async Task RefreshToken_CannotExpandScope()
    {
        var verifier = CreateCodeVerifier();
        var challenge = CreateCodeChallenge(verifier);
        var authorizeResponse = await _client.GetAsync($"/connect/authorize?response_type=code&client_id=mvc&redirect_uri={Uri.EscapeDataString("https://localhost:5002/signin-oidc")}&scope=openid%20api1&state=expand&code_challenge={challenge}&code_challenge_method=S256&subject_id=test-user");
        var query = System.Web.HttpUtility.ParseQueryString(GetAuthorizationResponseUri(authorizeResponse).Query);

        var exchangeResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["code"] = query["code"]!,
            ["redirect_uri"] = "https://localhost:5002/signin-oidc",
            ["code_verifier"] = verifier
        }));
        exchangeResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await exchangeResponse.Content.ReadAsStreamAsync());
        var refreshToken = tokenJson.RootElement.GetProperty("refresh_token").GetString()!;

        var refreshResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mvc",
            ["client_secret"] = "secret",
            ["refresh_token"] = refreshToken,
            ["scope"] = "openid profile api1"
        }));

        Assert.AreEqual(HttpStatusCode.BadRequest, refreshResponse.StatusCode);
        var errorJson = await JsonDocument.ParseAsync(await refreshResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("invalid_scope", errorJson.RootElement.GetProperty("error").GetString());
    }

    #endregion

    #region Introspection

    /// <summary>
    /// Test introspection with valid token returns active
    /// </summary>
    [TestMethod]
    public async Task Introspection_ValidToken_ReturnsActive()
    {
        // Get a token first
        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "secret",
            ["scope"] = "api1"
        }));
        tokenResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;

        // Introspect using Basic auth (as the controller expects)
        var response = await _client.SendAsync(PostForm("/connect/introspect", new()
        {
            ["token"] = accessToken
        }, "console:secret"));
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.IsTrue(json.RootElement.GetProperty("active").GetBoolean());
    }

    /// <summary>
    /// Test introspection with invalid client secret returns unauthorized
    /// </summary>
    [TestMethod]
    public async Task Introspection_InvalidClientSecret_ReturnsUnauthorized()
    {
        var response = await _client.SendAsync(PostForm("/connect/introspect", new()
        {
            ["token"] = "any-token"
        }, "console:wrong-secret"));
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Test introspection with invalid token returns inactive
    /// </summary>
    [TestMethod]
    public async Task Introspection_InvalidToken_ReturnsInactive()
    {
        var response = await _client.SendAsync(PostForm("/connect/introspect", new()
        {
            ["token"] = "invalid-token-value"
        }, "console:secret"));
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.IsFalse(json.RootElement.GetProperty("active").GetBoolean());
    }

    /// <summary>
    /// Test introspection of revoked token returns inactive
    /// </summary>
    [TestMethod]
    public async Task Introspection_RevokedToken_ReturnsInactive()
    {
        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "console",
            ["client_secret"] = "secret",
            ["scope"] = "api1"
        }));
        tokenResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;

        var revokeResponse = await _client.SendAsync(PostForm("/connect/revocation", new()
        {
            ["token"] = accessToken
        }, "console:secret"));
        revokeResponse.EnsureSuccessStatusCode();

        var introspectResponse = await _client.SendAsync(PostForm("/connect/introspect", new()
        {
            ["token"] = accessToken
        }, "console:secret"));
        introspectResponse.EnsureSuccessStatusCode();
        var introspection = await JsonDocument.ParseAsync(await introspectResponse.Content.ReadAsStreamAsync());
        Assert.IsFalse(introspection.RootElement.GetProperty("active").GetBoolean());
    }

    #endregion

    #region Device Flow

    /// <summary>
    /// Test device authorization with valid client returns device code
    /// </summary>
    [TestMethod]
    public async Task DeviceAuthorization_ValidClient_ReturnsDeviceCode()
    {
        var response = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "device",
            ["scope"] = "openid profile api1"
        }));
        response.EnsureSuccessStatusCode();
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = json.RootElement;
        Assert.IsTrue(root.TryGetProperty("device_code", out var dc));
        Assert.IsFalse(string.IsNullOrEmpty(dc.GetString()));
        Assert.IsTrue(root.TryGetProperty("user_code", out var uc));
        Assert.IsFalse(string.IsNullOrEmpty(uc.GetString()));
        Assert.IsTrue(root.TryGetProperty("verification_uri", out _));
        Assert.IsTrue(root.TryGetProperty("verification_uri_complete", out _));
        Assert.IsTrue(root.GetProperty("expires_in").GetInt32() > 0);
        Assert.AreEqual(5, root.GetProperty("interval").GetInt32());
    }

    /// <summary>
    /// Test device authorization with unauthorized client returns 400
    /// </summary>
    [TestMethod]
    public async Task DeviceAuthorization_UnauthorizedClient_Returns400()
    {
        var response = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "console"
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Test device code pending authorization returns authorization pending
    /// </summary>
    [TestMethod]
    public async Task DeviceCode_PendingAuthorization_ReturnsAuthorizationPending()
    {
        // Get device code
        var authResponse = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "device",
            ["scope"] = "openid api1"
        }));
        authResponse.EnsureSuccessStatusCode();
        var authJson = await JsonDocument.ParseAsync(await authResponse.Content.ReadAsStreamAsync());
        var deviceCode = authJson.RootElement.GetProperty("device_code").GetString()!;

        // Try to exchange before user authorizes
        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["client_id"] = "device",
            ["device_code"] = deviceCode
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var errorJson = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("authorization_pending", errorJson.RootElement.GetProperty("error").GetString());
    }

    /// <summary>
    /// Test device code polling too quickly returns slow down
    /// </summary>
    [TestMethod]
    public async Task DeviceCode_PollingTooQuickly_ReturnsSlowDown()
    {
        var authResponse = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "device",
            ["scope"] = "openid api1"
        }));
        authResponse.EnsureSuccessStatusCode();
        var authJson = await JsonDocument.ParseAsync(await authResponse.Content.ReadAsStreamAsync());
        var deviceCode = authJson.RootElement.GetProperty("device_code").GetString()!;

        var firstPollResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["client_id"] = "device",
            ["device_code"] = deviceCode
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, firstPollResponse.StatusCode);
        var firstErrorJson = await JsonDocument.ParseAsync(await firstPollResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("authorization_pending", firstErrorJson.RootElement.GetProperty("error").GetString());

        var secondPollResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["client_id"] = "device",
            ["device_code"] = deviceCode
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, secondPollResponse.StatusCode);
        var secondErrorJson = await JsonDocument.ParseAsync(await secondPollResponse.Content.ReadAsStreamAsync());
        Assert.AreEqual("slow_down", secondErrorJson.RootElement.GetProperty("error").GetString());
    }

    /// <summary>
    /// Test device code full flow returns access token
    /// </summary>
    [TestMethod]
    public async Task DeviceCode_FullFlow_ReturnsAccessToken()
    {
        // Step 1: Get device code
        var authResponse = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "device",
            ["scope"] = "openid api1"
        }));
        authResponse.EnsureSuccessStatusCode();
        var authJson = await JsonDocument.ParseAsync(await authResponse.Content.ReadAsStreamAsync());
        var deviceCode = authJson.RootElement.GetProperty("device_code").GetString()!;
        var userCode = authJson.RootElement.GetProperty("user_code").GetString()!;

        // Step 2: User authorizes the device
        var verifyResponse = await _client.SendAsync(PostForm("/connect/device_verify", new()
        {
            ["user_code"] = userCode,
            ["subject_id"] = "test-user-123"
        }));
        verifyResponse.EnsureSuccessStatusCode();

        // Step 3: Exchange device code for tokens
        var tokenResponse = await _client.SendAsync(PostForm("/connect/token", new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["client_id"] = "device",
            ["device_code"] = deviceCode
        }));
        tokenResponse.EnsureSuccessStatusCode();
        var tokenJson = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        Assert.IsTrue(tokenJson.RootElement.TryGetProperty("access_token", out var at));
        Assert.IsFalse(string.IsNullOrEmpty(at.GetString()));
        Assert.AreEqual("Bearer", tokenJson.RootElement.GetProperty("token_type").GetString());
    }

    #endregion
}
