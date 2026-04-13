using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace EasilyNET.IdentityServer.IntegrationTests;

[TestClass]
public class IdentityServerTests
{
    private HttpClient _client = null!;

    [TestInitialize]
    public void Setup()
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder => builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Development"));
        _client = factory.CreateClient();
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

    #region Revocation

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

    #endregion

    #region Health

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
    }

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

    #region Introspection

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

    #endregion

    #region Device Flow

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

    [TestMethod]
    public async Task DeviceAuthorization_UnauthorizedClient_Returns400()
    {
        var response = await _client.SendAsync(PostForm("/connect/device_authorization", new()
        {
            ["client_id"] = "console"
        }));
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

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