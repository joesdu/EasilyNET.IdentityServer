using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using EasilyNET.IdentityServer.Abstractions.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace EasilyNET.IdentityServer.IntegrationTests;

/// <summary>
/// 速率限制集成测试
/// </summary>
[TestClass]
public class RateLimitTests
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [TestInitialize]
    public void Setup()
    {
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            // 配置测试环境
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<ISigningService>();
                services.AddSingleton<ISigningService, TestSigningService>();

                // 配置更严格的限制用于测试
                services.Configure<EasilyNET.IdentityServer.Abstractions.Extensions.RateLimitOptions>(options =>
                {
                    options.Enabled = true;
                    options.IpLimits = new()
                    {
                        new()
                        {
                            EndpointPattern = "/connect/token",
                            WindowSeconds = 60,
                            MaxRequests = 3 // 测试用限制
                        },
                        new()
                        {
                            EndpointPattern = "*",
                            WindowSeconds = 60,
                            MaxRequests = 120
                        }
                    };
                    options.IncludeHeaders = true;
                });
            });
        });

        _client = _factory.CreateClient();
    }

    [TestCleanup]
    public void Cleanup()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [TestMethod]
    public async Task TokenEndpoint_WithinLimit_ShouldReturn200()
    {
        // Act
        var response = await _client.PostAsync("/connect/token", CreateValidTokenRequest());

        // Assert
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsTrue(response.Headers.Contains("X-RateLimit-Limit"));
        Assert.IsTrue(response.Headers.Contains("X-RateLimit-Remaining"));
    }

    [TestMethod]
    public async Task TokenEndpoint_ExceedsLimit_ShouldReturn429()
    {
        // Act - 发送超过限制的请求
        for (var i = 0; i < 3; i++)
        {
            await _client.PostAsync("/connect/token", CreateValidTokenRequest());
        }

        // 第4个请求应该被限制
        var limitedResponse = await _client.PostAsync("/connect/token", CreateValidTokenRequest());

        // Assert
        Assert.AreEqual(HttpStatusCode.TooManyRequests, limitedResponse.StatusCode);
        Assert.IsTrue(limitedResponse.Headers.Contains("Retry-After"));

        var responseBody = await limitedResponse.Content.ReadAsStringAsync();
        StringAssert.Contains(responseBody, "rate_limit_exceeded");
    }

    [TestMethod]
    public async Task TokenEndpoint_RateLimitHeaders_ShouldBePresent()
    {
        // Act
        var response = await _client.PostAsync("/connect/token", CreateValidTokenRequest());

        // Assert
        Assert.IsTrue(response.Headers.Contains("X-RateLimit-Limit"));
        Assert.IsTrue(response.Headers.Contains("X-RateLimit-Remaining"));
        Assert.IsTrue(response.Headers.Contains("X-RateLimit-Reset"));

        var limit = response.Headers.GetValues("X-RateLimit-Limit").First();
        Assert.AreEqual("3", limit);
    }

    [TestMethod]
    public async Task DiscoveryEndpoint_ShouldNotBeRateLimited()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [TestMethod]
    public async Task TokenEndpoint_InvalidClient_ShouldStillCountTowardsRateLimit()
    {
        // Act - 发送多次无效请求
        for (var i = 0; i < 3; i++)
        {
            var response = await _client.PostAsync("/connect/token", CreateInvalidClientTokenRequest());
            // 即使是 401 也应该计数
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // 第4个请求应该被限制
        var limitedResponse = await _client.PostAsync("/connect/token", CreateInvalidClientTokenRequest());

        // Assert
        Assert.AreEqual(HttpStatusCode.TooManyRequests, limitedResponse.StatusCode);
    }

    [TestMethod]
    public async Task DifferentEndpoints_ShouldHaveIndependentLimits()
    {
        // Act - 消耗 Token 端点配额
        for (var i = 0; i < 3; i++)
        {
            await _client.PostAsync("/connect/token", CreateValidTokenRequest());
        }

        // Token 端点应该被限制
        var tokenResponse = await _client.PostAsync("/connect/token", CreateValidTokenRequest());

        // 但其他端点应该仍然可以访问
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.AreEqual(HttpStatusCode.TooManyRequests, tokenResponse.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, discoveryResponse.StatusCode);
    }

    private static FormUrlEncodedContent CreateValidTokenRequest() =>
        new(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "console"),
            new KeyValuePair<string, string>("client_secret", "secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

    private static FormUrlEncodedContent CreateInvalidClientTokenRequest() =>
        new(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "invalid-client"),
            new KeyValuePair<string, string>("client_secret", "wrong-secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });
}
