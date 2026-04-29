using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace EasilyNET.IdentityServer.IntegrationTests;

/// <summary>
/// 速率限制集成测试
/// </summary>
public class RateLimitTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public RateLimitTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            // 配置测试环境
            builder.ConfigureServices(services =>
            {
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
                        }
                    };
                    options.IncludeHeaders = true;
                });
            });
        });

        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task TokenEndpoint_WithinLimit_ShouldReturn200()
    {
        // Act
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "console"),
            new KeyValuePair<string, string>("client_secret", "secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.Contains("X-RateLimit-Limit"));
        Assert.True(response.Headers.Contains("X-RateLimit-Remaining"));
    }

    [Fact]
    public async Task TokenEndpoint_ExceedsLimit_ShouldReturn429()
    {
        // Arrange - 先消耗掉所有配额
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "console"),
            new KeyValuePair<string, string>("client_secret", "secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

        // Act - 发送超过限制的请求
        for (int i = 0; i < 3; i++)
        {
            var response = await _client.PostAsync("/connect/token", content);
        }

        // 第4个请求应该被限制
        var limitedResponse = await _client.PostAsync("/connect/token", content);

        // Assert
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedResponse.StatusCode);
        Assert.True(limitedResponse.Headers.Contains("Retry-After"));

        var responseBody = await limitedResponse.Content.ReadAsStringAsync();
        Assert.Contains("rate_limit_exceeded", responseBody);
    }

    [Fact]
    public async Task TokenEndpoint_RateLimitHeaders_ShouldBePresent()
    {
        // Act
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "console"),
            new KeyValuePair<string, string>("client_secret", "secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

        var response = await _client.PostAsync("/connect/token", content);

        // Assert
        Assert.True(response.Headers.Contains("X-RateLimit-Limit"));
        Assert.True(response.Headers.Contains("X-RateLimit-Remaining"));
        Assert.True(response.Headers.Contains("X-RateLimit-Reset"));

        var limit = response.Headers.GetValues("X-RateLimit-Limit").First();
        Assert.Equal("3", limit);
    }

    [Fact]
    public async Task DiscoveryEndpoint_ShouldNotBeRateLimited()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_InvalidClient_ShouldStillCountTowardsRateLimit()
    {
        // Arrange
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "invalid-client"),
            new KeyValuePair<string, string>("client_secret", "wrong-secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

        // Act - 发送多次无效请求
        for (int i = 0; i < 3; i++)
        {
            var response = await _client.PostAsync("/connect/token", content);
            // 即使是 401 也应该计数
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // 第4个请求应该被限制
        var limitedResponse = await _client.PostAsync("/connect/token", content);

        // Assert
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedResponse.StatusCode);
    }

    [Fact]
    public async Task DifferentEndpoints_ShouldHaveIndependentLimits()
    {
        // Arrange
        var tokenContent = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "client_credentials"),
            new KeyValuePair<string, string>("client_id", "console"),
            new KeyValuePair<string, string>("client_secret", "secret"),
            new KeyValuePair<string, string>("scope", "api1")
        });

        // Act - 消耗 Token 端点配额
        for (int i = 0; i < 3; i++)
        {
            await _client.PostAsync("/connect/token", tokenContent);
        }

        // Token 端点应该被限制
        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);

        // 但其他端点应该仍然可以访问
        var discoveryResponse = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(HttpStatusCode.TooManyRequests, tokenResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, discoveryResponse.StatusCode);
    }
}
