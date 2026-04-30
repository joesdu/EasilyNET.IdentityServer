using System;
using System.Threading;
using System.Threading.Tasks;
using EasilyNET.IdentityServer.Abstractions.Extensions;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Core.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EasilyNET.IdentityServer.Core.Tests.Services;

/// <summary>
/// 速率限制服务测试
/// </summary>
[TestClass]
public class RateLimitServiceTests : IDisposable
{
    private readonly RateLimitService _service;
    private readonly Mock<ILogger<RateLimitService>> _loggerMock;

    public RateLimitServiceTests()
    {
        _loggerMock = new Mock<ILogger<RateLimitService>>();
        var options = new RateLimitOptions
        {
            Enabled = true,
            IpLimits = new()
            {
                new() { EndpointPattern = "/connect/token", WindowSeconds = 60, MaxRequests = 5 },
                new() { EndpointPattern = "*", WindowSeconds = 60, MaxRequests = 10 }
            }
        };

        _service = new RateLimitService(
            Options.Create(options),
            _loggerMock.Object);
    }

    [TestMethod]
    public async Task IsAllowedAsync_FirstRequest_ShouldReturnTrue()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act
        var result = await _service.IsAllowedAsync(key, limitType);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public async Task IsAllowedAsync_WithinLimit_ShouldReturnTrue()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act - 记录4个请求（限制是5个）
        for (int i = 0; i < 4; i++)
        {
            await _service.RecordRequestAsync(key, limitType);
        }

        var result = await _service.IsAllowedAsync(key, limitType);

        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public async Task IsAllowedAsync_ExceedsLimit_ShouldReturnFalse()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act - 记录5个请求达到限制
        for (int i = 0; i < 5; i++)
        {
            await _service.RecordRequestAsync(key, limitType);
        }

        var result = await _service.IsAllowedAsync(key, limitType);

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task IsAllowedAsync_DifferentKeys_ShouldBeIndependent()
    {
        // Arrange
        var key1 = "192.168.1.1";
        var key2 = "192.168.1.2";
        var limitType = RateLimitType.TokenEndpoint;

        // Act - key1 达到限制
        for (int i = 0; i < 5; i++)
        {
            await _service.RecordRequestAsync(key1, limitType);
        }

        // key1 应该被限制
        var key1Result = await _service.IsAllowedAsync(key1, limitType);
        // key2 应该仍然允许
        var key2Result = await _service.IsAllowedAsync(key2, limitType);

        // Assert
        Assert.IsFalse(key1Result);
        Assert.IsTrue(key2Result);
    }

    [TestMethod]
    public async Task IsAllowedAsync_DifferentLimitTypes_ShouldBeIndependent()
    {
        // Arrange
        var key = "192.168.1.1";

        // Act - TokenEndpoint 达到限制
        for (int i = 0; i < 5; i++)
        {
            await _service.RecordRequestAsync(key, RateLimitType.TokenEndpoint);
        }

        // TokenEndpoint 应该被限制
        var tokenResult = await _service.IsAllowedAsync(key, RateLimitType.TokenEndpoint);
        // AuthorizeEndpoint 应该仍然允许
        var authorizeResult = await _service.IsAllowedAsync(key, RateLimitType.AuthorizeEndpoint);

        // Assert
        Assert.IsFalse(tokenResult);
        Assert.IsTrue(authorizeResult);
    }

    [TestMethod]
    public async Task GetRemainingRequestsAsync_NoRequests_ShouldReturnMax()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act
        var remaining = await _service.GetRemainingRequestsAsync(key, limitType);

        // Assert
        Assert.AreEqual(5, remaining);
    }

    [TestMethod]
    public async Task GetRemainingRequestsAsync_AfterRequests_ShouldReturnCorrectCount()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act
        await _service.RecordRequestAsync(key, limitType);
        await _service.RecordRequestAsync(key, limitType);

        var remaining = await _service.GetRemainingRequestsAsync(key, limitType);

        // Assert (5 - 2 = 3)
        Assert.AreEqual(3, remaining);
    }

    [TestMethod]
    public async Task ClearLimitAsync_ShouldResetCount()
    {
        // Arrange
        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // 达到限制
        for (int i = 0; i < 5; i++)
        {
            await _service.RecordRequestAsync(key, limitType);
        }

        // 验证被限制
        Assert.IsFalse(await _service.IsAllowedAsync(key, limitType));

        // Act - 清除限制
        await _service.ClearLimitAsync(key);

        // Assert - 应该再次允许
        Assert.IsTrue(await _service.IsAllowedAsync(key, limitType));
        Assert.AreEqual(5, await _service.GetRemainingRequestsAsync(key, limitType));
    }

    [TestMethod]
    public async Task IsAllowedAsync_Disabled_ShouldAlwaysReturnTrue()
    {
        // Arrange
        var loggerMock = new Mock<ILogger<RateLimitService>>();
        var options = new RateLimitOptions
        {
            Enabled = false,
            IpLimits = new()
            {
                new() { EndpointPattern = "*", WindowSeconds = 60, MaxRequests = 1 }
            }
        };

        var service = new RateLimitService(
            Options.Create(options),
            loggerMock.Object);

        var key = "192.168.1.1";
        var limitType = RateLimitType.TokenEndpoint;

        // Act - 即使记录很多请求
        for (int i = 0; i < 100; i++)
        {
            await service.RecordRequestAsync(key, limitType);
        }

        var result = await service.IsAllowedAsync(key, limitType);

        // Assert - 应该仍然允许
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void IsIpWhitelisted_WhitelistedIp_ShouldReturnTrue()
    {
        // Arrange
        var loggerMock = new Mock<ILogger<RateLimitService>>();
        var options = new RateLimitOptions
        {
            WhitelistIps = new() { "127.0.0.1", "10.0.0.1" }
        };

        var service = new RateLimitService(
            Options.Create(options),
            loggerMock.Object);

        // Act & Assert
        Assert.IsTrue(service.IsIpWhitelisted("127.0.0.1"));
        Assert.IsTrue(service.IsIpWhitelisted("10.0.0.1"));
        Assert.IsFalse(service.IsIpWhitelisted("192.168.1.1"));
    }

    [TestMethod]
    public void IsClientWhitelisted_WhitelistedClient_ShouldReturnTrue()
    {
        // Arrange
        var loggerMock = new Mock<ILogger<RateLimitService>>();
        var options = new RateLimitOptions
        {
            WhitelistClients = new() { "admin", "internal-service" }
        };

        var service = new RateLimitService(
            Options.Create(options),
            loggerMock.Object);

        // Act & Assert
        Assert.IsTrue(service.IsClientWhitelisted("admin"));
        Assert.IsTrue(service.IsClientWhitelisted("internal-service"));
        Assert.IsFalse(service.IsClientWhitelisted("regular-client"));
    }

    [DataTestMethod]
    [DataRow("/connect/token", RateLimitType.TokenEndpoint)]
    [DataRow("/connect/authorize", RateLimitType.AuthorizeEndpoint)]
    [DataRow("/connect/device_authorization", RateLimitType.DeviceAuthorizationEndpoint)]
    [DataRow("/connect/device_verify", RateLimitType.VerifyEndpoint)]
    [DataRow("/unknown", RateLimitType.General)]
    public void GetLimitTypeForEndpoint_VariousPaths_ShouldReturnCorrectType(string path, RateLimitType expected)
    {
        // Arrange
        var loggerMock = new Mock<ILogger<RateLimitService>>();
        var service = new RateLimitService(
            Options.Create(new RateLimitOptions()),
            loggerMock.Object);

        // Act
        var result = service.GetLimitTypeForEndpoint(path);

        // Assert
        Assert.AreEqual(expected, result);
    }

    [TestCleanup]
    public void Dispose()
    {
        _service?.Dispose();
    }
}
