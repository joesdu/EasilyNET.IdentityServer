using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EasilyNET.IdentityServer.Core.Tests.Services;

/// <summary>
/// 客户端认证服务测试
/// </summary>
[TestClass]
public class ClientAuthenticationServiceTests
{
    private readonly Mock<IClientStore> _clientStoreMock;
    private readonly Mock<ILogger<ClientAuthenticationService>> _loggerMock;
    private readonly ClientAuthenticationService _service;

    public ClientAuthenticationServiceTests()
    {
        _clientStoreMock = new Mock<IClientStore>();
        _loggerMock = new Mock<ILogger<ClientAuthenticationService>>();
        _service = new ClientAuthenticationService(_clientStoreMock.Object, _loggerMock.Object);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ValidClientCredentials_ShouldReturnClient()
    {
        // Arrange
        var clientId = "test-client";
        var clientSecret = "secret123";
        var hashedSecret = SecretHasher.HashSecret(clientSecret);

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = hashedSecret,
                    Type = "SharedSecret"
                }
            },
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual(clientId, result.ClientId);
    }

    [TestMethod]
    public async Task AuthenticateAsync_InvalidClientId_ShouldReturnNull()
    {
        // Arrange
        var clientId = "non-existent-client";
        var clientSecret = "secret123";

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Client?)null);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_DisabledClient_ShouldReturnNull()
    {
        // Arrange
        var clientId = "disabled-client";
        var clientSecret = "secret123";
        var hashedSecret = SecretHasher.HashSecret(clientSecret);

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = hashedSecret,
                    Type = "SharedSecret"
                }
            },
            Enabled = false
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_WrongSecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var correctSecret = "correct-secret";
        var wrongSecret = "wrong-secret";
        var hashedSecret = SecretHasher.HashSecret(correctSecret);

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = hashedSecret,
                    Type = "SharedSecret"
                }
            },
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, wrongSecret);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_NoSecrets_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var clientSecret = "secret123";

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>(),
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ExpiredSecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var clientSecret = "secret123";
        var hashedSecret = SecretHasher.HashSecret(clientSecret);

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = hashedSecret,
                    Type = "SharedSecret",
                    Expiration = DateTime.UtcNow.AddDays(-1) // 已过期
                }
            },
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_MultipleSecrets_OneValid_ShouldReturnClient()
    {
        // Arrange
        var clientId = "test-client";
        var validSecret = "valid-secret";
        var expiredSecret = "expired-secret";

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = SecretHasher.HashSecret(expiredSecret),
                    Type = "SharedSecret",
                    Expiration = DateTime.UtcNow.AddDays(-1) // 已过期
                },
                new()
                {
                    Value = SecretHasher.HashSecret(validSecret),
                    Type = "SharedSecret"
                }
            },
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, validSecret);

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual(clientId, result.ClientId);
    }

    [TestMethod]
    public async Task AuthenticateAsync_PlainTextSecretType_ShouldAuthenticate()
    {
        // Arrange
        var clientId = "test-client";
        var clientSecret = "plain-secret";

        var client = new Client
        {
            ClientId = clientId,
            ClientSecrets = new List<Secret>
            {
                new()
                {
                    Value = clientSecret, // 明文存储
                    Type = "PlainText" // 明文类型
                }
            },
            Enabled = true
        };

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(client);

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual(clientId, result.ClientId);
    }

    [TestMethod]
    public async Task AuthenticateAsync_StoreThrowsException_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var clientSecret = "secret123";

        _clientStoreMock.Setup(x => x.FindClientByIdAsync(clientId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _service.AuthenticateAsync(clientId, clientSecret);

        // Assert
        Assert.IsNull(result);

        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => true),
                It.IsAny<Exception>(),
                It.Is<Func<It.IsAnyType, Exception?, string>>((v, t) => true)),
            Times.Once);
    }
}
