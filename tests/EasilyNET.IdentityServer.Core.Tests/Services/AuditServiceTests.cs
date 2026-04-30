using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EasilyNET.IdentityServer.Core.Tests.Services;

/// <summary>
/// 审计服务测试
/// </summary>
[TestClass]
public class AuditServiceTests
{
    private readonly Mock<IAuditLogStore> _auditLogStoreMock;
    private readonly Mock<ILogger<AuditService>> _loggerMock;
    private readonly AuditService _service;

    public AuditServiceTests()
    {
        _auditLogStoreMock = new Mock<IAuditLogStore>();
        _loggerMock = new Mock<ILogger<AuditService>>();
        _service = new AuditService(_auditLogStoreMock.Object, _loggerMock.Object);
    }

    [TestMethod]
    public async Task LogTokenIssuedAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var subjectId = "user123";
        var grantType = "client_credentials";
        var scopes = new[] { "api1", "openid" };
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogTokenIssuedAsync(clientId, subjectId, grantType, scopes, ipAddress);

        // Assert
        _auditLogStoreMock.Verify(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual("token_issued", capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual(subjectId, capturedEntry.SubjectId);
        Assert.AreEqual(grantType, capturedEntry.GrantType);
        Assert.AreEqual(ipAddress, capturedEntry.IpAddress);
    }

    [TestMethod]
    public async Task LogAuthenticationFailedAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var grantType = "client_credentials";
        var reason = "invalid_client";
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogAuthenticationFailedAsync(clientId, grantType, reason, ipAddress);

        // Assert
        _auditLogStoreMock.Verify(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual("authentication_failed", capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual(reason, capturedEntry.Error);
    }

    [TestMethod]
    public async Task LogTokenRevokedAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var subjectId = "user123";
        var tokenType = "refresh_token";
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogTokenRevokedAsync(clientId, subjectId, tokenType, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual("token_revoked", capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual(tokenType, capturedEntry.TokenType);
    }

    [TestMethod]
    public async Task LogAuthorizationCodeExchangedAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var subjectId = "user123";
        var scopes = new[] { "api1", "openid", "profile" };
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogAuthorizationCodeExchangedAsync(clientId, subjectId, scopes, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual("authorization_code_exchanged", capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual("authorization_code", capturedEntry.GrantType);
    }

    [TestMethod]
    public async Task LogRefreshTokenUsedAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var subjectId = "user123";
        var scopes = new[] { "api1" };
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogRefreshTokenUsedAsync(clientId, subjectId, scopes, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual("refresh_token_used", capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual("refresh_token", capturedEntry.GrantType);
    }

    [TestMethod]
    public async Task LogSecurityEventAsync_ShouldStoreAuditLog()
    {
        // Arrange
        var eventType = "suspicious_activity";
        var clientId = "test-client";
        var details = "Multiple failed login attempts";
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogSecurityEventAsync(eventType, clientId, details, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual(eventType, capturedEntry.EventType);
        Assert.AreEqual(clientId, capturedEntry.ClientId);
        Assert.AreEqual(details, capturedEntry.Error);
    }

    [TestMethod]
    public async Task LogTokenIssuedAsync_WithNullSubject_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        string? subjectId = null;
        var grantType = "client_credentials";
        var scopes = new[] { "api1" };
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogTokenIssuedAsync(clientId, subjectId, grantType, scopes, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.IsNull(capturedEntry.SubjectId);
    }

    [TestMethod]
    public async Task LogTokenIssuedAsync_WithEmptyScopes_ShouldStoreAuditLog()
    {
        // Arrange
        var clientId = "test-client";
        var subjectId = "user123";
        var grantType = "client_credentials";
        var scopes = Array.Empty<string>();
        var ipAddress = "192.168.1.1";

        AuditLogEntry? capturedEntry = null;
        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .Callback<AuditLogEntry, CancellationToken>((entry, _) => capturedEntry = entry)
            .Returns(Task.CompletedTask);

        // Act
        await _service.LogTokenIssuedAsync(clientId, subjectId, grantType, scopes, ipAddress);

        // Assert
        Assert.IsNotNull(capturedEntry);
        Assert.AreEqual(string.Empty, capturedEntry.Scope);
    }

    [TestMethod]
    public async Task LogTokenIssuedAsync_StoreThrowsException_ShouldLogError()
    {
        // Arrange
        var clientId = "test-client";
        var grantType = "client_credentials";
        var scopes = new[] { "api1" };
        var ipAddress = "192.168.1.1";

        _auditLogStoreMock
            .Setup(x => x.StoreAsync(It.IsAny<AuditLogEntry>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act & Assert - 不应该抛出异常
        await _service.LogTokenIssuedAsync(clientId, null, grantType, scopes, ipAddress);

        // 验证错误日志被记录
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
