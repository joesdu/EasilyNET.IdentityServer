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
using Xunit;

namespace EasilyNET.IdentityServer.Core.Tests.Services;

/// <summary>
/// 审计服务测试
/// </summary>
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

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal("token_issued", capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal(subjectId, capturedEntry.SubjectId);
        Assert.Equal(grantType, capturedEntry.GrantType);
        Assert.Equal(ipAddress, capturedEntry.IpAddress);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal("authentication_failed", capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal(reason, capturedEntry.Error);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal("token_revoked", capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal(tokenType, capturedEntry.TokenType);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal("authorization_code_exchanged", capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal("authorization_code", capturedEntry.GrantType);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal("refresh_token_used", capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal("refresh_token", capturedEntry.GrantType);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal(eventType, capturedEntry.EventType);
        Assert.Equal(clientId, capturedEntry.ClientId);
        Assert.Equal(details, capturedEntry.Error);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Null(capturedEntry.SubjectId);
    }

    [Fact]
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
        Assert.NotNull(capturedEntry);
        Assert.Equal(string.Empty, capturedEntry.Scope);
    }

    [Fact]
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
