namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 审计服务接口
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// 记录审计事件
    /// </summary>
    Task LogEventAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录令牌颁发事件
    /// </summary>
    Task LogTokenIssuedAsync(string clientId, string? subjectId, string grantType, IEnumerable<string> scopes, string? ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录令牌撤销事件
    /// </summary>
    Task LogTokenRevokedAsync(string clientId, string tokenType, string? ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录认证失败事件
    /// </summary>
    Task LogAuthenticationFailedAsync(string clientId, string grantType, string reason, string? ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录授权码交换事件
    /// </summary>
    Task LogAuthorizationCodeExchangedAsync(string clientId, string? subjectId, string? ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// 记录刷新令牌使用事件
    /// </summary>
    Task LogRefreshTokenUsedAsync(string clientId, string? subjectId, bool rotated, string? ipAddress, CancellationToken cancellationToken = default);
}

/// <summary>
/// 审计事件
/// </summary>
public class AuditEvent
{
    /// <summary>
    /// 事件类型
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// 时间戳
    /// </summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// 客户端 ID
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// 用户 ID
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// 授权类型
    /// </summary>
    public string? GrantType { get; init; }

    /// <summary>
    /// 请求的作用域
    /// </summary>
    public IEnumerable<string>? Scopes { get; init; }

    /// <summary>
    /// 是否成功
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// 失败原因
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// IP 地址
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// 用户代理
    /// </summary>
    public string? UserAgent { get; init; }

    /// <summary>
    /// 请求路径
    /// </summary>
    public string? RequestPath { get; init; }

    /// <summary>
    /// 额外属性
    /// </summary>
    public Dictionary<string, string>? Properties { get; init; }
}

/// <summary>
/// 审计事件类型
/// </summary>
public static class AuditEventTypes
{
    public const string TokenIssued = "token_issued";
    public const string TokenRevoked = "token_revoked";
    public const string TokenIntrospected = "token_introspected";
    public const string AuthenticationFailed = "authentication_failed";
    public const string AuthorizationCodeExchanged = "authorization_code_exchanged";
    public const string RefreshTokenUsed = "refresh_token_used";
    public const string ClientAuthenticated = "client_authenticated";
    public const string ClientAuthenticationFailed = "client_authentication_failed";
    public const string DeviceAuthorized = "device_authorized";
    public const string ConsentGranted = "consent_granted";
    public const string ConsentDenied = "consent_denied";
}
