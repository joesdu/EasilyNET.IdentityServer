namespace EasilyNET.IdentityServer.DataAccess.EFCore.Entities;

/// <summary>
/// 审计日志实体
/// </summary>
public class AuditLogEntity
{
    public long Id { get; set; }

    public required string EventType { get; set; }

    public DateTime Timestamp { get; set; }

    public string? ClientId { get; set; }

    public string? SubjectId { get; set; }

    public string? GrantType { get; set; }

    public string? Scopes { get; set; }

    public bool Success { get; set; }

    public string? FailureReason { get; set; }

    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    public string? RequestPath { get; set; }

    public string? PropertiesJson { get; set; }
}