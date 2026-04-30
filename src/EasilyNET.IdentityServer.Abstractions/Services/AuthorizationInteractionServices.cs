namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 授权交互账号候选服务
/// </summary>
public interface IAuthorizationAccountService
{
    /// <summary>
    /// 根据当前授权上下文解析可选账号
    /// </summary>
    Task<IReadOnlyCollection<AuthorizationAccountCandidate>> GetAccountsAsync(AuthorizationAccountQuery query, CancellationToken cancellationToken = default);

    /// <summary>
    /// 根据 subjectId 获取账号
    /// </summary>
    Task<AuthorizationAccountCandidate?> FindBySubjectIdAsync(string subjectId, CancellationToken cancellationToken = default);
}

/// <summary>
/// 账号查询参数
/// </summary>
public class AuthorizationAccountQuery
{
    /// <summary>
    /// 当前已选 subjectId
    /// </summary>
    public string? CurrentSubjectId { get; init; }

    /// <summary>
    /// 客户端允许的 Identity Provider 列表
    /// </summary>
    public IEnumerable<string> IdentityProviderRestrictions { get; init; } = [];

    /// <summary>
    /// 登录提示
    /// </summary>
    public string? LoginHint { get; init; }
}

/// <summary>
/// 授权交互中的账号候选项
/// </summary>
public class AuthorizationAccountCandidate
{
    /// <summary>
    /// 展示名称
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Identity Provider
    /// </summary>
    public string? IdentityProvider { get; init; }

    /// <summary>
    /// 是否为当前选中账号
    /// </summary>
    public bool IsCurrent { get; init; }

    /// <summary>
    /// 登录提示（例如 email）
    /// </summary>
    public string? LoginHint { get; init; }

    /// <summary>
    /// subject 标识
    /// </summary>
    public required string SubjectId { get; init; }
}