namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 授权作用域元数据服务
/// </summary>
public interface IAuthorizationScopeMetadataService
{
    /// <summary>
    /// 解析授权作用域元数据
    /// </summary>
    Task<IReadOnlyCollection<AuthorizationScopeDescriptor>> DescribeScopesAsync(
        IEnumerable<string> requestedScopes,
        IEnumerable<string>? selectedScopes = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// 授权作用域描述
/// </summary>
public class AuthorizationScopeDescriptor
{
    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 展示名称
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// 是否强调展示
    /// </summary>
    public bool Emphasize { get; init; }

    /// <summary>
    /// 名称
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 是否为必选作用域
    /// </summary>
    public bool Required { get; init; }

    /// <summary>
    /// 是否已选中
    /// </summary>
    public bool Selected { get; init; }

    /// <summary>
    /// 作用域类型：identity/api
    /// </summary>
    public required string Type { get; init; }
}