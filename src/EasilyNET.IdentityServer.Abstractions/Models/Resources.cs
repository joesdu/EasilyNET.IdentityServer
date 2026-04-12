namespace EasilyNET.IdentityServer.Abstractions.Models;

/// <summary>
/// API 资源
/// </summary>
public class ApiResource
{
    /// <summary>
    /// 唯一标识符
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 显示名称
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 是否启用
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// 允许的作用域
    /// </summary>
    public required IEnumerable<string> Scopes { get; init; }

    /// <summary>
    /// 允许的声明
    /// </summary>
    public IEnumerable<string> UserClaims { get; init; } = [];

    /// <summary>
    /// 密钥列表
    /// </summary>
    public IEnumerable<Secret> ApiSecrets { get; init; } = [];

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// API 作用域
/// </summary>
public class ApiScope
{
    /// <summary>
    /// 唯一标识符
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 显示名称
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 是否启用
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// 是否必须显示在发现文档中
    /// </summary>
    public bool Required { get; init; }

    /// <summary>
    /// 是否可以在同意屏幕中取消选择
    /// </summary>
    public bool Emphasize { get; init; }

    /// <summary>
    /// 允许的声明
    /// </summary>
    public IEnumerable<string> UserClaims { get; init; } = [];

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Identity 资源
/// </summary>
public class IdentityResource
{
    /// <summary>
    /// 唯一标识符
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 显示名称
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 是否启用
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// 是否必须显示在发现文档中
    /// </summary>
    public bool Required { get; init; }

    /// <summary>
    /// 是否可以在同意屏幕中取消选择
    /// </summary>
    public bool Emphasize { get; init; }

    /// <summary>
    /// 是否可以在同意屏幕中取消选择
    /// </summary>
    public bool ShowInDiscoveryDocument { get; init; } = true;

    /// <summary>
    /// 允许的声明
    /// </summary>
    public required IEnumerable<string> UserClaims { get; init; }

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// 资源集合
/// </summary>
public class Resources
{
    /// <summary>
    /// API 资源列表
    /// </summary>
    public List<ApiResource> ApiResources { get; init; } = [];

    /// <summary>
    /// API 作用域列表
    /// </summary>
    public List<ApiScope> ApiScopes { get; init; } = [];

    /// <summary>
    /// Identity 资源列表
    /// </summary>
    public List<IdentityResource> IdentityResources { get; init; } = [];
}