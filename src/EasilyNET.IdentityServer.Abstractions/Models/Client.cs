namespace EasilyNET.IdentityServer.Abstractions.Models;

/// <summary>
/// 客户端模型
/// </summary>
public class Client
{
    /// <summary>
    /// 联系人
    /// </summary>
    public IEnumerable<string> Contacts { get; init; } = [];

    /// <summary>
    /// 访问令牌生命周期（秒）
    /// </summary>
    public int AccessTokenLifetime { get; init; } = 3600;

    /// <summary>
    /// 允许的跨域源
    /// </summary>
    public IEnumerable<string> AllowedCorsOrigins { get; init; } = [];

    /// <summary>
    /// 允许的授权类型
    /// </summary>
    public required IEnumerable<string> AllowedGrantTypes { get; init; }

    /// <summary>
    /// 允许的授权响应类型
    /// </summary>
    public IEnumerable<string> AllowedResponseTypes { get; init; } = [];

    /// <summary>
    /// 允许的作用域
    /// </summary>
    public required IEnumerable<string> AllowedScopes { get; init; }

    /// <summary>
    /// 是否允许纯文本 PKCE
    /// </summary>
    public bool AllowPlainTextPkce { get; init; }

    /// <summary>
    /// 允许 Remember Consent
    /// </summary>
    public bool AllowRememberConsent { get; init; } = true;

    /// <summary>
    /// 授权码生命周期（秒）
    /// </summary>
    public int AuthorizationCodeLifetime { get; init; } = 300;

    /// <summary>
    /// 授权提示
    /// </summary>
    public IEnumerable<string> AuthorizationPromptTypes { get; init; } = [];

    /// <summary>
    /// 允许的后端登出 URI
    /// </summary>
    public IEnumerable<string> BackChannelLogoutUris { get; init; } = [];

    /// <summary>
    /// 声明类型列表
    /// </summary>
    public IEnumerable<ClientClaim> Claims { get; init; } = [];

    /// <summary>
    /// 唯一标识符
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 客户端名称
    /// </summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// 客户端密钥列表
    /// </summary>
    public IEnumerable<Secret> ClientSecrets { get; init; } = [];

    /// <summary>
    /// 客户端类型
    /// </summary>
    public ClientType ClientType { get; init; } = ClientType.Confidential;

    /// <summary>
    /// 客户端 URI
    /// </summary>
    public string? ClientUri { get; init; }

    /// <summary>
    /// JWK Set（JSON 文本）
    /// </summary>
    public string? Jwks { get; init; }

    /// <summary>
    /// JWK Set URI
    /// </summary>
    public string? JwksUri { get; init; }

    /// <summary>
    /// 描述
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// 设备代码生命周期（秒）
    /// </summary>
    public int DeviceCodeLifetime { get; init; } = 300;

    /// <summary>
    /// 设备代码验证
    /// </summary>
    public int? DeviceCodeLifetimeValue { get; init; }

    /// <summary>
    /// 设备流轮询间隔（秒）
    /// </summary>
    public int DevicePollingInterval { get; init; }

    /// <summary>
    /// 是否启用
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// 允许的前端登出 URI
    /// </summary>
    public IEnumerable<string> FrontChannelLogoutUris { get; init; } = [];

    /// <summary>
    /// 授权类型列表
    /// </summary>
    public IEnumerable<string> IdentityProviderRestrictions { get; init; } = [];

    /// <summary>
    /// Logo URI
    /// </summary>
    public string? LogoUri { get; init; }

    /// <summary>
    /// Policy URI
    /// </summary>
    public string? PolicyUri { get; init; }

    /// <summary>
    /// 额外的属性
    /// </summary>
    public IDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// 是否要求 DPoP 证明
    /// </summary>
    public bool RequireDpopProof { get; init; }

    /// <summary>
    /// 允许的重定向 URI
    /// </summary>
    public IEnumerable<string> RedirectUris { get; init; } = [];

    /// <summary>
    /// 刷新令牌生命周期（秒）
    /// </summary>
    public int RefreshTokenLifetime { get; init; } = 86400;

    /// <summary>
    /// 是否需要 Secret
    /// </summary>
    public bool RequireClientSecret { get; init; } = true;

    /// <summary>
    /// token 端点认证方法
    /// </summary>
    public string TokenEndpointAuthMethod { get; init; } = "client_secret_basic";

    /// <summary>
    /// 是否需要Consent
    /// </summary>
    public bool RequireConsent { get; init; } = true;

    /// <summary>
    /// 是否需要 PKCE
    /// </summary>
    public bool RequirePkce { get; init; } = true;

    /// <summary>
    /// 用户代码类型
    /// </summary>
    public string? UserCodeType { get; init; }

    /// <summary>
    /// TLS 客户端认证证书主题 DN
    /// </summary>
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>
    /// TLS 客户端认证证书指纹
    /// </summary>
    public string? TlsClientAuthThumbprint { get; init; }

    /// <summary>
    /// 服务条款 URI
    /// </summary>
    public string? TosUri { get; init; }
}

/// <summary>
/// 客户端类型
/// </summary>
public enum ClientType
{
    /// <summary>
    /// 机密客户端
    /// </summary>
    Confidential = 0,

    /// <summary>
    /// 公开客户端
    /// </summary>
    Public = 1
}