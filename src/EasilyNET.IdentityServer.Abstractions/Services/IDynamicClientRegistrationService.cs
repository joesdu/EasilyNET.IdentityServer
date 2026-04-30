using System.Text.Json;
using System.Text.Json.Serialization;

namespace EasilyNET.IdentityServer.Abstractions.Services;

/// <summary>
/// 动态客户端注册服务
/// </summary>
public interface IDynamicClientRegistrationService
{
    /// <summary>
    /// 注册客户端
    /// </summary>
    Task<DynamicClientRegistrationResult> RegisterClientAsync(DynamicClientRegistrationRequest request, string? initialAccessToken, CancellationToken cancellationToken = default);
}

/// <summary>
/// 动态客户端注册请求
/// </summary>
public sealed class DynamicClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")]
    public string[] RedirectUris { get; init; } = [];

    [JsonPropertyName("grant_types")]
    public string[] GrantTypes { get; init; } = [];

    [JsonPropertyName("response_types")]
    public string[] ResponseTypes { get; init; } = [];

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; init; }

    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; init; }

    [JsonPropertyName("contacts")]
    public string[] Contacts { get; init; } = [];

    [JsonPropertyName("policy_uri")]
    public string? PolicyUri { get; init; }

    [JsonPropertyName("tos_uri")]
    public string? TosUri { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("jwks")]
    public JsonElement? Jwks { get; init; }

    [JsonPropertyName("tls_client_auth_subject_dn")]
    public string? TlsClientAuthSubjectDn { get; init; }

    [JsonPropertyName("tls_client_auth_thumbprint")]
    public string? TlsClientAuthThumbprint { get; init; }

    [JsonPropertyName("require_dpop_proof")]
    public bool? RequireDpopProof { get; init; }

    [JsonPropertyName("software_statement")]
    public string? SoftwareStatement { get; init; }
}

/// <summary>
/// 动态客户端注册文档
/// </summary>
public sealed class DynamicClientRegistrationDocument
{
    [JsonPropertyName("client_id")]
    public required string ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("client_id_issued_at")]
    public long ClientIdIssuedAt { get; init; }

    [JsonPropertyName("client_secret_expires_at")]
    public long ClientSecretExpiresAt { get; init; }

    [JsonPropertyName("redirect_uris")]
    public string[] RedirectUris { get; init; } = [];

    [JsonPropertyName("grant_types")]
    public string[] GrantTypes { get; init; } = [];

    [JsonPropertyName("response_types")]
    public string[] ResponseTypes { get; init; } = [];

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public required string TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; init; }

    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; init; }

    [JsonPropertyName("contacts")]
    public string[] Contacts { get; init; } = [];

    [JsonPropertyName("policy_uri")]
    public string? PolicyUri { get; init; }

    [JsonPropertyName("tos_uri")]
    public string? TosUri { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("jwks")]
    public JsonElement? Jwks { get; init; }

    [JsonPropertyName("tls_client_auth_subject_dn")]
    public string? TlsClientAuthSubjectDn { get; init; }

    [JsonPropertyName("tls_client_auth_thumbprint")]
    public string? TlsClientAuthThumbprint { get; init; }

    [JsonPropertyName("require_dpop_proof")]
    public bool RequireDpopProof { get; init; }

    [JsonPropertyName("software_statement")]
    public string? SoftwareStatement { get; init; }
}

/// <summary>
/// 动态客户端注册结果
/// </summary>
public sealed class DynamicClientRegistrationResult
{
    public DynamicClientRegistrationDocument? Document { get; init; }

    public string? Error { get; init; }

    public string? ErrorDescription { get; init; }

    public bool IsSuccess { get; init; }

    public int StatusCode { get; init; } = 201;
}
