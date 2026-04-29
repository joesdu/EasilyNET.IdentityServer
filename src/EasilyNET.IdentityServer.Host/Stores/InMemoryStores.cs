using System.Collections.Concurrent;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Stores;
using EasilyNET.IdentityServer.Core.Services;

namespace EasilyNET.IdentityServer.Host.Stores;

/// <summary>
/// 内存客户端存储 (开发环境使用)
/// </summary>
public class InMemoryClientStore : IClientStore
{
    private readonly List<Client> _clients = [];

    public InMemoryClientStore()
    {
        // 添加示例客户端
        _clients.Add(new()
        {
            ClientId = "mvc",
            ClientName = "MVC Client",
            ClientType = ClientType.Confidential,
            Enabled = true,
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            RedirectUris = ["https://localhost:5002/signin-oidc"],
            FrontChannelLogoutUris = ["https://localhost:5002/signout-oidc"],
            BackChannelLogoutUris = ["https://localhost:5002/bff/signout-oidc"],
            AllowedScopes = ["openid", "profile", "email", "api1"],
            ClientSecrets = [new() { Value = SecretHasher.HashSecret("secret"), Description = "MVC Client Secret" }],
            RequirePkce = true,
            RequireClientSecret = true,
            RequireConsent = false
        });
        _clients.Add(new()
        {
            ClientId = "console",
            ClientName = "Console Client",
            ClientType = ClientType.Confidential,
            Enabled = true,
            AllowedGrantTypes = [GrantType.ClientCredentials],
            AllowedScopes = ["api1"],
            ClientSecrets = [new() { Value = SecretHasher.HashSecret("secret"), Description = "Console Client Secret" }],
            RequireClientSecret = true
        });
        _clients.Add(new()
        {
            ClientId = "spa",
            ClientName = "SPA Client",
            ClientType = ClientType.Public,
            Enabled = true,
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            RedirectUris = ["http://localhost:3000/callback"],
            AllowedScopes = ["openid", "profile", "api1"],
            RequirePkce = true,
            RequireClientSecret = false
        });
        _clients.Add(new()
        {
            ClientId = "device",
            ClientName = "Device Client",
            ClientType = ClientType.Public,
            Enabled = true,
            AllowedGrantTypes = [GrantType.DeviceCode],
            AllowedScopes = ["openid", "profile", "api1"],
            RequireClientSecret = false,
            DeviceCodeLifetime = 300
        });
    }

    public Task<Client?> FindClientByIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
        return Task.FromResult(client);
    }

    public Task<IEnumerable<Client>> FindEnabledClientsAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_clients.Where(c => c.Enabled).AsEnumerable());
    }
}

/// <summary>
/// 内存资源存储 (开发环境使用)
/// </summary>
public class InMemoryResourceStore : IResourceStore
{
    private readonly List<ApiResource> _apiResources = [];
    private readonly List<ApiScope> _apiScopes = [];
    private readonly List<IdentityResource> _identityResources = [];

    public InMemoryResourceStore()
    {
        // 添加 API 资源
        _apiResources.Add(new()
        {
            Name = "api1",
            DisplayName = "API 1",
            Description = "Main API",
            Enabled = true,
            Scopes = ["api1"],
            UserClaims = ["scope", "role"]
        });

        // 添加 API 作用域
        _apiScopes.Add(new()
        {
            Name = "api1",
            DisplayName = "API 1 Access",
            Enabled = true
        });

        // 添加 Identity 资源
        _identityResources.Add(new()
        {
            Name = "openid",
            DisplayName = "Your user identifier",
            Required = true,
            UserClaims = ["sub"]
        });
        _identityResources.Add(new()
        {
            Name = "profile",
            DisplayName = "User profile",
            Emphasize = true,
            UserClaims = ["name", "email", "picture"]
        });
        _identityResources.Add(new()
        {
            Name = "email",
            DisplayName = "Email",
            UserClaims = ["email"]
        });
    }

    public Task<IEnumerable<ApiResource>> FindEnabledApiResourcesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_apiResources.Where(r => r.Enabled).AsEnumerable());
    }

    public Task<IEnumerable<IdentityResource>> FindEnabledIdentityResourcesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_identityResources.Where(r => r.Enabled).AsEnumerable());
    }

    public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        return Task.FromResult(_apiResources.Where(r => r.Enabled && r.Scopes.Any(s => names.Contains(s))).AsEnumerable());
    }

    public Task<IEnumerable<ApiScope>> FindEnabledScopesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_apiScopes.Where(s => s.Enabled).AsEnumerable());
    }

    public Task<IEnumerable<ApiScope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default)
    {
        var names = scopeNames.ToHashSet();
        return Task.FromResult(_apiScopes.Where(s => s.Enabled && names.Contains(s.Name)).AsEnumerable());
    }

    public Task<Resources> GetAllResourcesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new Resources
        {
            ApiResources = _apiResources.Where(r => r.Enabled).ToList(),
            ApiScopes = _apiScopes.Where(s => s.Enabled).ToList(),
            IdentityResources = _identityResources.Where(r => r.Enabled).ToList()
        });
    }
}

/// <summary>
/// 内存持久化授权存储 (开发环境使用)
/// </summary>
public class InMemoryPersistedGrantStore : IPersistedGrantStore
{
    private readonly Dictionary<string, PersistedGrant> _grants = new();
    private readonly object _lock = new();

    public Task StoreAsync(PersistedGrant grant, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _grants[grant.Key] = grant;
        }
        return Task.CompletedTask;
    }

    public Task<PersistedGrant?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _grants.TryGetValue(key, out var grant);
            // 过滤掉已消费的授权码
            if (grant != null && grant.ConsumedTime.HasValue)
            {
                return Task.FromResult<PersistedGrant?>(null);
            }
            return Task.FromResult(grant);
        }
    }

    public Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var query = _grants.Values.AsEnumerable();
            if (!string.IsNullOrEmpty(filter.SubjectId))
            {
                query = query.Where(g => g.SubjectId == filter.SubjectId);
            }
            if (!string.IsNullOrEmpty(filter.ClientId))
            {
                query = query.Where(g => g.ClientId == filter.ClientId);
            }
            if (!string.IsNullOrEmpty(filter.Type))
            {
                query = query.Where(g => g.Type == filter.Type);
            }
            return Task.FromResult(query.AsEnumerable());
        }
    }

    public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _grants.Remove(key);
        }
        return Task.CompletedTask;
    }

    public Task RemoveAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var keys = _grants.Values
                              .Where(g => (string.IsNullOrEmpty(filter.SubjectId) || g.SubjectId == filter.SubjectId) &&
                                          (string.IsNullOrEmpty(filter.ClientId) || g.ClientId == filter.ClientId) &&
                                          (string.IsNullOrEmpty(filter.Type) || g.Type == filter.Type))
                              .Select(g => g.Key)
                              .ToList();
            foreach (var key in keys)
            {
                _grants.Remove(key);
            }
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// 内存设备流存储 (开发环境使用)
/// </summary>
public class InMemoryDeviceFlowStore : IDeviceFlowStore
{
    private readonly ConcurrentDictionary<string, DeviceCodeData> _deviceCodes = new();
    private readonly ConcurrentDictionary<string, string> _userCodeIndex = new(); // userCode -> deviceCode

    public Task StoreAsync(DeviceCodeData deviceCode, CancellationToken cancellationToken = default)
    {
        _deviceCodes[deviceCode.Code] = deviceCode;
        _userCodeIndex[deviceCode.UserCode] = deviceCode.Code;
        return Task.CompletedTask;
    }

    public Task<DeviceCodeData?> FindByDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        _deviceCodes.TryGetValue(deviceCode, out var data);
        return Task.FromResult(data);
    }

    public Task<DeviceCodeData?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default)
    {
        if (_userCodeIndex.TryGetValue(userCode, out var deviceCode))
        {
            _deviceCodes.TryGetValue(deviceCode, out var data);
            return Task.FromResult(data);
        }
        return Task.FromResult<DeviceCodeData?>(null);
    }

    public Task ConsumeDeviceCodeAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        if (_deviceCodes.TryGetValue(deviceCode, out var existing))
        {
            // Mark as consumed by setting SubjectId (will be set during authorization)
            var consumed = new DeviceCodeData
            {
                Code = existing.Code,
                UserCode = existing.UserCode,
                SubjectId = existing.SubjectId,
                ClientId = existing.ClientId,
                Description = existing.Description,
                CreationTime = existing.CreationTime,
                ExpirationTime = existing.ExpirationTime,
                Data = "consumed",
                Properties = existing.Properties
            };
            _deviceCodes[deviceCode] = consumed;
        }
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        if (_deviceCodes.TryRemove(deviceCode, out var data))
        {
            _userCodeIndex.TryRemove(data.UserCode, out _);
        }
        return Task.CompletedTask;
    }
}