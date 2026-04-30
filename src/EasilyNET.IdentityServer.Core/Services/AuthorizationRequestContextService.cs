using System.Text.Json;
using EasilyNET.IdentityServer.Abstractions.Models;
using EasilyNET.IdentityServer.Abstractions.Services;
using EasilyNET.IdentityServer.Abstractions.Stores;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 授权请求上下文持久化服务
/// </summary>
public class AuthorizationRequestContextService(IPersistedGrantStore grantStore) : IAuthorizationRequestContextService
{
    private const string AuthorizationRequestContextType = "authorization_request";

    public async Task StoreAsync(AuthorizationRequestContext context, CancellationToken cancellationToken = default)
    {
        await grantStore.StoreAsync(new PersistedGrant
        {
            Key = context.RequestId,
            Type = AuthorizationRequestContextType,
            ClientId = context.ClientId,
            CreationTime = context.CreationTime,
            ExpirationTime = context.ExpirationTime,
            Data = JsonSerializer.Serialize(context)
        }, cancellationToken);
    }

    public async Task<AuthorizationRequestContext?> GetAsync(string requestId, CancellationToken cancellationToken = default)
    {
        var grant = await grantStore.GetAsync(requestId, cancellationToken);
        if (grant == null || grant.Type != AuthorizationRequestContextType)
        {
            return null;
        }

        if (grant.ExpirationTime.HasValue && grant.ExpirationTime.Value <= DateTime.UtcNow)
        {
            await grantStore.RemoveAsync(requestId, cancellationToken);
            return null;
        }

        return JsonSerializer.Deserialize<AuthorizationRequestContext>(grant.Data);
    }

    public Task RemoveAsync(string requestId, CancellationToken cancellationToken = default) =>
        grantStore.RemoveAsync(requestId, cancellationToken);
}