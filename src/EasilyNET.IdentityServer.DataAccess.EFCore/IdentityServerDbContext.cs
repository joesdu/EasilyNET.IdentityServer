using EasilyNET.IdentityServer.DataAccess.Abstractions;
using EasilyNET.IdentityServer.DataAccess.EFCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasilyNET.IdentityServer.DataAccess.EFCore;

/// <summary>
/// IdentityServer EF Core 数据库上下文
/// </summary>
public class IdentityServerDbContext(DbContextOptions<IdentityServerDbContext> options) : DbContext(options), IIdentityServerDbContext
{
    public DbSet<SigningKeyEntity> SigningKeys => Set<SigningKeyEntity>();
    public DbSet<ApiResourceClaimEntity> ApiResourceClaims => Set<ApiResourceClaimEntity>();

    public DbSet<ApiResourcePropertyEntity> ApiResourceProperties => Set<ApiResourcePropertyEntity>();

    public DbSet<ApiResourceEntity> ApiResources => Set<ApiResourceEntity>();

    public DbSet<ApiResourceScopeEntity> ApiResourceScopes => Set<ApiResourceScopeEntity>();

    public DbSet<ApiResourceSecretEntity> ApiResourceSecrets => Set<ApiResourceSecretEntity>();

    public DbSet<ApiScopeClaimEntity> ApiScopeClaims => Set<ApiScopeClaimEntity>();

    public DbSet<ApiScopePropertyEntity> ApiScopeProperties => Set<ApiScopePropertyEntity>();

    public DbSet<ApiScopeEntity> ApiScopes => Set<ApiScopeEntity>();

    public DbSet<ClientClaimEntity> ClientClaims => Set<ClientClaimEntity>();

    public DbSet<ClientAuthorizationPromptTypeEntity> ClientAuthorizationPromptTypes => Set<ClientAuthorizationPromptTypeEntity>();

    public DbSet<ClientCorsOriginEntity> ClientCorsOrigins => Set<ClientCorsOriginEntity>();

    public DbSet<ClientGrantTypeEntity> ClientGrantTypes => Set<ClientGrantTypeEntity>();

    public DbSet<ClientIdentityProviderRestrictionEntity> ClientIdentityProviderRestrictions => Set<ClientIdentityProviderRestrictionEntity>();

    public DbSet<ClientPropertyEntity> ClientProperties => Set<ClientPropertyEntity>();

    public DbSet<ClientRedirectUriEntity> ClientRedirectUris => Set<ClientRedirectUriEntity>();

    public DbSet<ClientEntity> Clients => Set<ClientEntity>();

    public DbSet<ClientScopeEntity> ClientScopes => Set<ClientScopeEntity>();

    public DbSet<ClientSecretEntity> ClientSecrets => Set<ClientSecretEntity>();

    public DbSet<DeviceCodeEntity> DeviceCodes => Set<DeviceCodeEntity>();

    public DbSet<IdentityResourceClaimEntity> IdentityResourceClaims => Set<IdentityResourceClaimEntity>();

    public DbSet<IdentityResourcePropertyEntity> IdentityResourceProperties => Set<IdentityResourcePropertyEntity>();

    public DbSet<IdentityResourceEntity> IdentityResources => Set<IdentityResourceEntity>();

    public DbSet<PersistedGrantEntity> PersistedGrants => Set<PersistedGrantEntity>();

    public DbSet<UserConsentEntity> UserConsents => Set<UserConsentEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Client
        modelBuilder.Entity<ClientEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.ClientId).IsUnique();
            b.HasMany(x => x.AllowedGrantTypes).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.RedirectUris).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.AllowedScopes).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.ClientSecrets).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.AuthorizationPromptTypes).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.Claims).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.AllowedCorsOrigins).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.IdentityProviderRestrictions).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.Properties).WithOne(x => x.Client).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
        });

        // ApiResource
        modelBuilder.Entity<ApiResourceEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.Name).IsUnique();
            b.HasMany(x => x.Scopes).WithOne(x => x.ApiResource).HasForeignKey(x => x.ApiResourceId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.UserClaims).WithOne(x => x.ApiResource).HasForeignKey(x => x.ApiResourceId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.ApiSecrets).WithOne(x => x.ApiResource).HasForeignKey(x => x.ApiResourceId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.Properties).WithOne(x => x.ApiResource).HasForeignKey(x => x.ApiResourceId).OnDelete(DeleteBehavior.Cascade);
        });

        // ApiScope
        modelBuilder.Entity<ApiScopeEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.Name).IsUnique();
            b.HasMany(x => x.UserClaims).WithOne(x => x.ApiScope).HasForeignKey(x => x.ApiScopeId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.Properties).WithOne(x => x.ApiScope).HasForeignKey(x => x.ApiScopeId).OnDelete(DeleteBehavior.Cascade);
        });

        // IdentityResource
        modelBuilder.Entity<IdentityResourceEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.Name).IsUnique();
            b.HasMany(x => x.UserClaims).WithOne(x => x.IdentityResource).HasForeignKey(x => x.IdentityResourceId).OnDelete(DeleteBehavior.Cascade);
            b.HasMany(x => x.Properties).WithOne(x => x.IdentityResource).HasForeignKey(x => x.IdentityResourceId).OnDelete(DeleteBehavior.Cascade);
        });

        // PersistedGrant
        modelBuilder.Entity<PersistedGrantEntity>(b =>
        {
            b.HasKey(x => x.Key);
            b.Property(x => x.Key).HasMaxLength(200);
            b.Property(x => x.RowVersion).IsRowVersion();
            b.HasIndex(x => new { x.SubjectId, x.ClientId, x.Type });
            b.HasIndex(x => x.ExpirationTime);
        });

        // DeviceCode
        modelBuilder.Entity<DeviceCodeEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.DeviceCode).IsUnique();
            b.HasIndex(x => x.UserCode).IsUnique();
            b.HasIndex(x => x.ExpirationTime);
        });

        // UserConsent
        modelBuilder.Entity<UserConsentEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => new { x.SubjectId, x.ClientId }).IsUnique();
        });

        // SigningKey
        modelBuilder.Entity<SigningKeyEntity>(b =>
        {
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.KeyId).IsUnique();
            b.HasIndex(x => x.DisabledAt);
            b.Property(x => x.PrivateKey).HasMaxLength(4000);
        });
    }
}