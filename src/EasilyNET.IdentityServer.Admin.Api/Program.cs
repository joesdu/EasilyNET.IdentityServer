using EasilyNET.IdentityServer.DataAccess.EFCore;
using EasilyNET.IdentityServer.DataAccess.EFCore.Sqlite.Extensions;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// 默认使用 SQLite
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=identityserver.db";
builder.Services.AddIdentityServerSqlite(connectionString);

// CORS (允许前端访问)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:8000", "http://localhost:8001")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
var app = builder.Build();

// 使用迁移演进数据库架构，避免 EnsureCreated 绕过 migrations。
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityServerDbContext>();
    await db.Database.MigrateAsync();
}
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
app.UseCors();
app.UseRouting();
app.UseAuthorization();
app.MapControllers();
app.Run();
