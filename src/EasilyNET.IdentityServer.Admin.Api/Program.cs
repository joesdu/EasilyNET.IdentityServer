using EasilyNET.IdentityServer.DataAccess.EFCore;
using EasilyNET.IdentityServer.DataAccess.EFCore.Sqlite.Extensions;

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

// 自动创建数据库
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityServerDbContext>();
    await db.Database.EnsureCreatedAsync();
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