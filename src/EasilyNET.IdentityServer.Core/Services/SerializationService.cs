using System.Text.Json;
using System.Text.Json.Serialization;
using EasilyNET.IdentityServer.Abstractions.Services;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 序列化服务实现
/// </summary>
public class SerializationService : ISerializationService
{
    private static readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <inheritdoc />
    public string Serialize<T>(T obj) => JsonSerializer.Serialize(obj, _options);

    /// <inheritdoc />
    public T? Deserialize<T>(string data) => JsonSerializer.Deserialize<T>(data, _options);
}