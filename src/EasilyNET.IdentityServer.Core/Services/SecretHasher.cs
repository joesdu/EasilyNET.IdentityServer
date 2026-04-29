using System.Security.Cryptography;
using System.Text;

namespace EasilyNET.IdentityServer.Core.Services;

/// <summary>
/// 密钥哈希工具类
/// </summary>
public static class SecretHasher
{
    /// <summary>
    /// 哈希密钥（使用 SHA-256）
    /// </summary>
    public static string HashSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret))
            return string.Empty;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// 验证密钥是否匹配
    /// </summary>
    public static bool VerifySecret(string secret, string hashedSecret)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(hashedSecret))
            return false;

        var computedHash = HashSecret(secret);
        return FixedTimeEquals(computedHash, hashedSecret);
    }

    /// <summary>
    /// 常量时间字符串比较
    /// </summary>
    private static bool FixedTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
        {
            // 保持常量时间
            var dummyA = new byte[Math.Max(a.Length, b.Length)];
            var dummyB = new byte[Math.Max(a.Length, b.Length)];
            CryptographicOperations.FixedTimeEquals(dummyA, dummyB);
            return false;
        }
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }
}
