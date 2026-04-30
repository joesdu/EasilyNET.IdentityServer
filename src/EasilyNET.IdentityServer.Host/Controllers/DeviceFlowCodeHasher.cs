using System.Security.Cryptography;
using System.Text;

namespace EasilyNET.IdentityServer.Host.Controllers;

internal static class DeviceFlowCodeHasher
{
    public static string HashDeviceCode(string deviceCode) => Hash(deviceCode.Trim());

    public static string HashUserCode(string userCode) => Hash(NormalizeUserCode(userCode));

    private static string NormalizeUserCode(string userCode) => userCode
        .Trim()
        .Replace("-", string.Empty, StringComparison.Ordinal)
        .ToUpperInvariant();

    private static string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }
}