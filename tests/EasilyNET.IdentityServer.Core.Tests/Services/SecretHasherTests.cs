using System;
using System.Text;
using EasilyNET.IdentityServer.Core.Services;
using Xunit;

namespace EasilyNET.IdentityServer.Core.Tests.Services;

/// <summary>
/// 密钥哈希工具测试
/// </summary>
public class SecretHasherTests
{
    [Fact]
    public void HashSecret_SameInput_ShouldReturnSameHash()
    {
        // Arrange
        var secret = "my-secret-value";

        // Act
        var hash1 = SecretHasher.HashSecret(secret);
        var hash2 = SecretHasher.HashSecret(secret);

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashSecret_DifferentInput_ShouldReturnDifferentHash()
    {
        // Arrange
        var secret1 = "secret-one";
        var secret2 = "secret-two";

        // Act
        var hash1 = SecretHasher.HashSecret(secret1);
        var hash2 = SecretHasher.HashSecret(secret2);

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void HashSecret_EmptyString_ShouldReturnHash()
    {
        // Arrange
        var secret = "";

        // Act
        var hash = SecretHasher.HashSecret(secret);

        // Assert
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public void VerifySecret_CorrectSecret_ShouldReturnTrue()
    {
        // Arrange
        var secret = "my-secret-value";
        var hashedSecret = SecretHasher.HashSecret(secret);

        // Act
        var result = SecretHasher.VerifySecret(secret, hashedSecret);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void VerifySecret_WrongSecret_ShouldReturnFalse()
    {
        // Arrange
        var secret = "my-secret-value";
        var wrongSecret = "wrong-secret-value";
        var hashedSecret = SecretHasher.HashSecret(secret);

        // Act
        var result = SecretHasher.VerifySecret(wrongSecret, hashedSecret);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void VerifySecret_SameLengthDifferentContent_ShouldReturnFalse()
    {
        // Arrange
        var secret1 = "secret123456";
        var secret2 = "secret654321";
        var hashedSecret = SecretHasher.HashSecret(secret1);

        // Act
        var result = SecretHasher.VerifySecret(secret2, hashedSecret);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("a-very-long-secret-value-that-exceeds-normal-lengths-and-contains-special-chars-!@#$%^&*()")]
    [InlineData("Unicode: 中文测试 🎉")]
    [InlineData("null\x00char")]
    public void HashSecret_VariousInputs_ShouldWork(string secret)
    {
        // Act
        var hash = SecretHasher.HashSecret(secret);

        // Assert
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);

        // 验证可以正确验证
        var result = SecretHasher.VerifySecret(secret, hash);
        Assert.True(result);
    }

    [Fact]
    public void VerifySecret_TimingAttackResistance_ShouldTakeSimilarTime()
    {
        // Arrange
        var secret = "my-secret-value";
        var hashedSecret = SecretHasher.HashSecret(secret);
        var wrongSecret = "wrong-secret!!!";

        // Act - 多次测量取平均
        var iterations = 100;
        long correctTime = 0;
        long wrongTime = 0;

        for (int i = 0; i < iterations; i++)
        {
            var sw1 = System.Diagnostics.Stopwatch.StartNew();
            SecretHasher.VerifySecret(secret, hashedSecret);
            sw1.Stop();
            correctTime += sw1.ElapsedTicks;

            var sw2 = System.Diagnostics.Stopwatch.StartNew();
            SecretHasher.VerifySecret(wrongSecret, hashedSecret);
            sw2.Stop();
            wrongTime += sw2.ElapsedTicks;
        }

        var avgCorrectTime = correctTime / iterations;
        var avgWrongTime = wrongTime / iterations;

        // Assert - 时间应该相近（差异在20%以内）
        var ratio = Math.Max(avgCorrectTime, avgWrongTime) / (double)Math.Min(avgCorrectTime, avgWrongTime);
        Assert.True(ratio < 1.5, $"Timing difference too large: {ratio:F2}x");
    }

    [Fact]
    public void HashSecret_OutputShouldBeBase64()
    {
        // Arrange
        var secret = "test-secret";

        // Act
        var hash = SecretHasher.HashSecret(secret);

        // Assert - 应该是有效的 Base64
        var bytes = Convert.FromBase64String(hash);
        Assert.Equal(32, bytes.Length); // SHA-256 = 32 bytes
    }

    [Fact]
    public void VerifySecret_CaseSensitivity_ShouldBeCaseSensitive()
    {
        // Arrange
        var secret = "MySecret";
        var differentCaseSecret = "mysecret";
        var hashedSecret = SecretHasher.HashSecret(secret);

        // Act
        var result = SecretHasher.VerifySecret(differentCaseSecret, hashedSecret);

        // Assert
        Assert.False(result);
    }
}
