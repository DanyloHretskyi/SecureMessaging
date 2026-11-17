
using SecureMessaging.Core.Services;

namespace SecureMessaging.Tests.Services;

public class AesServiceTests
{
    private readonly IAesService _aesService = new AesService();

    [Fact]
    public void GenerateSecretKey_ShouldGenerateValidKeyAndIV()
    {
        // Act
        var aesKey = _aesService.GenerateSecretKey();

        // Assert
        Assert.Equal(32, Convert.FromBase64String(aesKey.Key).Length);
        Assert.Equal(16, Convert.FromBase64String(aesKey.IV).Length);
    }

    [Fact]
    public void Encrypt_ShouldReturnEncryptedText()
    {
        // Arrange
        var aesKey = _aesService.GenerateSecretKey();
        string plainText = "Hello, World!";

        // Act
        string cipherText = _aesService.Encrypt(aesKey, plainText);

        // Assert
        Assert.NotEmpty(cipherText);
        Assert.NotEqual(plainText, cipherText);
    }

    [Fact]
    public void Decrypt_ShouldRestoreOriginalText()
    {
        // Arrange
        var aesKey = _aesService.GenerateSecretKey();
        string plainText = "Hello, World!";

        // Act
        string cipherText = _aesService.Encrypt(aesKey, plainText);
        string decryptedText = _aesService.Decrypt(aesKey, cipherText);

        // Assert
        Assert.Equal(plainText, decryptedText);
    }

    [Fact]
    public void Encrypt_ShouldUseDifferentIVForEachMessage()
    {
        // Arrange
        var aesKey = _aesService.GenerateSecretKey();
        string plainText = "Hello, World!";

        // Act
        string first = _aesService.Encrypt(aesKey, plainText);
        string second = _aesService.Encrypt(aesKey, plainText);

        // Assert
        Assert.NotEqual(first, second);
        Assert.Equal(plainText, _aesService.Decrypt(aesKey, first));
        Assert.Equal(plainText, _aesService.Decrypt(aesKey, second));
    }

    [Fact]
    public void Decrypt_ShouldRejectTamperedMessage()
    {
        // Arrange
        var aesKey = _aesService.GenerateSecretKey();
        string cipherText = _aesService.Encrypt(aesKey, "Hello!");

        byte[] encryptedBytes = Convert.FromBase64String(cipherText);

        // Modify one byte of the encrypted message
        encryptedBytes[20] ^= 0x01;

        string tamperedText = Convert.ToBase64String(encryptedBytes);

        // Act & Assert
        Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => _aesService.Decrypt(aesKey, tamperedText));
    }

}
