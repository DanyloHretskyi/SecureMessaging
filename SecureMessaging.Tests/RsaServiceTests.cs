
using SecureMessaging.Core.Services;

namespace SecureMessaging.Tests.Services;

public class RsaServiceTests
{
    // Create an instance of RsaService to test everything in the RsaServiceTests
    private readonly IRsaService _rsaService = new RsaService();

    [Fact]
    public void GenerateCryptoKeys_ShouldGenerateKeys()
    {
        // Arrange & Act
        var keys = _rsaService.GenerateCryptoKeys();

        // Assert
        Assert.False(string.IsNullOrEmpty(keys.PublicKey));
        Assert.False(string.IsNullOrEmpty(keys.PrivateKey));
    }

    [Fact]
    public void Encrypt_ShouldReturnEncryptedText()
    {
        // Arrange
        var keys = _rsaService.GenerateCryptoKeys();
        string plainText = "Hello, World!";

        // Act
        string cipherText = _rsaService.Encrypt(
            keys.PublicKey, plainText);

        // Assert
        Assert.NotEqual(plainText, cipherText);
        Assert.NotEmpty(cipherText);
    }

    [Fact]
    public void Decrypt_ShouldRestoreOriginalText()
    {
        // Arrange
        var keys = _rsaService.GenerateCryptoKeys();
        string plainText = "Hello, World!";

        string cipherText = _rsaService.Encrypt(
            keys.PublicKey, plainText);

        // Act
        string decryptedText = _rsaService.Decrypt(
            keys.PrivateKey, cipherText);

        // Assert
        Assert.Equal(plainText, decryptedText);
    }
}
