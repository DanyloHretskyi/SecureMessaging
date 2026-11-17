
using System.Security.Cryptography;
using System.Text;
using SecureMessaging.Core.Models;

namespace SecureMessaging.Core.Services;

public class RsaService : IRsaService
{
    public RsaKeys GenerateCryptoKeys()
    {
        // Create RSA instance rsa that will perform cryptographic operations
        using var rsa = RSA.Create();
        rsa.KeySize = 2048;

        return new RsaKeys
        {
            // Export keys and encode them as a Base64 string
            PublicKey = Convert.ToBase64String(
                rsa.ExportSubjectPublicKeyInfo()),

            PrivateKey = Convert.ToBase64String(
                rsa.ExportPkcs8PrivateKey())
        };
    }

    public string Encrypt(string publicKey, string plainText)
    {
        using var rsa = RSA.Create();

        // Decode the public key from Base64 into bytes
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);

        // Import the public key into the RSA instance
        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        // Convert the plain text into UTF-8 bytes
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

        // Encrypt the data using RSA with OAEP-SHA256 padding
        byte[] encryptedBytes = rsa.Encrypt(
            plainTextBytes,
            RSAEncryptionPadding.OaepSHA256);

        // Encode encrypted bytes as a Base64 string
        return Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string privateKey, string cipherText)
    {
        using var rsa = RSA.Create();

        // Decode the private key from Base64 into bytes
        byte[] privateKeyBytes = Convert.FromBase64String(privateKey);

        // Import the private key into the RSA instance
        rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

        // Decode the encrypted text from Base64 into bytes
        byte[] encryptedBytes = Convert.FromBase64String(cipherText);

        // Decrypt the data using RSA with OAEP-SHA256 padding
        byte[] decryptedBytes = rsa.Decrypt(
            encryptedBytes,
            RSAEncryptionPadding.OaepSHA256);

        // Convert decrypted bytes back into a UTF-8 string
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}