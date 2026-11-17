
using System.Security.Cryptography;
using System.Text;
using SecureMessaging.Core.Models;

namespace SecureMessaging.Core.Services;

public class AesService : IAesService
{
    public AesKey GenerateSecretKey()
    {
        // Create an AES instance
        using var aes = Aes.Create();
        aes.KeySize = 256;

        // Generate a random secret key and IV
        aes.GenerateKey();
        aes.GenerateIV();

        return new AesKey
        {
            Key = Convert.ToBase64String(aes.Key),
            IV = Convert.ToBase64String(aes.IV)
        };
    }



    public string Encrypt(AesKey aesKey, string plainText)
    {
        // Create and configure an AES instance
        using var aes = Aes.Create();

        byte[] keyBytes = Convert.FromBase64String(aesKey.Key);

        aes.Key = keyBytes;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // Generate a new random IV
        aes.GenerateIV();

        // Convert the plain text into UTF-8 bytes
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

        // Encrypt the message
        using var encryptor = aes.CreateEncryptor();

        byte[] encryptedBytes = encryptor.TransformFinalBlock(
            plainTextBytes, 0, plainTextBytes.Length);

        // Combine the IV and encrypted data
        byte[] result = new byte[aes.IV.Length + encryptedBytes.Length];

        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);

        Buffer.BlockCopy(
            encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

        // Derive a separate key for HMAC
        byte[] macKey = HMACSHA256.HashData(
            keyBytes,
            Encoding.UTF8.GetBytes("SecureMessaging-HMAC-v1"));

        // Calculate HMAC for the IV and encrypted data
        byte[] hmac = HMACSHA256.HashData(macKey, result);

        // Append HMAC to the encrypted data
        byte[] finalResult = new byte[result.Length + hmac.Length];

        Buffer.BlockCopy(result, 0, finalResult, 0, result.Length);
        Buffer.BlockCopy(hmac, 0, finalResult, result.Length, hmac.Length);

        // Encode everything as a Base64 string
        return Convert.ToBase64String(finalResult);
    }

    public string Decrypt(AesKey aesKey, string cipherText)
    {
        // Create and configure an AES instance
        using var aes = Aes.Create();

        byte[] keyBytes = Convert.FromBase64String(aesKey.Key);

        aes.Key = keyBytes;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        // Decode the Base64 string
        byte[] encryptedData = Convert.FromBase64String(cipherText);

        int ivLength = aes.BlockSize / 8;
        const int hmacLength = 32;

        // Validate the encrypted data length
        if (encryptedData.Length < ivLength + 16 + hmacLength ||
            (encryptedData.Length - ivLength - hmacLength) % 16 != 0)
        {
            throw new CryptographicException("Invalid encrypted data.");
        }

        // Separate the encrypted content and HMAC
        // ..^32 - take all but the last 32 bytes for HMAC, and the rest is the data
        byte[] data = encryptedData[..^hmacLength];
        // ^32.. - take the last 32 bytes for HMAC
        byte[] receivedHmac = encryptedData[^hmacLength..];

        // Derive the same HMAC key
        byte[] macKey = HMACSHA256.HashData(
            keyBytes,
            Encoding.UTF8.GetBytes("SecureMessaging-HMAC-v1"));

        // Calculate the expected HMAC
        byte[] expectedHmac = HMACSHA256.HashData(macKey, data);

        // Verify HMAC before decrypting
        if (!CryptographicOperations.FixedTimeEquals(
            receivedHmac, expectedHmac))
        {
            throw new CryptographicException("HMAC verification failed.");
        }

        // Extract the IV and encrypted message
        byte[] iv = data[..ivLength];
        byte[] cipherBytes = data[ivLength..];

        aes.IV = iv;

        // Decrypt the verified message
        using var decryptor = aes.CreateDecryptor();

        byte[] decryptedBytes = decryptor.TransformFinalBlock(
            cipherBytes, 0, cipherBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }

}
