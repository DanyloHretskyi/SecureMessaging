using SecureMessaging.Core.Models;

namespace SecureMessaging.Core.Services;

public interface IRsaService
{
    RsaKeys GenerateCryptoKeys();

    string Encrypt(string publicKey, string plainText);

    string Decrypt(string privateKey, string cipherText);
}