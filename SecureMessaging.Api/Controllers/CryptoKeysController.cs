
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using SecureMessaging.Api.Services;
using SecureMessaging.Core.Services;

namespace SecureMessaging.Api.Controllers;

[ApiController]
[Route("api/crypto-keys")]
public class CryptoKeysController : ControllerBase
{
    private readonly IRsaService _rsaService;
    private readonly RsaKeyStore _keyStore;

    public CryptoKeysController(
        IRsaService rsaService,
        RsaKeyStore keyStore)
    {
        _rsaService = rsaService;
        _keyStore = keyStore;
    }

    [HttpPost("generate/rsa-keys")]
    public IActionResult GenerateRsaKeys()
    {
        try
        {
            // Generate and store a new RSA key pair
            var keys = _rsaService.GenerateCryptoKeys();
            int id = _keyStore.Add(keys);

            return Ok(id);
        }
        catch (CryptographicException)
        {
            return BadRequest("Failed to generate RSA keys.");
        }
    }

    [HttpGet("rsa-public-key/{id:int}")]
    public IActionResult GetPublicKey(int id)
    {
        // Find the key pair by its ID
        var keys = _keyStore.Get(id);

        if (keys is null)
        {
            return NotFound("RSA key pair not found.");
        }

        // Return only the public key
        return Ok(keys.PublicKey);
    }
}
