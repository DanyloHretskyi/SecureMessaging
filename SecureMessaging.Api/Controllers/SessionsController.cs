
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SecureMessaging.Api.Services;
using SecureMessaging.Core.Models;
using SecureMessaging.Core.Services;

namespace SecureMessaging.Api.Controllers;

[ApiController]
[Route("api/sessions")]
public class SessionsController : ControllerBase
{
    private readonly IRsaService _rsaService;
    private readonly RsaKeyStore _rsaKeyStore;
    private readonly AesSessionStore _sessionStore;

    public SessionsController(IRsaService rsaService, RsaKeyStore rsaKeyStore, AesSessionStore sessionStore)
    {
        _rsaService = rsaService;
        _rsaKeyStore = rsaKeyStore;
        _sessionStore = sessionStore;
    }

    [HttpPost("establish")]
    public IActionResult EstablishSession(
        [FromHeader(Name = "x-rsa-id")] int rsaId,
        [FromHeader(Name = "x-session-id")] string sessionId,
        [FromBody] CreateSessionRequest request)
    {
        // Find the RSA key pair used by the client
        var rsaKeys = _rsaKeyStore.Get(rsaId);

        if (rsaKeys is null)
            return NotFound("RSA key pair not found.");

        // Validate the session ID
        if (!Guid.TryParse(sessionId, out _))
            return BadRequest("Invalid session ID.");

        try
        {
            // Decrypt the session data using the RSA private key
            string decryptedData = _rsaService.Decrypt(
                rsaKeys.PrivateKey,
                request.EncryptedSessionData);

            // Deserialize the AES key and IV
            AesKey? aesKey = JsonSerializer.Deserialize<AesKey>(
                decryptedData);

            if (aesKey is null)
                return BadRequest("Invalid AES session data.");

            // Validate the AES-256 key and IV sizes
            byte[] keyBytes = Convert.FromBase64String(aesKey.Key);
            byte[] ivBytes = Convert.FromBase64String(aesKey.IV);

            if (keyBytes.Length != 32 || ivBytes.Length != 16)
                return BadRequest("Invalid AES key or IV size.");

            // Store the session in memory
            if (!_sessionStore.Add(sessionId, aesKey))
                return Conflict("Session already exists.");

            return Ok("Session established successfully.");
        }
        catch (CryptographicException)
        {
            return BadRequest("Failed to decrypt session data.");
        }
        catch (FormatException)
        {
            return BadRequest("Invalid Base64 data.");
        }
        catch (JsonException)
        {
            return BadRequest("Invalid session data format.");
        }
    }
}
