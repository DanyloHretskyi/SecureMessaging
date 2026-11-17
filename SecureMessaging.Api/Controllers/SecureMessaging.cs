
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using SecureMessaging.Api.Services;
using SecureMessaging.Core.Models;
using SecureMessaging.Core.Services;

namespace SecureMessaging.Api.Controllers;

[ApiController]
[Route("api/messages")]
public class MessagesController : ControllerBase
{
    private readonly IAesService _aesService;
    private readonly AesSessionStore _sessionStore;

    public MessagesController(IAesService aesService, AesSessionStore sessionStore)
    {
        _aesService = aesService;
        _sessionStore = sessionStore;
    }

    [HttpPost("send")]
    public IActionResult SendMessage(
        [FromHeader(Name = "x-session-id")] string? sessionId,
        [FromBody] EncryptedMessageRequest request)
    {
        // Validate the session ID
        if (string.IsNullOrWhiteSpace(sessionId))
            return BadRequest("Session ID is required.");

        // Find the AES key associated with the session
        var aesKey = _sessionStore.Get(sessionId);

        if (aesKey is null)
            return NotFound("Session not found.");

        if (string.IsNullOrWhiteSpace(request.CipherText))
            return BadRequest("Encrypted message is required.");

        try
        {
            // Decrypt the incoming message using AES
            string plainText = _aesService.Decrypt(
                aesKey, request.CipherText);

            // Add the server's current UTC time to the message
            string responseText =
                $"{plainText} | Received at: {DateTimeOffset.UtcNow:O}";

            // Encrypt the response using the same AES key
            string encryptedResponse = _aesService.Encrypt(
                aesKey, responseText);

            // Return the encrypted response to the client
            return Ok(new EncryptedMessageResponse
            {
                CipherText = encryptedResponse
            });
        }
        catch (CryptographicException)
        {
            return BadRequest("Invalid encrypted message.");
        }
        catch (FormatException)
        {
            return BadRequest("Invalid encrypted message.");
        }
    }
}
