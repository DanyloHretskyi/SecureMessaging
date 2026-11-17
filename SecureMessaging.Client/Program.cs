
using System.Net.Http.Json;
using System.Text.Json;
using SecureMessaging.Core.Models;
using SecureMessaging.Core.Services;

// Create an HTTP client to communicate with the API
using var httpClient = new HttpClient
{
    BaseAddress = new Uri("https://localhost:7130/")
};

// Create cryptographic services
IRsaService rsaService = new RsaService();
IAesService aesService = new AesService();

// Request the server to generate an RSA key pair
using var rsaResponse = await httpClient.PostAsync(
    "api/crypto-keys/generate/rsa-keys", null);

rsaResponse.EnsureSuccessStatusCode();

// Read the RSA key pair ID
int rsaId = await rsaResponse.Content.ReadFromJsonAsync<int>();

// Get the RSA public key from the server
string publicKey = await httpClient.GetStringAsync(
    $"api/crypto-keys/rsa-public-key/{rsaId}");

// Generate an AES key and IV
AesKey aesKey = aesService.GenerateSecretKey();

// Generate a unique session ID
string sessionId = Guid.NewGuid().ToString();

// Serialize the AES key and IV into JSON
string sessionData = JsonSerializer.Serialize(aesKey);

// Encrypt the session data using the RSA public key
string encryptedSessionData = rsaService.Encrypt(
    publicKey, sessionData);

// Create a request to establish the session
using var request = new HttpRequestMessage(
    HttpMethod.Post, "api/sessions/establish");

// Add RSA and session IDs to the request headers
request.Headers.Add("x-rsa-id", rsaId.ToString());
request.Headers.Add("x-session-id", sessionId);

// Add the encrypted session data to the request body
request.Content = JsonContent.Create(new CreateSessionRequest
{
    EncryptedSessionData = encryptedSessionData
});

// Send the request to the server
using var response = await httpClient.SendAsync(request);

response.EnsureSuccessStatusCode();

Console.WriteLine("Session established successfully!");
Console.WriteLine($"RSA Key ID: {rsaId}");
Console.WriteLine($"Session ID: {sessionId}");



while (true)
{
    Console.Write("\nEnter message (or 'exit'): ");
    string? message = Console.ReadLine();

    if (message == "exit")
        break;

    if (string.IsNullOrWhiteSpace(message))
        continue;

    Console.WriteLine("\n========== CLIENT ==========");
    Console.WriteLine($"Original message: {message}");

    // Encrypt the user's message using AES
    string encryptedMessage = aesService.Encrypt(aesKey, message);

    Console.WriteLine($"Encrypted request: {encryptedMessage}");

    // Create an HTTP request with the session ID
    using var messageRequest = new HttpRequestMessage(
        HttpMethod.Post, "api/messages/send");

    messageRequest.Headers.Add("x-session-id", sessionId);

    // Add the encrypted message to the request body
    messageRequest.Content = JsonContent.Create(
        new EncryptedMessageRequest
        {
            CipherText = encryptedMessage
        });

    // Send the encrypted message to the server
    using var messageResponse = await httpClient.SendAsync(
        messageRequest);

    messageResponse.EnsureSuccessStatusCode();

    // Read the encrypted response
    var result = await messageResponse.Content
        .ReadFromJsonAsync<EncryptedMessageResponse>();

    if (result is null)
    {
        Console.WriteLine("Invalid server response.");
        continue;
    }

    Console.WriteLine("\n========== SERVER RESPONSE ==========");
    Console.WriteLine($"Encrypted response: {result.CipherText}");

    // Decrypt the server's response using AES
    string decryptedResponse = aesService.Decrypt(
        aesKey, result.CipherText);

    Console.WriteLine($"Decrypted response: {decryptedResponse}");
    Console.WriteLine($"Session ID: {sessionId}");
    Console.WriteLine("=====================================");
}


