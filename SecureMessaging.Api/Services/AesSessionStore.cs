
using System.Collections.Concurrent;
using SecureMessaging.Core.Models;

namespace SecureMessaging.Api.Services;

public class AesSessionStore
{
    // Store AES keys by their session IDs
    private readonly ConcurrentDictionary<string, AesKey> _sessions = new();

    public bool Add(string sessionId, AesKey aesKey)
    {
        // Add a new session if the ID does not already exist
        return _sessions.TryAdd(sessionId, aesKey);
    }

    public AesKey? Get(string sessionId)
    {
        // Find the AES key associated with the session
        return _sessions.TryGetValue(sessionId, out var aesKey)
            ? aesKey
            : null;
    }
}
