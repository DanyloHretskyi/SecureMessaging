
using System.Collections.Concurrent;
using SecureMessaging.Core.Models;

namespace SecureMessaging.Api.Services;

public class RsaKeyStore
{
    // Store RSA key pairs in memory using integer IDs
    private readonly ConcurrentDictionary<int, RsaKeys> _keys = new();

    private int _nextId = 0;

    public int Add(RsaKeys keys)
    {
        // Generate a unique ID for the key pair
        int id = Interlocked.Increment(ref _nextId);

        _keys[id] = keys;

        return id;
    }

    public RsaKeys? Get(int id)
    {
        // Return the key pair if it exists
        return _keys.TryGetValue(id, out var keys) ? keys : null;
    }
}
