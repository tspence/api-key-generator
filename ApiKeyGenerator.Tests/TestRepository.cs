using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator.Tests;

public class TestRepository : IApiKeyRepository
{
    private Dictionary<Guid, IPersistedApiKey> _dictionary = new();

    public async Task<IPersistedApiKey?> GetKey(Guid id)
    {
        await Task.CompletedTask;
        if (_dictionary.TryGetValue(id, out var key))
        {
            return key;
        }

        return null;
    }

    public async Task<bool> SaveKey(IPersistedApiKey key)
    {
        await Task.CompletedTask;
        _dictionary[key.ApiKeyId] = key;
        return true;
    }

    public IEnumerable<ApiKeyAlgorithm>? GetSupportedAlgorithms()
    {
        return null;
    }

    public ApiKeyAlgorithm? GetNewKeyAlgorithm()
    {
        return null;
    }
}