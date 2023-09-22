using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator.Tests;

public class MultiRepository : IApiKeyRepository
{
    public List<ApiKeyAlgorithm> Algorithms { get; set; } = new();
    private Dictionary<Guid, IPersistedApiKey> _dictionary = new();

    public MultiRepository(params ApiKeyAlgorithm[] algorithms)
    {
        Algorithms.AddRange(algorithms);
    }
    
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

    public IEnumerable<ApiKeyAlgorithm> GetSupportedAlgorithms()
    {
        return Algorithms;
    }

    public ApiKeyAlgorithm GetNewKeyAlgorithm()
    {
        return Algorithms.First();
    }
}