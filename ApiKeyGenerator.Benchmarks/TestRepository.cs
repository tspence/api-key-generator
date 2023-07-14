using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator.Benchmarks;

public class TestRepository : IApiKeyRepository
{
    private readonly Dictionary<Guid, IPersistedApiKey> _dictionary = new();
    
    public ApiKeyAlgorithm? Algorithm { get; set; }

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
        if (Algorithm == null)
        {
            return null;
        }

        return new[] { Algorithm };
    }

    public ApiKeyAlgorithm? GetNewKeyAlgorithm()
    {
        return Algorithm;
    }
}