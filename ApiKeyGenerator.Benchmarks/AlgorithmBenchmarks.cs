using BenchmarkDotNet.Attributes;

namespace ApiKeyGenerator.Benchmarks;

public class AlgorithmBenchmarks
{
    private static TestRepository MakeTestRepository(HashAlgorithmType hash)
    {
        return new TestRepository()
        {
            Algorithm = new ApiKeyAlgorithm()
            {
                Hash = hash,
                SaltLength = 64,
                ClientSecretLength = 64,
                Prefix = "key",
                Suffix = "yek",
            }
        };
    }

    private readonly int iterations = 100000;
    
    [Params(HashAlgorithmType.SHA256, HashAlgorithmType.SHA512, HashAlgorithmType.BCrypt, HashAlgorithmType.PBKDF2100K)]
    public HashAlgorithmType HashType { get; set; }

    [Benchmark]
    public async Task Generate()
    {
        var repository = MakeTestRepository(HashType);
        var validator = new ApiKeyValidator(repository);
        for (int i = 0; i < iterations; i++)
        {
            var persistedKey = new PersistedKey() { KeyName = $"Test Key {i}" };
            var keyString = await validator.GenerateApiKey(persistedKey);
            if (string.IsNullOrWhiteSpace(keyString))
            {
                throw new Exception("Failed to generate key");
            }
        }
    }

    [Benchmark]
    public async Task Validate()
    {
        var sha256Repo = MakeTestRepository(HashType);
        var validator = new ApiKeyValidator(sha256Repo);
        var persistedKey = new PersistedKey() { KeyName = $"Test Key" };
        var keyString = await validator.GenerateApiKey(persistedKey);
        for (int i = 0; i < iterations; i++)
        {
            var result = await validator.TryValidate(keyString);
            if (!result.Success)
            {
                throw new Exception("Failed to validate key");
            }
        }
    }
}