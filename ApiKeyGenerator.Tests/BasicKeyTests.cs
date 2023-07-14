using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SimpleBase;

namespace ApiKeyGenerator.Tests;

[TestClass]
public class BasicKeyTests
{
    [DataTestMethod]
    [DataRow(null)]
    [DataRow(HashAlgorithmType.SHA256)]
    [DataRow(HashAlgorithmType.SHA512)]
    [DataRow(HashAlgorithmType.BCrypt)]
    [DataRow(HashAlgorithmType.PBKDF2100K)]
    public async Task TestAlgorithm(HashAlgorithmType? hashType)
    {
        var repository = new TestRepository();
        if (hashType != null)
        {
            repository.Algorithm = new ApiKeyAlgorithm()
            {
                Hash = hashType.Value,
                SaltLength = 64,
                ClientSecretLength = 64,
                Prefix = "key",
                Suffix = "yek",
            };
        }
        var validator = new ApiKeyValidator(repository);
        var algorithm = repository.Algorithm ?? ApiKeyAlgorithm.DefaultAlgorithm;
        
        // Generate a key
        var persistedKey = new PersistedApiKey
        {
            KeyName = "TestKeyGeneration"
        };
        Assert.AreEqual(Guid.Empty, persistedKey.ApiKeyId);
        var apiKeyString = await validator.GenerateApiKey(persistedKey);
        Assert.AreNotEqual(string.Empty, apiKeyString);
        Assert.AreNotEqual(Guid.Empty, persistedKey.ApiKeyId);
        
        // Generate a second key - they should not match
        var key2 = new PersistedApiKey() { KeyName = "SecondKey" };
        var apiKey2 = await validator.GenerateApiKey(key2);
        Assert.AreNotEqual(apiKeyString, apiKey2);

        // Trivial test
        var result0 = await validator.TryValidate(null);
        Assert.IsNotNull(result0);
        Assert.IsFalse(result0.Success);
        Assert.AreEqual("Key is null or empty.", result0.Message);
        
        // Alternative interfaces test
        var matchingKey = validator.ParseKey(apiKeyString, repository.Algorithm);
        Assert.IsNotNull(matchingKey);
        var ex = Assert.ThrowsException<Exception>(() => validator.ParseKey("", null));
        Assert.AreEqual("Key is null or empty.", ex.Message);

        // Break the prefix and attempt to validate
        var result1 = await validator.TryValidate("extra" + apiKeyString);
        Assert.IsNotNull(result1);
        Assert.IsFalse(result1.Success);
        Assert.AreEqual("Key prefix does not match any supported key algorithms.", result1.Message);

        // Break the suffix and attempt to validate
        var result2 = await validator.TryValidate(apiKeyString + "extra");
        Assert.IsNotNull(result2);
        Assert.IsFalse(result2.Success);
        Assert.AreEqual("This key was truncated and is missing some data.", result2.Message);

        // Try random garbage
        var result3 = await validator.TryValidate(algorithm.Prefix + "abc" + algorithm.Suffix);
        Assert.IsNotNull(result3);
        Assert.IsFalse(result3.Success);
        Assert.AreEqual("Key and client secret are not properly delimited.", result3.Message);
        
        // Try properly delimited garbage
        var result4 = await validator.TryValidate(algorithm.Prefix + $"abc{ApiKeyValidator.Separator}123" + algorithm.Suffix);
        Assert.IsNotNull(result4);
        Assert.IsFalse(result4.Success);
        Assert.AreEqual("Key ID is not properly formatted.", result4.Message);
        
        // Try properly delimited garbage
        var result5 = await validator.TryValidate(algorithm.Prefix + Base58.Ripple.Encode(Guid.NewGuid().ToByteArray()) + $"{ApiKeyValidator.Separator}123" + algorithm.Suffix);
        Assert.IsNotNull(result5);
        Assert.IsFalse(result5.Success);
        Assert.AreEqual("Repository does not contain a key matching this ID.", result5.Message);
        
        // Validate the key successfully this time
        var validated = await validator.TryValidate(apiKeyString);
        Assert.IsNotNull(validated);
        Assert.IsTrue(validated.Success);
        Assert.AreEqual(persistedKey.ApiKeyId, validated.ApiKey.ApiKeyId);
        Assert.AreEqual(persistedKey.KeyName, validated.ApiKey.KeyName);
    }
}