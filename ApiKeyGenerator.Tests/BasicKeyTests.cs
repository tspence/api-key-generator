using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ApiKeyGenerator.Tests;

[TestClass]
public class BasicKeyTests
{
    [DataTestMethod]
    [DataRow(HashAlgorithmType.SHA256)]
    [DataRow(HashAlgorithmType.SHA512)]
    [DataRow(HashAlgorithmType.BCrypt)]
    public async Task TestAlgorithm(HashAlgorithmType hashType)
    {
        var repository = new TestRepository
        {
            Algorithm = new ApiKeyAlgorithm()
            {
                Hash = hashType,
                SaltLength = 64,
                ClientSecretLength = 64,
                Prefix = "key",
                Suffix = "yek",
            }
        };
        var validator = new ApiKeyValidator(repository);
        
        // Generate a key
        var persistedKey = new PersistedApiKey
        {
            KeyName = "TestKeyGeneration"
        };
        Assert.AreEqual(Guid.Empty, persistedKey.ApiKeyId);
        var apiKeyString = await validator.GenerateApiKey(persistedKey);
        Assert.AreNotEqual(string.Empty, apiKeyString);
        Assert.AreNotEqual(Guid.Empty, persistedKey.ApiKeyId);

        // Validate the key
        var validated = await validator.TryValidate(apiKeyString);
        Assert.IsNotNull(validated);
        Assert.IsTrue(validated.Success);
        Assert.AreEqual(persistedKey.ApiKeyId, validated.ApiKey.ApiKeyId);
        Assert.AreEqual(persistedKey.KeyName, validated.ApiKey.KeyName);
    }

    [DataTestMethod]
    [DataRow(HashAlgorithmType.SHA256)]
    [DataRow(HashAlgorithmType.SHA512)]
    [DataRow(HashAlgorithmType.BCrypt)]
    public async Task TestFailureModes(HashAlgorithmType hashType)
    {
        var repository = new TestRepository
        {
            Algorithm = new ApiKeyAlgorithm()
            {
                Hash = hashType,
                SaltLength = 64,
                ClientSecretLength = 64,
                Prefix = "key",
                Suffix = "yek",
            }
        };
        var validator = new ApiKeyValidator(repository);
        
        // Generate a key
        var persistedKey = new PersistedApiKey
        {
            KeyName = "TestKeyGeneration"
        };
        Assert.AreEqual(Guid.Empty, persistedKey.ApiKeyId);
        var apiKeyString = await validator.GenerateApiKey(persistedKey);
        Assert.AreNotEqual(string.Empty, apiKeyString);
        Assert.AreNotEqual(Guid.Empty, persistedKey.ApiKeyId);

        // Break the prefix and attempt to validate
        var result = await validator.TryValidate("extra" + apiKeyString);
        Assert.IsNotNull(result);
        Assert.IsFalse(result.Success);
        Assert.AreEqual("Key prefix does not match any supported key algorithms.", result.Message);

        // Break the suffix and attempt to validate
        var result2 = await validator.TryValidate(apiKeyString + "extra");
        Assert.IsNotNull(result2);
        Assert.IsFalse(result2.Success);
        Assert.AreEqual("This key was truncated and is missing some data.", result2.Message);

        // Try random garbage
        var result3 = await validator.TryValidate(repository.Algorithm.Prefix + "abc" + repository.Algorithm.Suffix);
        Assert.IsNotNull(result3);
        Assert.IsFalse(result3.Success);
        Assert.AreEqual("Key and client secret are not properly delimited.", result3.Message);
        
        // Try properly delimited garbage
        var result4 = await validator.TryValidate(repository.Algorithm.Prefix + "abc:123" + repository.Algorithm.Suffix);
        Assert.IsNotNull(result4);
        Assert.IsFalse(result4.Success);
        Assert.AreEqual("Key ID is not properly formatted.", result4.Message);
        
        // Try properly delimited garbage
        var result5 = await validator.TryValidate(repository.Algorithm.Prefix + Convert.ToBase64String(Guid.NewGuid().ToByteArray()) + ":123" + repository.Algorithm.Suffix);
        Assert.IsNotNull(result5);
        Assert.IsFalse(result5.Success);
        Assert.AreEqual("Repository does not contain a key matching this ID.", result5.Message);
    }
}