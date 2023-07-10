using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ApiKeyGenerator.Tests;

[TestClass]
public class BasicKeyTests
{
    [TestMethod]
    public async Task TestKeyGeneration()
    {
        var repository = new TestRepository();
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
}