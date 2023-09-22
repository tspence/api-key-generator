using System;
using System.Threading.Tasks;
using ApiKeyGenerator.Exceptions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
// ReSharper disable StringLiteralTypo

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
        var ex = Assert.ThrowsException<InvalidKeyException>(() => validator.ParseKey("", null));
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
        var result5 = await validator.TryValidate(algorithm.Prefix + ApiKeyValidator.Encode(Guid.NewGuid().ToByteArray()) + $"{ApiKeyValidator.Separator}123" + algorithm.Suffix);
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

    [TestMethod]
    public async Task TestMultipleAlgorithmParsing()
    {
        // Let's imagine a scenario where a customer has multiple key algorithms, and then we need to validate
        // a key with any one that matches.  Let's generate three algorithms and build a key with each.
        var bcrypt = new ApiKeyAlgorithm()
        {
            Hash = HashAlgorithmType.BCrypt,
            SaltLength = 64,
            ClientSecretLength = 64,
            Prefix = "keyb",
            Suffix = "byek",
        };
        var pbkdf = new ApiKeyAlgorithm()
        {
            Hash = HashAlgorithmType.PBKDF2100K,
            SaltLength = 64,
            ClientSecretLength = 64,
            Prefix = "keyp",
            Suffix = "pyek",
        };
        var sha = new ApiKeyAlgorithm()
        {
            Hash = HashAlgorithmType.SHA512,
            SaltLength = 64,
            ClientSecretLength = 64,
            Prefix = "keys",
            Suffix = "syek",
        };
        var repository = new MultiRepository(bcrypt, pbkdf, sha);
        var validator = new ApiKeyValidator(repository);
               
        // Generate some keys with each of these
        var bcryptKey = new PersistedApiKey() { KeyName = "BCryptKey" };
        var bcryptString = await validator.GenerateApiKey(bcryptKey, bcrypt);
        var pbkdfKey = new PersistedApiKey() { KeyName = "PbkdfKey" };
        var pbkdfString = await validator.GenerateApiKey(pbkdfKey, pbkdf);
        var shaKey = new PersistedApiKey() { KeyName = "ShaKey" };
        var shaString = await validator.GenerateApiKey(shaKey, sha);
        
        // Now validate them - they should all validate!
        var validated1 = await validator.TryValidate(bcryptString);
        Assert.IsNotNull(validated1);
        Assert.IsTrue(validated1.Success);
        Assert.AreEqual(bcryptKey.ApiKeyId, validated1.ApiKey.ApiKeyId);
        Assert.AreEqual(bcryptKey.KeyName, validated1.ApiKey.KeyName);
        
        var validated2 = await validator.TryValidate(pbkdfString);
        Assert.IsNotNull(validated2);
        Assert.IsTrue(validated2.Success);
        Assert.AreEqual(pbkdfKey.ApiKeyId, validated2.ApiKey.ApiKeyId);
        Assert.AreEqual(pbkdfKey.KeyName, validated2.ApiKey.KeyName);

        var validated3 = await validator.TryValidate(shaString);
        Assert.IsNotNull(validated3);
        Assert.IsTrue(validated3.Success);
        Assert.AreEqual(shaKey.ApiKeyId, validated3.ApiKey.ApiKeyId);
        Assert.AreEqual(shaKey.KeyName, validated3.ApiKey.KeyName);

        // Now validate something that's clearly not a key
        var validated4 = await validator.TryValidate("something random");
        Assert.IsNotNull(validated4);
        Assert.IsFalse(validated4.Success);
        Assert.AreEqual("Key prefix does not match any supported key algorithms.", validated4.Message);
        
        // Now add another algorithm with a conflicting prefix, and get a different error message
        repository.Algorithms.Add(new ApiKeyAlgorithm()
        {
            Hash = HashAlgorithmType.SHA512,
            SaltLength = 128,
            ClientSecretLength = 128,
            Prefix = "keys",
            Suffix = "longsyek",
        });
        var validated5 = await validator.TryValidate("keys_random");
        Assert.IsNotNull(validated5);
        Assert.IsFalse(validated5.Success);
        Assert.AreEqual("Invalid API key hash.", validated5.Message);
    }

}