using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using ApiKeyGenerator.Exceptions;
using ApiKeyGenerator.Interfaces;
using ApiKeyGenerator.Keys;
using SimpleBase;

namespace ApiKeyGenerator
{
    public class ApiKeyValidator
    {
        private readonly IApiKeyRepository _repository;

        public static readonly char Separator = '_';

        public ApiKeyValidator(IApiKeyRepository repository)
        {
            _repository = repository;
        }

        /// <summary>
        /// Validate a client's API key string.  If successful, returns the matching persisted API key with all
        /// relevant claims information from your persistent storage.  If unable to validate, returns information that
        /// can assist the developer in understanding why their key could not be validated.  Consult your security
        /// professionals to identify which diagnostic information should be exposed to your end users.
        /// </summary>
        /// <param name="clientApiKeyString">The raw client API key string as provided to your API</param>
        /// <returns>A result object with information about validation</returns>
        public async Task<ApiKeyResult> TryValidate(string clientApiKeyString)
        {
            if (string.IsNullOrWhiteSpace(clientApiKeyString))
            {
                return new ApiKeyResult() { Message = "Key is null or empty." };
            }
            
            // Determine supported algorithms, or default
            var algorithms = new List<ApiKeyAlgorithm>();
            var supported = _repository.GetSupportedAlgorithms();
            if (supported != null)
            {
                algorithms.AddRange(supported);
            }
            else
            {
                algorithms.Add(ApiKeyAlgorithm.DefaultAlgorithm);
            }
            
            // Check all supported algorithms to see if this API key is valid
            foreach (var algorithm in algorithms.Where(algorithm => clientApiKeyString.StartsWith(algorithm.Prefix)))
            {
                if (!TryParseKey(clientApiKeyString, algorithm, out var clientApiKey, out var message))
                {
                    return new ApiKeyResult() { Message = message };
                }
                    
                // Fetch the matching persisted key
                var persistedApiKey = await _repository.GetKey(clientApiKey.ApiKeyId);
                if (persistedApiKey == null)
                {
                    return new ApiKeyResult()
                        { Message = $"Repository does not contain a key matching this ID." };
                }
                if (TestKeys(algorithm, clientApiKey, persistedApiKey))
                {
                    return new ApiKeyResult() { Success = true, ApiKey = persistedApiKey };
                }

                return new ApiKeyResult() { Message = "Invalid API key hash." };
            }

            return new ApiKeyResult() { Message = "Key prefix does not match any supported key algorithms." };
        }

        /// <summary>
        /// Parses the key and throws an exception if the key is malformed
        /// </summary>
        /// <param name="keyString">The client API key string to test</param>
        /// <param name="algorithm">The algorithm to use, or null to use the default</param>
        /// <returns>The matching API key if successful</returns>
        /// <exception cref="Exception">If not successful, an exception explaining why it was not validated</exception>
        public ClientApiKey ParseKey(string keyString, ApiKeyAlgorithm algorithm = null)
        {
            var realAlgorithm = algorithm ?? ApiKeyAlgorithm.DefaultAlgorithm;
            if (!TryParseKey(keyString, realAlgorithm, out var value, out var message))
            {
                throw new InvalidKeyException(message);
            }

            return value;
        }

        /// <summary>
        /// Parses the key and returns true/false if the key is correctly parseable
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <param name="value"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public bool TryParseKey(string key, ApiKeyAlgorithm algorithm, out ClientApiKey value, out string message)
        {
            value = null;
            if (string.IsNullOrWhiteSpace(key))
            {
                message = "Key is null or empty.";
                return false;
            }

            if (!key.StartsWith(algorithm.Prefix))
            {
                message = $"This does not look like an API key (missing prefix {algorithm.Prefix}).";
                return false;
            }

            if (!key.EndsWith(algorithm.Suffix))
            {
                message = "This key was truncated and is missing some data.";
                return false;
            }

            var pos = key.IndexOf(Separator);
            if (pos <= 0)
            {
                message = "Key and client secret are not properly delimited.";
                return false;
            }
            
            // Extract the key ID and client secret
            var keyId = key.Substring(algorithm.Prefix.Length, pos - algorithm.Prefix.Length);
            if (!TryDecode(keyId, 16, out var keyBytes))
            {
                message = "Key ID is not properly formatted.";
                return false;
            }
            var keyGuid = new Guid(keyBytes);
            var clientSecret = key.Substring(pos + 1, key.Length - algorithm.Suffix.Length - 1 - pos);
            
            // Construct a new valid key
            value = new ClientApiKey() { ApiKeyId = keyGuid, ClientSecret = clientSecret };
            message = null;
            return true;
        }

        /// <summary>
        /// Generates a new key with the current key generation algorithm.
        ///
        /// You must supply an IPersistedApiKey object to this function.  This function will
        /// overwrite the values ApiKeyId, Hash, and Salt, with the data from the key
        /// generation process.  Once the necessary information has been generated, this function
        /// will invoke your repository's SaveKey method to persist the key in the database. If
        /// the key is successfully saved into the database, the return value of this function
        /// will be the client's API key string that they will use to authenticate.
        /// </summary>
        /// <param name="persisted">A key object that contains whatever claims you want.</param>
        /// <returns>The client API key string.</returns>
        public async Task<string> GenerateApiKey(IPersistedApiKey persisted)
        {
            var algorithm = _repository.GetNewKeyAlgorithm() ?? ApiKeyAlgorithm.DefaultAlgorithm;
            var keyId = Guid.NewGuid();
            var rand = RandomNumberGenerator.Create();
            var secretBytes = new byte[algorithm.ClientSecretLength];
            rand.GetBytes(secretBytes);
            var secret = Encode(secretBytes);
            string salt;
            if (algorithm.Hash == HashAlgorithmType.BCrypt)
            {
                salt = BCrypt.Net.BCrypt.GenerateSalt();
            }
            else
            {
                var saltBytes = new byte[algorithm.SaltLength];
                rand.GetBytes(saltBytes);
                salt = Encode(saltBytes);
            }

            // Construct client key
            var clientKey = new ClientApiKey() { ApiKeyId = keyId, ClientSecret = secret };
            
            // Fill information into persisted key
            persisted.ApiKeyId = keyId;
            persisted.Hash = Hash(algorithm, secret, salt);
            persisted.Salt = salt;
            
            // Save this API key into the repository
            if (!await _repository.SaveKey(persisted))
            {
                throw new KeyPersistFailedException("Unable to persist new API key in repository.");
            }
            
            // Return the client's key to them
            return clientKey.ToApiKeyString(algorithm);
        }

        private bool TestKeys(ApiKeyAlgorithm algorithm, ClientApiKey clientApiKey, IPersistedApiKey persistedApiKey)
        {
            // Compute hash and see if it matches
            var computedHash = Hash(algorithm, clientApiKey.ClientSecret, persistedApiKey.Salt);
            return string.Equals(computedHash, persistedApiKey.Hash);
        }

        private static Tuple<byte[], byte[]> SecretAndSaltToBytes(ApiKeyAlgorithm algorithm, string secret, string salt)
        {
            var s1 = TryDecode(secret, algorithm.ClientSecretLength, out var secretBytes);
            var s2 = TryDecode(salt, algorithm.SaltLength, out var saltBytes);
            if (!s1 || !s2)
            {
                return new Tuple<byte[], byte[]>(null, null);
            }

            return new Tuple<byte[], byte[]>(secretBytes, saltBytes);
        }

        /// <summary>
        /// Encode a series of bytes in the Ripple Base58 format
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string Encode(byte[] bytes)
        {
            return Base58.Ripple.Encode(bytes);
        }

        internal static bool TryDecode(string text, int expectedLength, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            
            // You would think that a function called "TryDecode" would not throw an exception.
            // However, you would be wrong.
            try
            {
                bytes = new byte[expectedLength];
                var success = Base58.Ripple.TryDecode(text, bytes, out var numBytesWritten);
                return success && numBytesWritten == expectedLength;
            }
            catch
            {
                return false;
            }
        }

        private static string Hash(ApiKeyAlgorithm algorithm, string secret, string salt)
        {
            switch (algorithm.Hash)
            {
                case HashAlgorithmType.SHA256:
                    using (var sha256 = SHA256.Create())
                    {
                        var rawBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                        var hashBytes = sha256.ComputeHash(rawBytes.Item1.Union(rawBytes.Item2).ToArray());
                        return Convert.ToBase64String(hashBytes);
                    }
                case HashAlgorithmType.SHA512:
                    using (var sha512 = SHA512.Create())
                    {
                        var rawBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                        var hashBytes = sha512.ComputeHash(rawBytes.Item1.Union(rawBytes.Item2).ToArray());
                        return Encode(hashBytes);
                    }
                case HashAlgorithmType.BCrypt:
                    return BCrypt.Net.BCrypt.HashPassword(secret, salt);
                case HashAlgorithmType.PBKDF2100K:
                    var pbkBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                    using (var pbk = new Rfc2898DeriveBytes(pbkBytes.Item1, pbkBytes.Item2, 100_000))
                    {
                        var hash = pbk.GetBytes(64);
                        return Encode(hash);
                    }
            }

            throw new InvalidAlgorithmException($"Unknown hash type {algorithm.Hash}");
        }
    }
}