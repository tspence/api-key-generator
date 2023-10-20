using System;
using System.Threading.Tasks;
using ApiKeyGenerator.Interfaces;
using ApiKeyGenerator.Keys;

namespace ApiKeyGenerator.Interfaces
{
    public interface IApiKeyValidator
    {
        /// <summary>
        /// Validate a client's API key string.  If successful, returns the matching persisted API key with all
        /// relevant claims information from your persistent storage.  If unable to validate, returns information that
        /// can assist the developer in understanding why their key could not be validated.  Consult your security
        /// professionals to identify which diagnostic information should be exposed to your end users.
        /// </summary>
        /// <param name="clientApiKeyString">The raw client API key string as provided to your API</param>
        /// <returns>A result object with information about validation</returns>
        Task<ApiKeyResult> TryValidate(string clientApiKeyString);

        /// <summary>
        /// Parses the key and throws an exception if the key is malformed
        /// </summary>
        /// <param name="keyString">The client API key string to test</param>
        /// <param name="algorithm">The algorithm to use, or null to use the default</param>
        /// <returns>The matching API key if successful</returns>
        /// <exception cref="Exception">If not successful, an exception explaining why it was not validated</exception>
        ClientApiKey ParseKey(string keyString, ApiKeyAlgorithm algorithm = null);

        /// <summary>
        /// Parses the key and returns true/false if the key is correctly parseable
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <param name="value"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        bool TryParseKey(string key, ApiKeyAlgorithm algorithm, out ClientApiKey value, out string message);

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
        /// <param name="algorithm">The algorithm to use when generating this key, or null to use the default algorithm.</param>
        /// <returns>The client API key string.</returns>
        Task<string> GenerateApiKey(IPersistedApiKey persisted, ApiKeyAlgorithm algorithm = null);
    }
}