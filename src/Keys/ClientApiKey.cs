using System;

namespace ApiKeyGenerator.Keys
{
    /// <summary>
    /// Represents a key to be shared to or received from the client.  This key can be validated
    /// by fetching the corresponding IApiKeyStorage object and recomputing the hash using the
    /// ClientSecret + Salt as input. 
    /// </summary>
    public class ClientApiKey
    {
        /// <summary>
        /// The unique identifier of this API key.
        /// </summary>
        public Guid ApiKeyId { get; set;  }
        
        /// <summary>
        /// The client secret portion of this key.  This is information only supposed to be held in
        /// memory for a short period of time and delivered to the customer as quickly as possible.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Converts this API key into a string the customer can use for authentication.
        /// </summary>
        /// <param name="algorithm">The selected algorithm</param>
        /// <returns></returns>
        public string ToApiKeyString(ApiKeyAlgorithm algorithm)
        {
            var idBytes = ApiKeyId.ToByteArray();
            var idString = ApiKeyValidator.Encode(idBytes);
            return $"{algorithm.Prefix}{idString}{ApiKeyValidator.Separator}{ClientSecret}{algorithm.Suffix}";
        }
    }
}