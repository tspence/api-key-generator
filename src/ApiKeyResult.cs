using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator
{
    public class ApiKeyResult
    {
        /// <summary>
        /// True if the client API key was successfully validated
        /// </summary>
        public bool Success { get; set; }
        
        /// <summary>
        /// If the API key was not validated, this contains a relevant error message.
        /// </summary>
        public string Message { get; set; }
        
        /// <summary>
        /// If the API key was successfully validated, this is the credential information of the caller.
        /// </summary>
        public IPersistedApiKey ApiKey { get; set; }
    }
}