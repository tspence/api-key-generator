using System;
using System.Threading.Tasks;
using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator.Keys
{
    public class CachedApiKeyResult
    {
        /// <summary>
        /// A hash of the remote IPv4 or IPv6 address combined with the API key
        /// </summary>
        public string AddressKeyHash { get; internal set; }
        
        /// <summary>
        /// The last time this key was verified
        /// </summary>
        public DateTimeOffset LastVerified { get; internal set; }
        
        /// <summary>
        /// The result from the most recent API key validation
        /// </summary>
        public ApiKeyResult Result { get; internal set; }
        
        /// <summary>
        /// If this cache entry is in the process of background re-verification, this task
        /// will be non-null.  You can await this task to see the updated results of the
        /// verification.
        /// </summary>
        public Task<ApiKeyResult> BackgroundVerificationTask { get; internal set; }
    }
}