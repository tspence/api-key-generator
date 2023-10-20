using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using ApiKeyGenerator.Interfaces;
using ApiKeyGenerator.Keys;

namespace ApiKeyGenerator
{
    /// <summary>
    /// For performance sensitive APIs where you are willing to make a compromise, you can use
    /// this cached validator instead of the normal ApiKeyValidator.  Here's why you might
    /// consider using it.
    ///
    /// * A healthy API key will be slow to validate (increases difficulty of rainbow table attacks)
    /// * Algorithms like BCrypt and PBKDF2100K can take 70ms or more on 2023 hardware.
    /// * Once a person has successfully validated with a specific API key from a specific IP address,
    /// it is reasonable to expect that they will make another API call from that same address soon.
    /// * In most systems, it is realistic to expect that revoking an API key will take a few moments
    /// before all usages of that API key will stop.
    ///
    /// Using this logic, you can define a caching system that works as follows:
    /// * Validate all API keys the first time they are seen (takes 70ms; similar overhead to
    /// establishing an SSL connection).
    /// * Keep track of a SHA512 hash of the IP address and the key, and the time it was last validated.
    /// * As long as calls continue to be made by that IP address with that same API key, allow them
    /// to succeed.
    /// * If the last validation time of an API key is > N1 seconds, start a background task to update
    /// the verification cache, BUT continue to allow API calls to succeed.
    /// * If the last validation time of an API key is > N2 seconds, force a full re-validation to
    /// occur and discard the cached information.
    ///
    /// The end result of this system is that well-behaved clients who make multiple API calls from
    /// the same server in a row and do not expire their keys often will see fewer API key validation
    /// delays in their API calls.
    ///
    /// Be sure to notify customers that expiring an API key may take N * 2 seconds to propagate across
    /// all systems that use this cached API validator.
    ///
    /// Full explanation:
    /// https://tedspence.com/caching-strategies-for-authentication-8346a040234d
    /// </summary>
    public class CachedValidator
    {
        private readonly IApiKeyRepository _repository;
        private readonly IApiKeyValidator _validator;
        private readonly int _cacheDurationMs;
        private ConcurrentDictionary<string, CachedApiKeyResult> _cache;
        private readonly ITimeProvider _timeProvider;
        private readonly int _backgroundVerificationWindowMs;

        public CachedValidator(IApiKeyRepository repository, IApiKeyValidator validator,
            ITimeProvider timeProvider, int cacheDurationMs, int backgroundVerificationWindowMs)
        {
            _repository = repository;
            _validator = validator;
            _cacheDurationMs = cacheDurationMs;
            _backgroundVerificationWindowMs = backgroundVerificationWindowMs;
            _timeProvider = timeProvider;
            _cache = new ConcurrentDictionary<string, CachedApiKeyResult>();
        }

        /// <summary>
        /// Validate a client's API key string.  If successful, returns the matching persisted API key with all
        /// relevant claims information from your persistent storage.  If unable to validate, returns information that
        /// can assist the developer in understanding why their key could not be validated.  Consult your security
        /// professionals to identify which diagnostic information should be exposed to your end users.
        ///
        /// If a caller makes multiple calls from the same source address in sequence
        /// </summary>
        /// <param name="clientApiKeyString">The raw client API key string as provided to your API</param>
        /// <param name="remoteAddress">The remote IPv4 or IPv6 address of the client using this API key</param>
        /// <returns>A result object with information about validation</returns>
        public async Task<ApiKeyResult> TryValidate(string clientApiKeyString, string remoteAddress)
        {
            var now = _timeProvider.GetUtcNow();
            
            // Check the cache to see if this key has been seen from this remote address recently
            var hashtag = EncryptionTools.QuickStringHash(remoteAddress + ":" + clientApiKeyString);
            if (_cache.TryGetValue(hashtag, out var cacheEntry))
            {
                var age = (now - cacheEntry.LastVerified).TotalMilliseconds;

                // If this value was last seen within the cache window, it's okay to return the result
                if (age < _backgroundVerificationWindowMs)
                {
                    return cacheEntry.Result;
                }

                // This cache key is old enough that we must start a background task to verify it.
                // We will start the task, but not await the result!
                if (cacheEntry.BackgroundVerificationTask == null)
                {
                    cacheEntry.BackgroundVerificationTask = VerifyApiKey(clientApiKeyString);
                }

                // If the cache entry is still within the cache window, we can return the previous
                // result.
                if (age < _cacheDurationMs)
                {
                    return cacheEntry.Result;
                }

                // We are no longer within the caching window.
                // We must await the background verification task, update the cache entry, and give
                // the result back to the caller. 
                var backgroundResult = await cacheEntry.BackgroundVerificationTask;
                cacheEntry.Result = backgroundResult;
                cacheEntry.LastVerified = _timeProvider.GetUtcNow();
                cacheEntry.BackgroundVerificationTask = null;
                return cacheEntry.Result;
            }

            // First time we have seen this remote address / API key combo. Validate it, then save
            // it in the cache.
            var result = await VerifyApiKey(clientApiKeyString);
            var entry = new CachedApiKeyResult()
            {
                AddressKeyHash = hashtag,
                LastVerified = _timeProvider.GetUtcNow(),
                Result = result,
                BackgroundVerificationTask = null,
            };
            _cache[hashtag] = entry;
            return entry.Result;
        }

        private async Task<ApiKeyResult> VerifyApiKey(string clientApiKeyString)
        {
            var result = await _validator.TryValidate(clientApiKeyString);
            return result;
        }
    }
}