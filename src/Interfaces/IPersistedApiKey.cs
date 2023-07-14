using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace ApiKeyGenerator.Interfaces
{
    /// <summary>
    /// Represents a key that will be preserved in your API key repository.
    /// </summary>
    public interface IPersistedApiKey
    {

        /// <summary>
        /// The unique identifier of this API key.
        /// </summary>
        Guid ApiKeyId { get; set; }
        
        /// <summary>
        /// The salt used in the computation of the hash - this is generated once and preserved
        /// in your API key repository.  This is generated using randomness/entropy and is at least
        /// 512 bits in length encoded using Base64.
        /// </summary>
        string Salt { get; set; }

        /// <summary>
        /// This is the hash computed as Hash_Algorithm(ClientSecret + Salt).
        /// </summary>
        string Hash { get; set; }
        
        /// <summary>
        /// The official "name" of this key, as provided by the creator, if any.
        /// </summary>
        string KeyName { get; set; }
        
        /// <summary>
        /// True if this API key has been revoked.
        /// </summary>
        bool? IsRevoked { get; set; }
        
        /// <summary>
        /// The date/time when this key expires.
        /// </summary>
        DateTime? ExpirationDate { get; set; }
        
        /// <summary>
        /// The list of claims attached to this key.
        /// </summary>
        List<Claim> Claims { get; set; }
    }
}