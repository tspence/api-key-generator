namespace ApiKeyGenerator
{
    public class ApiKeyAlgorithm
    {
        /// <summary>
        /// Default algorithm:
        /// * Prefix and Suffix are "api" and "key" slightly mixed up
        /// * Hash algorithm is BCrypt
        /// * Client secret and salt are both 512 bits (64 bytes)
        /// </summary>
        public static ApiKeyAlgorithm DefaultAlgorithm { get; } = new ApiKeyAlgorithm()
        {
            Prefix = "kpb",
            Suffix = "aei",
            Hash = HashAlgorithmType.PBKDF2100K,
            ClientSecretLength = 64,
            SaltLength = 64,
        };
        
        /// <summary>
        /// The prefix to use when generating an API key string for client use.
        /// </summary>
        public string Prefix { get; set; }
        /// <summary>
        /// The suffix to use when generating an API key string for client use.
        /// </summary>
        public string Suffix { get; set; }
        /// <summary>
        /// The hash algorithm to use.  Note that BCrypt is significantly slower
        /// than SHA256 or SHA512, but it is more resistant to brute force attacks.
        /// </summary>
        public HashAlgorithmType Hash { get; set; }
        /// <summary>
        /// The number of bytes to use for the length of the client secret.
        /// </summary>
        public int ClientSecretLength { get; set; }
        /// <summary>
        /// The number of bytes to use for the salt. In the case of BCrypt, this value
        /// is ignored and BCrypt's recommended salt length is used instead.
        /// </summary>
        public int SaltLength { get; set; }
    }
}