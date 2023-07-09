﻿namespace ApiKeyGenerator
{
    public class ApiKeyAlgorithm
    {
        /// <summary>
        /// Default algorithm:
        /// * Prefix and Suffix are "api" and "key" slightly mixed up
        /// * Hash algorithm is SHA256
        /// * Client secret and salt are both 512 bits / 64 bytes
        /// </summary>
        public static ApiKeyAlgorithm DefaultAlgorithm = new ApiKeyAlgorithm()
        {
            Prefix = "kpy",
            Suffix = "aei",
            Hash = HashAlgorithmType.SHA256,
            ClientSecretLength = 64,
            SaltLength = 64,
        };
        
        public string Prefix { get; set; }
        public string Suffix { get; set; }
        public HashAlgorithmType Hash { get; set; }
        public int ClientSecretLength { get; set; }
        public int SaltLength { get; set; }
    }
}