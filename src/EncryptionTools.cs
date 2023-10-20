using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ApiKeyGenerator.Exceptions;

namespace ApiKeyGenerator
{
    /// <summary>
    /// A collection of static functions to convert string values to bytes and hashes and back again
    /// </summary>
    public static class EncryptionTools
    {
        private class SecretSalt
        {
            /// <summary>
            /// The secret portion of the value, in byte array form
            /// </summary>
            public byte[] Secret { get; set; }
        
            /// <summary>
            /// The salt portion of the value, in byte array form
            /// </summary>
            public byte[] Salt { get; set; }
        }
        
        /// <summary>
        /// Convert values to bytes
        /// </summary>
        /// <param name="algorithm">The algorithm </param>
        /// <param name="secret"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private static SecretSalt SecretAndSaltToBytes(ApiKeyAlgorithm algorithm, string secret, string salt)
        {
            var s1 = TryDecode(secret, algorithm.ClientSecretLength, out var secretBytes);
            var s2 = TryDecode(salt, algorithm.SaltLength, out var saltBytes);
            if (!s1 || !s2)
            {
                return new SecretSalt();
            }

            return new SecretSalt() { Secret = secretBytes, Salt = saltBytes };
        }

        /// <summary>
        /// Encode a series of bytes in the Ripple Base58 format
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string Encode(byte[] bytes)
        {
            return Base58Ripple.Encode(bytes);
        }

        /// <summary>
        /// Attempt to decode a Ripple Base58 string into bytes
        /// </summary>
        /// <param name="text"></param>
        /// <param name="expectedLength"></param>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static bool TryDecode(string text, int expectedLength, out byte[] bytes)
        {
            bytes = new byte[expectedLength];
            var success = Base58Ripple.TryDecode(text, bytes, out var numBytesWritten);
            return success && numBytesWritten == expectedLength;
        }

        /// <summary>
        /// Convert a secret and salt into a hashed value using the selected algorithm
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="secret"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        /// <exception cref="InvalidAlgorithmException"></exception>
        public static string Hash(ApiKeyAlgorithm algorithm, string secret, string salt)
        {
            switch (algorithm.Hash)
            {
                case HashAlgorithmType.SHA256:
                    using (var sha256 = SHA256.Create())
                    {
                        var rawBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                        var hashBytes = sha256.ComputeHash(rawBytes.Secret.Union(rawBytes.Salt).ToArray());
                        return Convert.ToBase64String(hashBytes);
                    }
                case HashAlgorithmType.SHA512:
                    using (var sha512 = SHA512.Create())
                    {
                        var rawBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                        var hashBytes = sha512.ComputeHash(rawBytes.Secret.Union(rawBytes.Salt).ToArray());
                        return Encode(hashBytes);
                    }
                case HashAlgorithmType.BCrypt:
                    return BCrypt.Net.BCrypt.HashPassword(secret, salt);
                case HashAlgorithmType.PBKDF2100K:
                    var pbkBytes = SecretAndSaltToBytes(algorithm, secret, salt);
                    using (var pbk = new Rfc2898DeriveBytes(pbkBytes.Secret, pbkBytes.Salt, 100_000))
                    {
                        var hash = pbk.GetBytes(64);
                        return Encode(hash);
                    }
            }

            throw new InvalidAlgorithmException($"Unknown hash type {algorithm.Hash}");
        }

        /// <summary>
        /// Uses the SHA512 algorithm to create a simple and quick hash of a value, suitable for
        /// storing in a dictionary. Do not persist this value to disk since it can be attacked
        /// with a rainbow table.
        /// </summary>
        /// <param name="rawString">The raw string to hash</param>
        /// <returns>The SHA512 hash in Base64 format</returns>
        public static string QuickStringHash(string rawString)
        {
            using (var sha512 = SHA512.Create())
            {
                var rawBytes = Encoding.UTF8.GetBytes(rawString);
                var hashBytes = sha512.ComputeHash(rawBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
}