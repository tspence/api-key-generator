using System;

namespace ApiKeyGenerator.Exceptions
{
    /// <summary>
    /// This exception occurs when the user sends a request to validate a
    /// key with an invalid exception algorithm. 
    /// </summary>
    public class InvalidAlgorithmException : Exception
    {
        public InvalidAlgorithmException(string message)
            : base(message)
        {
        }
    }
}