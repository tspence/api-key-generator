using System;

namespace ApiKeyGenerator.Exceptions
{
    /// <summary>
    /// This exception is thrown when you use the `ParseKey` method but
    /// the key value is not correctly formatted.
    /// </summary>
    public class InvalidKeyException : Exception
    {
        public InvalidKeyException(string message)
            : base(message)
        {
        }
    }
}