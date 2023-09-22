using System;

namespace ApiKeyGenerator.Exceptions
{
    /// <summary>
    /// This exception occurs when a key is generated but it fails to be
    /// persisted into the data store.
    /// </summary>
    public class KeyPersistFailedException : Exception
    {
        public KeyPersistFailedException(string message)
         : base(message)
        {
        }
    }
}