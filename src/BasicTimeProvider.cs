using System;
using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator
{
    /// <summary>
    /// Similar to TimeProvider in DotNet 8.0.
    ///
    /// Provided to allow this library to be compatible with older versions of DotNet.
    /// </summary>
    public class BasicTimeProvider : ITimeProvider
    {
        public DateTimeOffset GetUtcNow()
        {
            return DateTimeOffset.UtcNow;
        }
    }
}