using System;

namespace ApiKeyGenerator.Interfaces
{
    /// <summary>
    /// Similar to TimeProvider in DotNet 8.0.
    ///
    /// Provided to allow this library to be compatible with older versions of DotNet.
    /// </summary>
    public interface ITimeProvider
    {
        DateTimeOffset GetUtcNow();
    }
}