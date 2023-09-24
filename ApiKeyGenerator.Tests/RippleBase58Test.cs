using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ApiKeyGenerator.Tests;

[TestClass]
public class RippleBase58Test
{
    [TestMethod]
    public void BasicRippleTest()
    {
        // Encode and decode a bunch of guids to verify sanity
        for (int i = 0; i < 100; i++)
        {
            var guid = Guid.NewGuid();
            var rippleText = Base58Ripple.Encode(guid.ToByteArray());
            Assert.IsNotNull(rippleText);
            var outputBytes = new byte[16];
            var success = Base58Ripple.TryDecode(rippleText, outputBytes, out var numBytesWritten);
            Assert.IsTrue(success);
            Assert.AreEqual(16, numBytesWritten);
            var decodedGuid = new Guid(outputBytes);
            Assert.AreEqual(guid, decodedGuid);
        }
    }

    [TestMethod]
    public void EncodingMatchesSimpleBase()
    {
        // We previously used the library SimpleBase for encoding.
        // However, SimpleBase enforces dependency rules on us - we want to be able to
        // support NetStandard 2.0 and SimpleBase doesn't anymore.  So we'll eliminate
        // this dependency and ensure that our code works interoperably with theirs.
        for (int i = 0; i < 100; i++)
        {
            var guid = Guid.NewGuid();
            var rippleText = SimpleBase.Base58.Ripple.Encode(guid.ToByteArray());
            Assert.IsNotNull(rippleText);
            var outputBytes = new byte[16];
            var success = Base58Ripple.TryDecode(rippleText, outputBytes, out var numBytesWritten);
            Assert.IsTrue(success);
            Assert.AreEqual(16, numBytesWritten);
            var decodedGuid = new Guid(outputBytes);
            Assert.AreEqual(guid, decodedGuid);
        }
        
    }
}