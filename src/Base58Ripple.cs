﻿using System;
using System.Text;

namespace ApiKeyGenerator
{
    /// <summary>
    /// Code adapted from micli, https://gist.github.com/micli/c242edd2a81a8f0d9f7953842bcc24f1 
    /// </summary>
    public static class Base58Ripple
    {
        // We use the Ripple alphabet
        private static readonly char[]
            _alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz".ToCharArray();

        private static int[] _indexes = null;

        private static int[] GetIndexes()
        {
            if (_indexes == null)
            {
                _indexes = new int[128];
                for (int i = 0; i < _indexes.Length; i++)
                {
                    _indexes[i] = -1;
                }

                for (int i = 0; i < _alphabet.Length; i++)
                {
                    _indexes[_alphabet[i]] = i;
                }
            }

            return _indexes;
        }

        public static string Encode(byte[] input)
        {
            if (0 == input.Length)
            {
                return string.Empty;
            }

            input = CopyOfRange(input, 0, input.Length);
            // Count leading zeroes.
            int zeroCount = 0;
            while (zeroCount < input.Length && input[zeroCount] == 0)
            {
                zeroCount++;
            }

            // The actual encoding.
            byte[] temp = new byte[input.Length * 2];
            int j = temp.Length;

            int startAt = zeroCount;
            while (startAt < input.Length)
            {
                byte mod = DivMod58(input, startAt);
                if (input[startAt] == 0)
                {
                    startAt++;
                }

                temp[--j] = (byte)_alphabet[mod];
            }

            // Strip extra '1' if there are some after decoding.
            while (j < temp.Length && temp[j] == _alphabet[0])
            {
                ++j;
            }

            // Add as many leading '1' as there were leading zeros.
            while (--zeroCount >= 0)
            {
                temp[--j] = (byte)_alphabet[0];
            }

            byte[] output = CopyOfRange(temp, j, temp.Length);
            try
            {
                return Encoding.ASCII.GetString(output);
            }
            catch
            {
                return null;
            }
        }

        public static bool TryDecode(string input, byte[] bytes, out int numBytesWritten)
        {
            numBytesWritten = 0;
            if (0 == input.Length)
            {
                return false;
            }

            var indexes = GetIndexes();
            byte[] input58 = new byte[input.Length];

            // Transform the String to a base58 byte sequence
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];

                int digit58 = -1;
                if (c >= 0 && c < 128)
                {
                    digit58 = indexes[c];
                }

                if (digit58 < 0)
                {
                    // Illegal character {c} ({(int)c} at position {i}
                    return false;
                }

                input58[i] = (byte)digit58;
            }

            // Count leading zeroes
            int zeroCount = 0;
            while (zeroCount < input58.Length && input58[zeroCount] == 0)
            {
                zeroCount++;
            }

            // The encoding
            byte[] temp = new byte[input.Length];
            int j = temp.Length;

            int startAt = zeroCount;
            while (startAt < input58.Length)
            {
                byte mod = DivMod256(input58, startAt);
                if (input58[startAt] == 0)
                {
                    ++startAt;
                }

                temp[--j] = mod;
            }

            // Do no add extra leading zeroes, move j to first non null byte.
            while (j < temp.Length && temp[j] == 0)
            {
                j++;
            }

            var output = CopyOfRange(temp, j - zeroCount, temp.Length);
            for (int i = 0; i < output.Length; i++)
            {
                bytes[i] = output[i];
            }

            numBytesWritten = output.Length;
            return true;
        }

        private static byte DivMod58(byte[] number, int startAt)
        {
            int remainder = 0;
            for (int i = startAt; i < number.Length; i++)
            {
                int digit256 = (int)number[i] & 0xFF;
                int temp = remainder * 256 + digit256;

                number[i] = (byte)(temp / 58);

                remainder = temp % 58;
            }

            return (byte)remainder;
        }

        private static byte DivMod256(byte[] number58, int startAt)
        {
            int remainder = 0;
            for (int i = startAt; i < number58.Length; i++)
            {
                int digit58 = (int)number58[i] & 0xFF;
                int temp = remainder * 58 + digit58;

                number58[i] = (byte)(temp / 256);

                remainder = temp % 256;
            }

            return (byte)remainder;
        }

        private static byte[] CopyOfRange(byte[] source, int from, int to)
        {
            byte[] range = new byte[to - from];
            for (int i = 0; i < to - from; i++)
            {
                range[i] = source[from + i];
            }

            return range;
        }
    }
}