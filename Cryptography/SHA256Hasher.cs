using System;
using System.Text;

namespace SecureFileShareP2P.Cryptography
{
    public static class SHA256Hasher
    {
        // Constants for SHA-256
        private static readonly uint[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Main hashing function
        public static string ComputeHash(string input)
        {
            // Pre-processing: Pad the input
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            int bitLength = inputBytes.Length * 8;
            int paddedLength = ((bitLength + 512 - 448 - 1) / 512) * 512 + 448;
            byte[] padded = new byte[(paddedLength + 64) / 8];

            Array.Copy(inputBytes, padded, inputBytes.Length);
            padded[inputBytes.Length] = 0x80; // Append '1' bit

            // Append original length (big-endian)
            byte[] lengthBytes = BitConverter.GetBytes((ulong)bitLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            Array.Copy(lengthBytes, 0, padded, padded.Length - 8, 8);

            // Initialize hash values (first 32 bits of fractional parts of sqrt(primes))
            uint[] hash = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };

            // Process chunks
            for (int i = 0; i < padded.Length; i += 64)
            {
                uint[] w = new uint[64];
                for (int t = 0; t < 16; t++)
                {
                    w[t] = BitConverter.ToUInt32(padded, i + t * 4);
                    if (BitConverter.IsLittleEndian)
                        w[t] = ReverseBytes(w[t]);
                }

                for (int t = 16; t < 64; t++)
                {
                    uint s0 = RightRotate(w[t - 15], 7) ^ RightRotate(w[t - 15], 18) ^ (w[t - 15] >> 3);
                    uint s1 = RightRotate(w[t - 2], 17) ^ RightRotate(w[t - 2], 19) ^ (w[t - 2] >> 10);
                    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
                }

                uint a = hash[0], b = hash[1], c = hash[2], d = hash[3],
                     e = hash[4], f = hash[5], g = hash[6], h = hash[7];

                for (int t = 0; t < 64; t++)
                {
                    uint S1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
                    uint ch = (e & f) ^ ((~e) & g);
                    uint temp1 = h + S1 + ch + K[t] + w[t];
                    uint S0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    uint temp2 = S0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }

                hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
                hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
            }

            // Convert hash to hex string
            byte[] hashBytes = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                byte[] part = BitConverter.GetBytes(hash[i]);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(part);
                Array.Copy(part, 0, hashBytes, i * 4, 4);
            }

            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        // Helper functions
        private static uint RightRotate(uint value, int count)
            => (value >> count) | (value << (32 - count));

        private static uint ReverseBytes(uint value)
            => (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
               (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
    }
}