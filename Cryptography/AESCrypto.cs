using System;
using System.Security.Cryptography;

namespace SecureFileShareP2P.Cryptography
{
    public static class AESCrypto
    {
        private const int BlockSize = 16; // AES block size (128 bits)
        private const int KeySize = 32;   // AES-256 key size (32 bytes)
        private const int Rounds = 14;    // AES-256 rounds

        // S-box and inverse S-box (same as your provided tables)
        private static readonly byte[] SBox = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

        private static readonly byte[] InvSBox = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

        // Round constants
        private static readonly byte[] Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };


        private static byte[] KeyExpansion(byte[] key)
        {
            byte[] expandedKey = new byte[BlockSize * (Rounds + 1)];
            Array.Copy(key, expandedKey, KeySize);

            for (int i = KeySize / 4; i < 4 * (Rounds + 1); i++)
            {
                byte[] temp = new byte[4];
                Array.Copy(expandedKey, (i - 1) * 4, temp, 0, 4);

                if (i % (KeySize / 4) == 0)
                {
                    // Rotate + SubWord + Rcon
                    temp = SubWord(RotWord(temp));
                    temp[0] ^= Rcon[i / (KeySize / 4) - 1];
                }
                else if (KeySize > 24 && i % (KeySize / 4) == 4)
                {
                    temp = SubWord(temp);
                }

                for (int j = 0; j < 4; j++)
                    expandedKey[i * 4 + j] = (byte)(expandedKey[(i - KeySize / 4) * 4 + j] ^ temp[j]);
            }

            return expandedKey;
        }

        private static byte[] SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++)
                word[i] = SBox[word[i]];
            return word;
        }

        private static byte[] RotWord(byte[] word)
        {
            byte tmp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = tmp;
            return word;
        }


        private static void SubBytes(byte[] state)
        {
            for (int i = 0; i < BlockSize; i++)
                state[i] = SBox[state[i]];
        }
        private static void ShiftRows(byte[] state)
        {
            // Row 0: No shift
            // Row 1: Left shift 1
            byte temp = state[1];
            state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;

            // Row 2: Left shift 2
            Swap(ref state[2], ref state[10]);
            Swap(ref state[6], ref state[14]);

            // Row 3: Left shift 3
            temp = state[15];
            state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
        }

        private static void MixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte s0 = state[i * 4];
                byte s1 = state[i * 4 + 1];
                byte s2 = state[i * 4 + 2];
                byte s3 = state[i * 4 + 3];

                state[i * 4] = (byte)(GFMul(s0, 2) ^ GFMul(s1, 3) ^ s2 ^ s3);
                state[i * 4 + 1] = (byte)(s0 ^ GFMul(s1, 2) ^ GFMul(s2, 3) ^ s3);
                state[i * 4 + 2] = (byte)(s0 ^ s1 ^ GFMul(s2, 2) ^ GFMul(s3, 3));
                state[i * 4 + 3] = (byte)(GFMul(s0, 3) ^ s1 ^ s2 ^ GFMul(s3, 2));
            }
        }

        private static byte GFMul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0) p ^= a;
                bool hi = (a & 0x80) != 0;
                a <<= 1;
                if (hi) a ^= 0x1B; // AES irreducible polynomial
                b >>= 1;
            }
            return p;
        }

        private static void AddRoundKey(byte[] state, byte[] roundKey, int offset)
        {
            for (int i = 0; i < BlockSize; i++)
                state[i] ^= roundKey[offset + i];
        }

        public static byte[] EncryptBlock(byte[] input, byte[] expandedKey)
        {
            byte[] state = new byte[BlockSize];
            Array.Copy(input, state, BlockSize);

            // Initial round
            AddRoundKey(state, expandedKey, 0);

            // Main rounds
            for (int round = 1; round < Rounds; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, expandedKey, round * BlockSize);
            }

            // Final round (no MixColumns)
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, expandedKey, Rounds * BlockSize);

            return state;
        }
        private static void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < BlockSize; i++)
                state[i] = InvSBox[state[i]];
        }
        private static void InvShiftRows(byte[] state)
        {
            // Row 0: No shift
            // Row 1: Right shift 1
            byte temp = state[13];
            state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;

            // Row 2: Swap back
            Swap(ref state[2], ref state[10]);
            Swap(ref state[6], ref state[14]);

            // Row 3: Right shift 1 (or left shift 3)
            temp = state[3];
            state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
        }

        private static void InvMixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte s0 = state[i * 4];
                byte s1 = state[i * 4 + 1];
                byte s2 = state[i * 4 + 2];
                byte s3 = state[i * 4 + 3];

                state[i * 4] = (byte)(GFMul(s0, 0x0E) ^ GFMul(s1, 0x0B) ^ GFMul(s2, 0x0D) ^ GFMul(s3, 0x09));
                state[i * 4 + 1] = (byte)(GFMul(s0, 0x09) ^ GFMul(s1, 0x0E) ^ GFMul(s2, 0x0B) ^ GFMul(s3, 0x0D));
                state[i * 4 + 2] = (byte)(GFMul(s0, 0x0D) ^ GFMul(s1, 0x09) ^ GFMul(s2, 0x0E) ^ GFMul(s3, 0x0B));
                state[i * 4 + 3] = (byte)(GFMul(s0, 0x0B) ^ GFMul(s1, 0x0D) ^ GFMul(s2, 0x09) ^ GFMul(s3, 0x0E));
            }
        }
        public static byte[] DecryptBlock(byte[] input, byte[] expandedKey)
        {
            byte[] state = new byte[BlockSize];
            Array.Copy(input, state, BlockSize);

            // Initial round
            AddRoundKey(state, expandedKey, Rounds * BlockSize);

            // Main rounds
            for (int round = Rounds - 1; round >= 1; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, round * BlockSize);
                InvMixColumns(state);
            }

            // Final round (no InvMixColumns)
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey, 0);

            return state;
        }
        private static void Swap(ref byte a, ref byte b)
        {
            byte temp = a;
            a = b;
            b = temp;
        }

        private static byte[] PKCS7Pad(byte[] data)
        {
            int padding = BlockSize - (data.Length % BlockSize);
            byte[] padded = new byte[data.Length + padding];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)padding;
            return padded;
        }

        private static byte[] PKCS7Unpad(byte[] data)
        {
            int padding = data[data.Length - 1];
            byte[] unpadded = new byte[data.Length - padding];
            Array.Copy(data, unpadded, unpadded.Length);
            return unpadded;
        }
        public static (byte[] ciphertext, byte[] iv) Encrypt(byte[] plaintext, byte[] key)
        {
            byte[] iv = new byte[BlockSize];
            RandomNumberGenerator.Fill(iv);

            byte[] padded = PKCS7Pad(plaintext);
            byte[] expandedKey = KeyExpansion(key);
            byte[] ciphertext = new byte[padded.Length];

            byte[] previousBlock = iv;
            for (int i = 0; i < padded.Length; i += BlockSize)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(padded, i, block, 0, BlockSize);

                // CBC XOR
                for (int j = 0; j < BlockSize; j++)
                    block[j] ^= previousBlock[j];

                byte[] encrypted = EncryptBlock(block, expandedKey);
                Array.Copy(encrypted, 0, ciphertext, i, BlockSize);
                previousBlock = encrypted;
            }

            return (ciphertext, iv);
        }

        public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            byte[] expandedKey = KeyExpansion(key);
            byte[] decrypted = new byte[ciphertext.Length];

            byte[] previousBlock = iv;
            for (int i = 0; i < ciphertext.Length; i += BlockSize)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(ciphertext, i, block, 0, BlockSize);

                byte[] temp = new byte[BlockSize];
                Array.Copy(block, temp, BlockSize);

                byte[] decryptedBlock = DecryptBlock(block, expandedKey);

                // CBC XOR
                for (int j = 0; j < BlockSize; j++)
                    decryptedBlock[j] ^= previousBlock[j];

                Array.Copy(decryptedBlock, 0, decrypted, i, BlockSize);
                previousBlock = temp;
            }

            return PKCS7Unpad(decrypted);
        }
    }
}