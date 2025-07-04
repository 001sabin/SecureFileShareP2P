//using SecureFileShareP2P.Cryptography;
//using System;
//using System.IO;
//using System.Numerics;
//using System.Security.Cryptography;
//using SecureFileShareP2P.Models;
//namespace SecureFileShareP2P.Services
//{
//    public static class FileCryptoService
//    {
//        public static (byte[] encryptedFile, byte[] encryptedAesKey, byte[] iv)
//            EncryptFileWithHybrid(string filePath, BigInteger rsaPublicKey, BigInteger rsaModulus)
//        {
//            // Step 1: Generate random AES-256 key
//            byte[] aesKey = new byte[32];
//            RandomNumberGenerator.Fill(aesKey);

//            // Step 2: Encrypt file with AES
//            var (encryptedFile, iv) = AESCrypto.Encrypt(File.ReadAllBytes(filePath), aesKey);



//            // Step 3: Encrypt AES key with RSA
//            byte[] encryptedAesKey = RSACrypto.Encrypt(aesKey, rsaModulus, rsaPublicKey);

//            return (encryptedFile, encryptedAesKey, iv);
//        }

//        public static void DecryptFileWithHybrid(
//            byte[] encryptedFile,
//            byte[] encryptedAesKey,
//            byte[] iv,
//            BigInteger rsaPrivateKey,
//            BigInteger rsaModulus,
//            string outputPath)
//        {
//            // Step 1: Decrypt AES key with RSA
//            byte[] aesKey = RSACrypto.Decrypt(encryptedAesKey, rsaModulus, rsaPrivateKey);

//            // Step 2: Decrypt file with AES
//            byte[] decryptedData = AESCrypto.Decrypt(encryptedFile, aesKey, iv);

//            File.WriteAllBytes(outputPath, decryptedData);
//        }
//    }
//}

using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SecureFileShareP2P.Cryptography;

namespace SecureFileShareP2P.Services
{
    public static class FileCryptoService
    {
        public static (byte[] encryptedFile, byte[] encryptedAesKey, byte[] iv)
            EncryptFileWithHybrid(string filePath, BigInteger rsaPublicKey, BigInteger rsaModulus)
        {
            // Step 1: Generate random AES-256 key
            byte[] aesKey = new byte[32];
            RandomNumberGenerator.Fill(aesKey);

            // Step 2: Encrypt file with AES
            var (encryptedFile, iv) = AESCrypto.Encrypt(File.ReadAllBytes(filePath), aesKey);

            // Step 3: Convert AES key to Base64 string for RSA encryption
            string aesKeyBase64 = Convert.ToBase64String(aesKey);
            string encryptedAesKeyBase64 = RSACrypto.Encrypt(aesKeyBase64, rsaModulus, rsaPublicKey);

            // Convert back to byte[] for network transfer
            byte[] encryptedAesKey = Convert.FromBase64String(encryptedAesKeyBase64);

            return (encryptedFile, encryptedAesKey, iv);
        }

        public static void DecryptFileWithHybrid(
            byte[] encryptedFile,
            byte[] encryptedAesKey,
            byte[] iv,
            BigInteger rsaPrivateKey,
            BigInteger rsaModulus,
            string outputPath)
        {
            // Step 1: Convert encrypted AES key to Base64 string for RSA decryption
            string encryptedAesKeyBase64 = Convert.ToBase64String(encryptedAesKey);
            string aesKeyBase64 = RSACrypto.Decrypt(encryptedAesKeyBase64, rsaModulus, rsaPrivateKey);

            // Step 2: Decrypt AES key
            byte[] aesKey = Convert.FromBase64String(aesKeyBase64);

            // Step 3: Decrypt file with AES
            byte[] decryptedData = AESCrypto.Decrypt(encryptedFile, aesKey, iv);
            File.WriteAllBytes(outputPath, decryptedData);
        }
    }
}