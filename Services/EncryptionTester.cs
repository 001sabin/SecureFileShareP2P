using SecureFileShareP2P.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;

namespace SecureFileShareP2P.Services
{
    public static class EncryptionTester
    {
        public static void TestHybridEncryption()
        {
            // 1. Generate RSA Keys
            var (n, e, d) = RSAKeyGenerator.GenerateKeys(bitLength: 512); // Smaller for testing

            // 2. Create a test file
            string testFilePath = "test_file.txt";
            File.WriteAllText(testFilePath, "This is a secret message!");

            // 3. Encrypt with Hybrid (RSA + AES)
            var (encryptedFile, encryptedAesKey, iv) =
                FileCryptoService.EncryptFileWithHybrid(testFilePath, e, n);

            // 4. Decrypt
            string outputPath = "decrypted_file.txt";
            FileCryptoService.DecryptFileWithHybrid(
                encryptedFile,
                encryptedAesKey,
                iv,
                d,
                n,
                outputPath
            );

            // 5. Verify
            string originalText = File.ReadAllText(testFilePath);
            string decryptedText = File.ReadAllText(outputPath);

            Console.WriteLine($"Original: {originalText}");
            Console.WriteLine($"Decrypted: {decryptedText}");
            Console.WriteLine($"Match: {originalText == decryptedText}");

            // Cleanup
            File.Delete(testFilePath);
            File.Delete(outputPath);
        }
    }
}