using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using SecureFileShareP2P.Services;

namespace SecureFileShareP2P.Network
{
    public static class FileTransferManager
    {
        // Receiver: Start listening for incoming files
        public static async Task ReceiveFileAsync(int port, Action<string> onFileReceived)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            try { 
            listener.Start();

            while (true)
            {
                using (TcpClient client = await listener.AcceptTcpClientAsync())
                using (NetworkStream stream = client.GetStream())
                {
                    // Read metadata (file name, RSA-encrypted AES key, IV)
                    byte[] fileNameBytes = await ReadBytesAsync(stream, 4);
                    string fileName = Encoding.UTF8.GetString(fileNameBytes);

                    byte[] encryptedAesKey = await ReadBytesAsync(stream, 256); // RSA-encrypted
                    byte[] iv = await ReadBytesAsync(stream, 16); // AES IV

                    // Save to temp file
                    string tempPath = Path.GetTempFileName();
                    using (FileStream fs = File.Create(tempPath))
                    {
                        await stream.CopyToAsync(fs);
                    }

                    // Notify UI
                    onFileReceived?.Invoke(tempPath);
                }
            }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                throw new Exception($"Port {port} is already in use. Try another port.");
            }
        }

        // Sender: Send file to another peer
        public static async Task SendFileAsync(string filePath, string receiverIP, int port,
            BigInteger rsaPublicKey, BigInteger rsaModulus)
        {
            long fileSize = new FileInfo(filePath).Length;
            if (fileSize == 0)
            {
                MessageBox.Show("Cannot send an empty file.");
                return;
            }
            using (TcpClient client = new TcpClient(receiverIP, port))
            using (NetworkStream stream = client.GetStream())
            {
                // Hybrid encrypt the file
                var (encryptedFile, encryptedAesKey, iv) =
                    FileCryptoService.EncryptFileWithHybrid(filePath, rsaPublicKey, rsaModulus);

                // Send metadata
                byte[] fileNameBytes = Encoding.UTF8.GetBytes(Path.GetFileName(filePath));
                await WriteBytesAsync(stream, BitConverter.GetBytes(fileNameBytes.Length));
                await WriteBytesAsync(stream, fileNameBytes);
                await WriteBytesAsync(stream, encryptedAesKey);
                await WriteBytesAsync(stream, iv);

                // Send encrypted file
                await stream.WriteAsync(encryptedFile, 0, encryptedFile.Length);
            }
        }

        private static async Task<byte[]> ReadBytesAsync(NetworkStream stream, int length)
        {
            byte[] buffer = new byte[length];
            int bytesRead = 0;
            while (bytesRead < length)
            {
                bytesRead += await stream.ReadAsync(buffer, bytesRead, length - bytesRead);
            }
            return buffer;
        }

        private static async Task WriteBytesAsync(NetworkStream stream, byte[] data)
        {
            await stream.WriteAsync(data, 0, data.Length);
        }

        // Add this delegate for progress updates
        public delegate void ProgressCallback(int bytesTransferred, int totalBytes);

        // Update SendFileAsync to include progress
        public static async Task SendFileAsync(
            string filePath,
            string receiverIP,
            int port,
            BigInteger rsaPublicKey,
            BigInteger rsaModulus,
            ProgressCallback progress = null)  // <-- New parameter
        {
            using (TcpClient client = new TcpClient(receiverIP, port))
            using (NetworkStream stream = client.GetStream())
            {
                byte[] fileData = File.ReadAllBytes(filePath);
                var (encryptedFile, encryptedAesKey, iv) =
                    FileCryptoService.EncryptFileWithHybrid(filePath, rsaPublicKey, rsaModulus);

                // Send metadata (unchanged)
                await WriteBytesAsync(stream, BitConverter.GetBytes(encryptedFile.Length));
                await WriteBytesAsync(stream, encryptedAesKey);
                await WriteBytesAsync(stream, iv);

                // Send file with progress tracking
                int totalBytes = encryptedFile.Length;
                int bytesSent = 0;
                int chunkSize = 4096; // 4KB chunks

                while (bytesSent < totalBytes)
                {
                    int remaining = totalBytes - bytesSent;
                    int currentChunk = Math.Min(chunkSize, remaining);

                    await stream.WriteAsync(encryptedFile, bytesSent, currentChunk);
                    bytesSent += currentChunk;

                    // Safe progress reporting (handles zero division)
                    if (totalBytes > 0 && progress != null)
                    {
                        progress.Invoke(bytesSent, totalBytes);  // Reports raw bytes (0-100% calculated in UI)
                    }
                }
            }
        }
    }
}