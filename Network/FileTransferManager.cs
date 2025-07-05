// File: Network/FileTransferManager.cs

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
        // This delegate is not used in the final version, but can be kept for other uses
        public delegate void ProgressCallback(long bytesTransferred, long totalBytes);

        // Sender: Send file to another peer
        public static async Task SendFileAsync(
            string filePath,
            string receiverIP,
            int port,
            BigInteger rsaPublicKey,
            BigInteger rsaModulus,
            Action<long, long> progress = null) // Changed delegate type for simplicity
        {
            if (!File.Exists(filePath) || new FileInfo(filePath).Length == 0)
            {
                MessageBox.Show("Cannot send an empty or non-existent file.", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(receiverIP, port);
                using (NetworkStream stream = client.GetStream())
                {
                    // 1. Hybrid encrypt the file
                    var (encryptedFile, encryptedAesKey, iv) =
                        FileCryptoService.EncryptFileWithHybrid(filePath, rsaPublicKey, rsaModulus);

                    // 2. Send metadata (Filename)
                    byte[] fileNameBytes = Encoding.UTF8.GetBytes(Path.GetFileName(filePath));
                    await WriteChunkAsync(stream, fileNameBytes);

                    // 3. Send encrypted AES key
                    await WriteChunkAsync(stream, encryptedAesKey);

                    // 4. Send IV
                    await WriteChunkAsync(stream, iv);

                    // 5. Send encrypted file content
                    await stream.WriteAsync(encryptedFile, 0, encryptedFile.Length);
                    progress?.Invoke(encryptedFile.Length, encryptedFile.Length); // Final progress update
                }
            }
        }

        // Receiver: Start listening for incoming files
        //  vvv THIS IS THE CORRECTED LINE vvv
        public static async Task ReceiveFileAsync(int port, Action<string, string, string, string> onFileReceived, Action<string> onError)
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();

                while (true)
                {
                    using (TcpClient client = await listener.AcceptTcpClientAsync())
                    using (NetworkStream stream = client.GetStream())
                    {
                        // 1. Read metadata
                        string fileName = Encoding.UTF8.GetString(await ReadChunkAsync(stream));
                        byte[] encryptedAesKey = await ReadChunkAsync(stream);
                        byte[] iv = await ReadChunkAsync(stream);

                        // 2. Read the rest of the stream (the encrypted file content)
                        using (var ms = new MemoryStream())
                        {
                            await stream.CopyToAsync(ms);
                            byte[] encryptedFile = ms.ToArray();

                            // 3. Notify UI to handle decryption and saving
                            // We pass all necessary data to the UI thread.
                            onFileReceived?.Invoke(fileName, Convert.ToBase64String(encryptedFile), Convert.ToBase64String(encryptedAesKey), Convert.ToBase64String(iv));
                        }
                    }
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                onError?.Invoke($"Error: Port {port} is already in use. Please choose another port.");
            }
            catch (Exception ex)
            {
                onError?.Invoke($"Receiver error: {ex.Message}");
            }
            finally
            {
                listener?.Stop();
            }
        }

        // Helper to write a chunk with its length first
        private static async Task WriteChunkAsync(NetworkStream stream, byte[] data)
        {
            byte[] lengthPrefix = BitConverter.GetBytes(data.Length);
            await stream.WriteAsync(lengthPrefix, 0, lengthPrefix.Length);
            await stream.WriteAsync(data, 0, data.Length);
        }

        // Helper to read a chunk that is prefixed with its length
        private static async Task<byte[]> ReadChunkAsync(NetworkStream stream)
        {
            byte[] lengthBuffer = new byte[4];
            int bytesRead = 0;
            while (bytesRead < lengthBuffer.Length)
            {
                int read = await stream.ReadAsync(lengthBuffer, bytesRead, lengthBuffer.Length - bytesRead);
                if (read == 0) throw new EndOfStreamException("Incomplete data stream (length).");
                bytesRead += read;
            }

            int length = BitConverter.ToInt32(lengthBuffer, 0);
            byte[] dataBuffer = new byte[length];
            await stream.ReadExactlyAsync(dataBuffer, 0, length);
            return dataBuffer;
        }
    }
}