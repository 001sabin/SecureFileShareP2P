using System.Numerics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
//using System.Windows.Shapes;
using Microsoft.Win32;
using SecureFileShareP2P.Cryptography;
using SecureFileShareP2P.Network;
using System.IO;
using System.Threading.Tasks;
using SecureFileShareP2P.Services;
using SecureFileShareP2P.Utils;
using System.Net.Sockets;
using System.Net;
namespace SecureFileShareP2P
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string _selectedFilePath;
        private BigInteger _rsaPublicKey, _rsaModulus, _rsaPrivateKey;

        public MainWindow()
        {
            InitializeComponent();
            // Auto-fill local IP and port
            try
            {
                ReceiverIPBox.Text = NetworkUtils.GetLocalIPAddress();  // Real IP (not 127.0.0.1)
                ReceiverPortBox.Text = GetFreePort().ToString();        // Random free port
            }
            catch (Exception ex)
            {
                ReceiverIPBox.Text = "127.0.0.1";  // Fallback
                ReceiverPortBox.Text = "12345";
                StatusText.Text = $"Auto-config failed: {ex.Message}";
            }


            // Initialize RSA keys (replace with your key generation logic)
            //(_rsaModulus, _rsaPublicKey, _rsaPrivateKey) = RSAKeyGenerator.GenerateKeys();
        }
        private static int GetFreePort()
        {
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                return ((IPEndPoint)socket.LocalEndPoint).Port;  // OS assigns free port
            }
        }
        // 1. File selection handler
        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _selectedFilePath = dialog.FileName;
                SelectedFileText.Text = $"Selected: {Path.GetFileName(_selectedFilePath)}";
            }
        }

        // 2. Start receiver (listen for incoming files)
        private async void StartReceiver_Click(object sender, RoutedEventArgs e)
        {
            int port = int.Parse(ReceiverPortBox.Text);
            await FileTransferManager.ReceiveFileAsync(port, tempFilePath =>
            {
                // This callback runs when a file is received
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"File saved to:\n{tempFilePath}", "Received Successfully!");
                });
            });
        }

        // 3. Send file to another peer
        //private async void SendFile_Click(object sender, RoutedEventArgs e)
        //{
        //    if (string.IsNullOrEmpty(_selectedFilePath))
        //    {
        //        MessageBox.Show("Please select a file first!", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        //        return;
        //    }

        //    try
        //    {
        //        string receiverIP = ReceiverIPBox.Text;
        //        int port = int.Parse(ReceiverPortBox.Text);

        //        await FileTransferManager.SendFileAsync(
        //            _selectedFilePath,
        //            receiverIP,
        //            port,
        //            _rsaPublicKey,
        //             _rsaModulus
        //    );

        //        MessageBox.Show("File sent successfully!", "Success");
        //    }
        //    catch (Exception ex)
        //    {
        //        MessageBox.Show($"Failed to send file: {ex.Message}", "Error");
        //    }
        //}
        private async void SendFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedFilePath))
            {
                MessageBox.Show("Select a file first!");
                return;
            }

            TransferProgress.Value = 0;
            StatusText.Text = "Preparing to send...";

            try
            {
                await FileTransferManager.SendFileAsync(
                    _selectedFilePath,
                    ReceiverIPBox.Text,
                    int.Parse(ReceiverPortBox.Text),
                    _rsaPublicKey,
                    _rsaModulus,
                    (bytesSent, totalBytes) =>
                    {
                        // Update UI on progress
                        Dispatcher.Invoke(() =>
                        {
                            TransferProgress.Maximum = totalBytes;
                            TransferProgress.Value = bytesSent;
                            //StatusText.Text = $"Sending: {bytesSent * 100 / totalBytes}%";
                            if (totalBytes > 0)
                            {
                                int percent = (int)((double)bytesSent / totalBytes * 100);
                                TransferProgress.Value = percent;
                                StatusText.Text = $"Sending: {percent}%";
                            }
                        });
                    }
                );

                StatusText.Text = "File sent successfully!";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
            }
        }
        // Add this to MainWindow.xaml.cs
        private void TestEncryption_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                EncryptionTester.TestHybridEncryption();
                MessageBox.Show("Encryption test succeeded! Check console output.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Test failed: {ex.Message}");
            }
        }

        //peer discovery logic 
        private CancellationTokenSource _discoveryCts;

        private async void ScanPeers_Click(object sender, RoutedEventArgs e)
        {
            _discoveryCts?.Cancel();  // Stop any existing scan
            _discoveryCts = new CancellationTokenSource();

            PeerList.Items.Clear();
            StatusText.Text = "Scanning for peers...";

            try
            {
                var peers = await PeerDiscovery.DiscoverPeersAsync(_discoveryCts.Token);
                PeerList.ItemsSource = peers;
                StatusText.Text = $"Found {peers.Count} peer(s)";
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Scan cancelled";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Scan failed: {ex.Message}";
            }
        }



        // 2. NEW: Add this method to start broadcasting your presence
        private CancellationTokenSource _broadcastCts;

        private async void StartBroadcast_Click(object sender, RoutedEventArgs e)
        {
            _broadcastCts?.Cancel();
            _broadcastCts = new CancellationTokenSource();

            try
            {
                int myPort = int.Parse(ReceiverPortBox.Text); // Get port from UI
                string myUsername = $"User_{myPort}"; // Unique username based on port
                await PeerDiscovery.BroadcastPresenceAsync(
                    myUsername, // Replace with actual username (e.g., from login)
                    myPort,         // Pass the current port
                    _broadcastCts.Token
                );
                StatusText.Text = "Broadcasting presence...";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Broadcast error: {ex.Message}";
            }
        }
        // Call this when the window closes
        protected override void OnClosed(EventArgs e)
        {
            _discoveryCts?.Cancel();
            _broadcastCts?.Cancel();
            base.OnClosed(e);
        }

        private void PeerList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PeerList.SelectedItem is DiscoveredPeer selectedPeer)
            {
                // Auto-fill both IP and port when a peer is selected
                ReceiverIPBox.Text = selectedPeer.IP;
                ReceiverPortBox.Text = selectedPeer.Port.ToString();
                StatusText.Text = $"Selected: {selectedPeer.Username}";

            }
        }

    }
}