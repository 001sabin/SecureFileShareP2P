using Microsoft.Win32;
using SecureFileShareP2P.Network;
using SecureFileShareP2P.Services;
using SecureFileShareP2P.Utils;
using System;
using System.IO;
using System.Numerics;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using SecureFileShareP2P.Cryptography;

namespace SecureFileShareP2P
{
    public partial class MainWindow : Window
    {
        private string _selectedFilePath;
        private BigInteger _rsaPublicKey, _rsaModulus, _rsaPrivateKey;
        private DiscoveredPeer _selectedPeer;

        // Threading control
        private CancellationTokenSource _broadcastCts;
        private CancellationTokenSource _discoveryCts;
        private Task _listenerTask;

        private readonly string _currentUser;

        // Constructor for login flow
        public MainWindow(string username)
        {
            InitializeComponent();
            _currentUser = username;
            InitializeApplication();
        }

        // Default constructor for testing (if needed)
        public MainWindow()
        {
            InitializeComponent();
            _currentUser = "TestUser (Default)";
            InitializeApplication();
        }

        private void InitializeApplication()
        {
            this.Title = $"Secure File Share P2P - Logged in as: {_currentUser}";
            try
            {
                ReceiverIPBox.Text = NetworkUtils.GetLocalIPAddress();
                ReceiverPortBox.Text = GetFreePort().ToString();
            }
            catch (Exception ex)
            {
                ReceiverIPBox.Text = "127.0.0.1";
                ReceiverPortBox.Text = "12345";
                StatusText.Text = $"Auto-config failed: {ex.Message}";
            }
            (_rsaModulus, _rsaPublicKey, _rsaPrivateKey) = RSAKeyGenerator.GenerateKeys();
            ResetUI_Click(null, null); // Set initial UI state
        }

        private static int GetFreePort()
        {
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                return ((IPEndPoint)socket.LocalEndPoint).Port;
            }
        }

        private void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _selectedFilePath = dialog.FileName;
                SelectedFileText.Text = $"Selected: {Path.GetFileName(_selectedFilePath)}";
            }
        }

        // **MODIFIED:** Receiver logic
        private void StartReceiver_Click(object sender, RoutedEventArgs e)
        {
            if (_listenerTask != null && !_listenerTask.IsCompleted)
            {
                StatusText.Text = "Listener is already running.";
                return;
            }

            int port;
            if (!int.TryParse(ReceiverPortBox.Text, out port))
            {
                StatusText.Text = "Invalid port number.";
                return;
            }

            StatusText.Text = $"Listening on port {port}...";
            StartReceiverButton.IsEnabled = false;

            Action<string, string, string, string> onFileReceived = (fileName, encryptedFileBase64, encryptedKeyBase64, ivBase64) =>
            {
                Dispatcher.Invoke(() =>
                {
                    var result = MessageBox.Show($"Incoming file: '{fileName}'. Do you want to accept and save it?", "File Transfer Request", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        try
                        {
                            byte[] encryptedFile = Convert.FromBase64String(encryptedFileBase64);
                            byte[] encryptedAesKey = Convert.FromBase64String(encryptedKeyBase64);
                            byte[] iv = Convert.FromBase64String(ivBase64);

                            SaveFileDialog saveDialog = new SaveFileDialog { FileName = fileName };

                            if (saveDialog.ShowDialog() == true)
                            {
                                FileCryptoService.DecryptFileWithHybrid(
                                    encryptedFile, encryptedAesKey, iv,
                                    _rsaPrivateKey, _rsaModulus,
                                    saveDialog.FileName
                                );
                                // **FIXED (Task 3):** Show success message on receiver side
                                MessageBox.Show($"File '{fileName}' saved and decrypted successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                                ResetUI_Click(null, null);
                            }
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Failed to decrypt or save file: {ex.Message}", "Decryption Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                });
            };

            Action<string> onError = (errorMessage) =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = errorMessage;
                    StartReceiverButton.IsEnabled = true;
                });
            };

            _listenerTask = Task.Run(() => FileTransferManager.ReceiveFileAsync(port, onFileReceived, onError));
        }

        private async void SendFile_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedFilePath))
            {
                MessageBox.Show("Select a file first!");
                return;
            }

            if (_selectedPeer == null)
            {
                MessageBox.Show("Please scan and select a peer from the list first!", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            TransferProgress.Value = 0;
            StatusText.Text = "Preparing to send...";

            try
            {
                await FileTransferManager.SendFileAsync(
                    _selectedFilePath, _selectedPeer.IP, _selectedPeer.Port,
                    _selectedPeer.RsaPublicKey, _selectedPeer.RsaModulus,
                    (bytesSent, totalBytes) =>
                    {
                        Dispatcher.Invoke(() =>
                        {
                            if (totalBytes > 0)
                            {
                                int percent = (int)((double)bytesSent / totalBytes * 100);
                                TransferProgress.Value = percent; // Progress is 0-100
                                StatusText.Text = $"Sending: {percent}%";
                            }
                        });
                    }
                );

                StatusText.Text = "File sent successfully!";
                MessageBox.Show("File sent successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                ResetUI_Click(null, null);
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show($"Error sending file: {ex.Message}", "Send Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ScanPeers_Click(object sender, RoutedEventArgs e)
        {
            _discoveryCts?.Cancel();
            _discoveryCts = new CancellationTokenSource();

            PeerList.ItemsSource = null; // Clear list immediately
            StatusText.Text = "Scanning for peers...";

            try
            {
                var peers = await PeerDiscovery.DiscoverPeersAsync(_discoveryCts.Token);
                // Exclude self from the list
                string myIP = NetworkUtils.GetLocalIPAddress();
                PeerList.ItemsSource = peers.Where(p => p.IP != myIP || p.Username != _currentUser).ToList();
                StatusText.Text = $"Found {PeerList.Items.Count} other peer(s)";
            }
            catch (OperationCanceledException) { StatusText.Text = "Scan cancelled"; }
            catch (Exception ex) { StatusText.Text = $"Scan failed: {ex.Message}"; }
        }

        // **MODIFIED:** Uses the real username
        private async void StartBroadcast_Click(object sender, RoutedEventArgs e)
        {
            _broadcastCts?.Cancel();
            _broadcastCts = new CancellationTokenSource();

            try
            {
                int myPort = int.Parse(ReceiverPortBox.Text);
                await PeerDiscovery.BroadcastPresenceAsync(
                    _currentUser, myPort,
                    _rsaModulus, _rsaPublicKey,
                    _broadcastCts.Token
                );
                StatusText.Text = $"Broadcasting as '{_currentUser}'...";
                StartBroadcastButton.IsEnabled = false; // Disable after starting
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Broadcast error: {ex.Message}";
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            // Clean up background tasks when window closes
            _discoveryCts?.Cancel();
            _broadcastCts?.Cancel();
            // Note: _listenerTask is harder to cancel cleanly, but this handles the others.
            base.OnClosed(e);
        }

        private void PeerList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PeerList.SelectedItem is DiscoveredPeer selectedPeer)
            {
                _selectedPeer = selectedPeer;
                ReceiverIPBox.Text = selectedPeer.IP;
                StatusText.Text = $"Selected peer: {selectedPeer.Username} ({selectedPeer.IP})";
            }
        }

        private void QuitButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        // **MODIFIED (Task 1):** True Reset logic
        private void ResetUI_Click(object sender, RoutedEventArgs e)
        {
            // Cancel any ongoing network operations
            _broadcastCts?.Cancel();
            _discoveryCts?.Cancel();
            // Note: the listener task continues running by design, but we can re-enable the button

            // Reset UI elements
            _selectedFilePath = null;
            _selectedPeer = null;
            SelectedFileText.Text = "No file selected.";

            PeerList.ItemsSource = null;
            PeerList.Items.Clear();

            StatusText.Text = "Ready. Select an action.";
            TransferProgress.Value = 0;
            ReceiverIPBox.Text = "Select a peer from the list";

            // Re-enable buttons
            StartReceiverButton.IsEnabled = true;
            StartBroadcastButton.IsEnabled = true;
        }
    }
}