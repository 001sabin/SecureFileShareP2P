using SecureFileShareP2P.Cryptography;
using System.Numerics;
using System.Windows;

namespace SecureFileShareP2P.Views
{
    public partial class RSATestWindow : Window
    {
        private BigInteger _n, _e, _d; // Store RSA keys
        private string _encryptedText;

        public RSATestWindow()
        {
            InitializeComponent();
        }

        // 1. Generate RSA Keys
        private void GenerateKeysButton_Click(object sender, RoutedEventArgs e)
        {
            (_n, _e, _d) = RSAKeyGenerator.GenerateKeys(512);
            ResultText.Text = $"Keys generated:\nn={_n}\ne={_e}\nd={_d}";
        }

        // 2. Encrypt with public key (n, e)
        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (_n == 0 || _e == 0)
            {
                MessageBox.Show("Generate keys first!");
                return;
            }
            _encryptedText = RSACrypto.Encrypt(InputTextBox.Text, _n, _e);
            ResultText.Text = $"Encrypted:\n{_encryptedText}";
        }

        // 3. Decrypt with private key (n, d)
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_encryptedText))
            {
                MessageBox.Show("Encrypt text first!");
                return;
            }
            string decrypted = RSACrypto.Decrypt(_encryptedText, _n, _d);
            ResultText.Text += $"\nDecrypted:\n{decrypted}";
        }
    }
}