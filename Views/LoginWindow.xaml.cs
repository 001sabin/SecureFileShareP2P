using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using SecureFileShareP2P.Services;
using SecureFileShareP2P.Models;
using SecureFileShareP2P.Cryptography;

namespace SecureFileShareP2P.Views
{
    /// <summary>
    /// Interaction logic for LoginWindow.xaml
    /// </summary>
    public partial class LoginWindow : Window
    {
        public LoginWindow()
        {
            InitializeComponent();
        }
        //private void LoginButton_Click(object sender, RoutedEventArgs e)
        //{
        //    // Your login logic will go here
        //    string username = UsernameTextBox.Text;
        //    string password = PasswordBox.Password;

        //    MessageBox.Show($"Login attempted for {username}");
        //}

        //private void RegisterButton_Click(object sender, RoutedEventArgs e)
        //{
        //    // Your registration logic will go here
        //    MessageBox.Show("Registration button clicked");
        //}
        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            if (AuthService.Login(UsernameTextBox.Text, PasswordBox.Password))
            {
                MessageBox.Show("Login successful!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                // Proceed to main window
                new MainWindow().Show();
                this.Close();
            }
            else
            {
                MessageBox.Show("Invalid credentials!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            if (AuthService.Register(UsernameTextBox.Text, PasswordBox.Password))
            {
                MessageBox.Show("Registration successful!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Username already exists!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        //yo tala ko function chae rsa test garna ko lagi matrai ho
        //private void TestRSAButton_Click(object sender, RoutedEventArgs e)
        //{
        //    new RSATestWindow().Show(); // Open the dedicated test window
        //}
      
    }
}
