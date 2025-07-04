using System.Configuration;
using System.Data;
using System.Windows;
using SecureFileShareP2P.Database;

namespace SecureFileShareP2P
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Initialize the database
            DatabaseHelper.Initialize(); 
            // Creates DB if it doesn't exist

            // Optional: Debug check
           // MessageBox.Show("Database initialized!", "Success",
                       //    MessageBoxButton.OK, MessageBoxImage.Information);

            // Skip login for testing (comment this out later)
            //var mainWindow = new MainWindow();
            //mainWindow.Show();

            // Uncomment this later when auth is ready:
            // var loginWindow = new LoginWindow();
            // loginWindow.Show();
        }
    }

}
