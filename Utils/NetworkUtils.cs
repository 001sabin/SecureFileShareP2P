using System.Net;
using System.Net.Sockets;

namespace SecureFileShareP2P.Utils
{
    public static class NetworkUtils
    {
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with IPv4 address found!");
        }
    }
}