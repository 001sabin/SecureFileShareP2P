using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFileShareP2P.Network
{
    public static class PeerDiscovery
    {
        private const int DiscoveryPort = 12345;  // Shared port for discovery
        private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

        // Broadcast "I'm here!" to the local network
        public static async Task BroadcastPresenceAsync(string myUsername,int myPort, CancellationToken ct)
        {
            using (var udpClient = new UdpClient())
            {
                udpClient.EnableBroadcast = true;
                //byte[] message = Encoding.UTF8.GetBytes($"DISCOVER:{myUsername}");
                byte[] message = Encoding.UTF8.GetBytes($"DISCOVER:{myUsername}:{myPort}");
                while (!ct.IsCancellationRequested)
                {
                    await udpClient.SendAsync(message, message.Length,
                        new IPEndPoint(IPAddress.Broadcast, DiscoveryPort));
                    await Task.Delay(2000, ct);  // Broadcast every 2 seconds
                }
            }
        }

        // Listen for other peers broadcasting their presence
        public static async Task<List<DiscoveredPeer>> DiscoverPeersAsync(CancellationToken ct)
        {
            var peers = new List<DiscoveredPeer>();
            using (var udpClient = new UdpClient(DiscoveryPort))
            {
                udpClient.EnableBroadcast = true;
                var startTime = DateTime.UtcNow;

                while (DateTime.UtcNow - startTime < DiscoveryTimeout && !ct.IsCancellationRequested)
                {
                    var result = await udpClient.ReceiveAsync(ct);
                    string message = Encoding.UTF8.GetString(result.Buffer);

                    //if (message.StartsWith("DISCOVER:"))
                    //{
                    //    peers.Add(new DiscoveredPeer
                    //    {
                    //        Username = message.Substring(9),
                    //        IP = result.RemoteEndPoint.Address.ToString()
                    //    });
                    //}
                    if (message.StartsWith("DISCOVER:"))
                    {
                        //var parts = message.Split(':');
                        //peers.Add(new DiscoveredPeer
                        //{
                        //    Username = parts[1],
                        //    IP = result.RemoteEndPoint.Address.ToString(),
                        //    Port = int.Parse(parts[2])  // Added port
                        //});
                        var parts = message.Split(':');
                        if (parts.Length >= 3 && int.TryParse(parts[2], out int peerPort))
                        {
                            peers.Add(new DiscoveredPeer
                            {
                                Username = parts[1],
                                IP = result.RemoteEndPoint.Address.ToString(),
                                Port = peerPort  // Store the port from the message
                            });
                        }
                    }
                }
            }
            return peers;
        }
    }

    public class DiscoveredPeer
    {
        public string Username { get; set; }
        public string IP { get; set; }
        public int Port { get; set; }
    }
}