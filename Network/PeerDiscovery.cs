using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
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
        //public static async Task BroadcastPresenceAsync(string myUsername,int myPort, CancellationToken ct)
        //{
        //    using (var udpClient = new UdpClient())
        //    {
        //        udpClient.EnableBroadcast = true;
        //        //byte[] message = Encoding.UTF8.GetBytes($"DISCOVER:{myUsername}");
        //        byte[] message = Encoding.UTF8.GetBytes($"DISCOVER:{myUsername}:{myPort}");
        //        while (!ct.IsCancellationRequested)
        //        {
        //            await udpClient.SendAsync(message, message.Length,
        //                new IPEndPoint(IPAddress.Broadcast, DiscoveryPort));
        //            await Task.Delay(2000, ct);  // Broadcast every 2 seconds
        //        }
        //    }
        //}

        // Modify BroadcastPresenceAsync
        public static async Task BroadcastPresenceAsync(string myUsername, int myPort,
            BigInteger rsaModulus, BigInteger rsaPublicKey, CancellationToken ct) // <-- Add key parameters
        {
            using (var udpClient = new UdpClient())
            {
                udpClient.EnableBroadcast = true;

                // Convert keys to Base64 strings
                string modulusBase64 = Convert.ToBase64String(rsaModulus.ToByteArray());
                string exponentBase64 = Convert.ToBase64String(rsaPublicKey.ToByteArray());

                // Construct the new message format
                string messageString = $"DISCOVER:{myUsername}:{myPort}:{modulusBase64}:{exponentBase64}";
                byte[] message = Encoding.UTF8.GetBytes(messageString);

                while (!ct.IsCancellationRequested)
                {
                    await udpClient.SendAsync(message, message.Length,
                        new IPEndPoint(IPAddress.Broadcast, DiscoveryPort));
                    await Task.Delay(2000, ct);
                }
            }
        }

        // Listen for other peers broadcasting their presence
        //    public static async Task<List<DiscoveredPeer>> DiscoverPeersAsync(CancellationToken ct)
        //    {
        //        var peers = new List<DiscoveredPeer>();
        //        using (var udpClient = new UdpClient(DiscoveryPort))
        //        {
        //            udpClient.EnableBroadcast = true;
        //            var startTime = DateTime.UtcNow;

        //            while (DateTime.UtcNow - startTime < DiscoveryTimeout && !ct.IsCancellationRequested)
        //            {
        //                var result = await udpClient.ReceiveAsync(ct);
        //                string message = Encoding.UTF8.GetString(result.Buffer);

        //                //if (message.StartsWith("DISCOVER:"))
        //                //{
        //                //    peers.Add(new DiscoveredPeer
        //                //    {
        //                //        Username = message.Substring(9),
        //                //        IP = result.RemoteEndPoint.Address.ToString()
        //                //    });
        //                //}
        //                if (message.StartsWith("DISCOVER:"))
        //                {
        //                    //var parts = message.Split(':');
        //                    //peers.Add(new DiscoveredPeer
        //                    //{
        //                    //    Username = parts[1],
        //                    //    IP = result.RemoteEndPoint.Address.ToString(),
        //                    //    Port = int.Parse(parts[2])  // Added port
        //                    //});
        //                    var parts = message.Split(':');
        //                    if (parts.Length >= 3 && int.TryParse(parts[2], out int peerPort))
        //                    {
        //                        peers.Add(new DiscoveredPeer
        //                        {
        //                            Username = parts[1],
        //                            IP = result.RemoteEndPoint.Address.ToString(),
        //                            Port = peerPort  // Store the port from the message
        //                        });
        //                    }
        //                }
        //            }
        //        }
        //        return peers;
        //    }
        // Modify DiscoverPeersAsync
        public static async Task<List<DiscoveredPeer>> DiscoverPeersAsync(CancellationToken ct)
        {
            var peers = new List<DiscoveredPeer>();
            var discoveredEndpoints = new HashSet<string>(); // To avoid duplicates

            using (var udpClient = new UdpClient(DiscoveryPort))
            {
                udpClient.EnableBroadcast = true;
                var startTime = DateTime.UtcNow;

                while (DateTime.UtcNow - startTime < DiscoveryTimeout && !ct.IsCancellationRequested)
                {
                    if (udpClient.Available == 0)
                    {
                        await Task.Delay(100, ct); // Avoid busy-waiting
                        continue;
                    }

                    var result = await udpClient.ReceiveAsync(ct);
                    string message = Encoding.UTF8.GetString(result.Buffer);

                    if (message.StartsWith("DISCOVER:"))
                    {
                        var parts = message.Split(':');
                        // New format has 5 parts: DISCOVER, User, Port, Modulus, Exponent
                        if (parts.Length >= 5 && int.TryParse(parts[2], out int peerPort))
                        {
                            string peerIp = result.RemoteEndPoint.Address.ToString();
                            string endpointIdentifier = $"{peerIp}:{peerPort}";

                            if (discoveredEndpoints.Contains(endpointIdentifier)) continue; // Skip duplicate

                            try
                            {
                                // Decode keys from Base64
                                var modulus = new BigInteger(Convert.FromBase64String(parts[3]));
                                var exponent = new BigInteger(Convert.FromBase64String(parts[4]));

                                peers.Add(new DiscoveredPeer
                                {
                                    Username = parts[1],
                                    IP = peerIp,
                                    Port = peerPort,
                                    RsaModulus = modulus,
                                    RsaPublicKey = exponent
                                });
                                discoveredEndpoints.Add(endpointIdentifier);
                            }
                            catch (FormatException)
                            {
                                // Ignore malformed broadcast packet
                            }
                        }
                    }
                }
            }
            return peers.DistinctBy(p => p.IP + ":" + p.Port).ToList(); // Final duplicate check
        }
    }

    public class DiscoveredPeer
    {
        public string Username { get; set; }
        public string IP { get; set; }
        public int Port { get; set; }
        public BigInteger RsaModulus { get; set; }  // <-- ADD THIS
        public BigInteger RsaPublicKey { get; set; } // <-- ADD THIS
    }
}