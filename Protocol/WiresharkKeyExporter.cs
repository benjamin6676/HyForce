using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace HyForce
{
    /// <summary>
    /// Exports keys in Wireshark-compatible format for verification
    /// </summary>
    public static class WiresharkKeyExporter
    {
        /// <summary>
        /// Converts various key log formats to standard Wireshark SSLKEYLOGFILE format
        /// </summary>
        public static void ExportForWireshark(string inputPath, string outputPath)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"Input file not found: {inputPath}");
                return;
            }

            var lines = File.ReadAllLines(inputPath);
            var outputLines = new List<string>();
            var seenEntries = new HashSet<string>();

            int clientCount = 0;
            int serverCount = 0;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                // Already in correct format
                if (trimmed.StartsWith("CLIENT_TRAFFIC_SECRET_0") ||
                    trimmed.StartsWith("SERVER_TRAFFIC_SECRET_0") ||
                    trimmed.StartsWith("CLIENT_EARLY_TRAFFIC_SECRET") ||
                    trimmed.StartsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET") ||
                    trimmed.StartsWith("SERVER_HANDSHAKE_TRAFFIC_SECRET"))
                {
                    if (seenEntries.Add(trimmed)) // Avoid duplicates
                    {
                        outputLines.Add(trimmed);

                        if (trimmed.StartsWith("CLIENT_TRAFFIC_SECRET_0")) clientCount++;
                        if (trimmed.StartsWith("SERVER_TRAFFIC_SECRET_0")) serverCount++;
                    }
                    continue;
                }

                // Try to parse other formats
                // Format: <label> <client_random> <secret>
                var match = Regex.Match(trimmed, @"(\S+)\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (match.Success)
                {
                    var label = match.Groups[1].Value.ToUpper();
                    var clientRandom = match.Groups[2].Value.ToLower();
                    var secret = match.Groups[3].Value.ToLower();

                    // Map to standard labels
                    string standardLabel = label switch
                    {
                        var l when l.Contains("CLIENT") && l.Contains("TRAFFIC") => "CLIENT_TRAFFIC_SECRET_0",
                        var l when l.Contains("SERVER") && l.Contains("TRAFFIC") => "SERVER_TRAFFIC_SECRET_0",
                        var l when l.Contains("EARLY") => "CLIENT_EARLY_TRAFFIC_SECRET",
                        var l when l.Contains("HANDSHAKE") && l.Contains("CLIENT") => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                        var l when l.Contains("HANDSHAKE") && l.Contains("SERVER") => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                        _ => null
                    };

                    if (standardLabel != null)
                    {
                        var formattedLine = $"{standardLabel} {clientRandom} {secret}";
                        if (seenEntries.Add(formattedLine))
                        {
                            outputLines.Add(formattedLine);

                            if (standardLabel == "CLIENT_TRAFFIC_SECRET_0") clientCount++;
                            if (standardLabel == "SERVER_TRAFFIC_SECRET_0") serverCount++;
                        }
                    }
                }
            }

            File.WriteAllLines(outputPath, outputLines);

            Console.WriteLine($"Exported {outputLines.Count} unique entries to {outputPath}");
            Console.WriteLine($"  Client secrets: {clientCount}");
            Console.WriteLine($"  Server secrets: {serverCount}");
            Console.WriteLine($"  Complete pairs: {Math.Min(clientCount, serverCount)}");
        }

        /// <summary>
        /// Creates a minimal key log with only the most recent complete connection
        /// Useful for testing with a specific connection
        /// </summary>
        public static void ExportSingleConnection(string inputPath, string outputPath, string clientRandom = null)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"Input file not found: {inputPath}");
                return;
            }

            var lines = File.ReadAllLines(inputPath);
            var connections = new Dictionary<string, ConnectionData>();

            // Parse all connections
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                var clientMatch = Regex.Match(trimmed, @"CLIENT_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (clientMatch.Success)
                {
                    var cr = clientMatch.Groups[1].Value.ToLower();
                    if (!connections.ContainsKey(cr))
                        connections[cr] = new ConnectionData { ClientRandom = cr };
                    connections[cr].ClientSecret = clientMatch.Groups[2].Value.ToLower();
                    continue;
                }

                var serverMatch = Regex.Match(trimmed, @"SERVER_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (serverMatch.Success)
                {
                    var cr = serverMatch.Groups[1].Value.ToLower();
                    if (!connections.ContainsKey(cr))
                        connections[cr] = new ConnectionData { ClientRandom = cr };
                    connections[cr].ServerSecret = serverMatch.Groups[2].Value.ToLower();
                }
            }

            // Find target connection
            ConnectionData target;

            if (clientRandom != null)
            {
                clientRandom = clientRandom.ToLower();
                if (!connections.ContainsKey(clientRandom))
                {
                    Console.WriteLine($"Connection {clientRandom} not found");
                    return;
                }
                target = connections[clientRandom];
            }
            else
            {
                // Find most recent complete connection
                target = connections.Values
                    .Where(c => c.IsComplete)
                    .OrderByDescending(c => c.ClientRandom) // Assuming later randoms = later connections
                    .FirstOrDefault();

                if (target == null)
                {
                    Console.WriteLine("No complete connections found");
                    return;
                }
            }

            // Export single connection
            var output = new List<string>();
            if (target.ClientSecret != null)
                output.Add($"CLIENT_TRAFFIC_SECRET_0 {target.ClientRandom} {target.ClientSecret}");
            if (target.ServerSecret != null)
                output.Add($"SERVER_TRAFFIC_SECRET_0 {target.ClientRandom} {target.ServerSecret}");

            File.WriteAllLines(outputPath, output);

            Console.WriteLine($"Exported single connection to {outputPath}");
            Console.WriteLine($"  Client Random: {target.ClientRandom}");
            Console.WriteLine($"  Client Secret: {target.ClientSecret?.Substring(0, 32)}...");
            Console.WriteLine($"  Server Secret: {target.ServerSecret?.Substring(0, 32)}...");
        }

        /// <summary>
        /// Lists all connections in the key log
        /// </summary>
        public static void ListConnections(string inputPath)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"Input file not found: {inputPath}");
                return;
            }

            var lines = File.ReadAllLines(inputPath);
            var connections = new Dictionary<string, ConnectionData>();

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                var clientMatch = Regex.Match(trimmed, @"CLIENT_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (clientMatch.Success)
                {
                    var cr = clientMatch.Groups[1].Value.ToLower();
                    if (!connections.ContainsKey(cr))
                        connections[cr] = new ConnectionData { ClientRandom = cr };
                    connections[cr].ClientSecret = clientMatch.Groups[2].Value.ToLower();
                    continue;
                }

                var serverMatch = Regex.Match(trimmed, @"SERVER_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (serverMatch.Success)
                {
                    var cr = serverMatch.Groups[1].Value.ToLower();
                    if (!connections.ContainsKey(cr))
                        connections[cr] = new ConnectionData { ClientRandom = cr };
                    connections[cr].ServerSecret = serverMatch.Groups[2].Value.ToLower();
                }
            }

            Console.WriteLine($"Found {connections.Count} connections:");
            Console.WriteLine();
            Console.WriteLine(string.Format("{0,-20} {1,-10} {2}", "Client Random", "Status", "Secret Length"));
            Console.WriteLine(new string('-', 60));

            foreach (var conn in connections.Values.OrderBy(c => c.ClientRandom))
            {
                var status = conn.IsComplete ? "Complete" : "Partial";
                var len = conn.ClientSecret?.Length / 2 ?? 0;
                Console.WriteLine(string.Format("{0}...{1}  {2,-10} {3} bytes",
                    conn.ClientRandom.Substring(0, 16),
                    conn.ClientRandom.Substring(48),
                    status,
                    len));
            }
        }

        private class ConnectionData
        {
            public string ClientRandom { get; set; }
            public string ClientSecret { get; set; }
            public string ServerSecret { get; set; }
            public bool IsComplete => ClientSecret != null && ServerSecret != null;
        }
    }
}