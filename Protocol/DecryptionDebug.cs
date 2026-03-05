using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HyForce
{
    /// <summary>
    /// Comprehensive debug logging for decryption
    /// </summary>
    public static class DecryptionDebug
    {
        private static List<DebugEntry> _entries = new();
        private static int _maxEntries = 10000;
        private static readonly object _lock = new object();

        public enum DebugLevel
        {
            Verbose,    // Everything
            Debug,      // Detailed
            Info,       // Normal
            Warning,    // Issues
            Error       // Failures only
        }

        public class DebugEntry
        {
            public DateTime Timestamp { get; set; }
            public DebugLevel Level { get; set; }
            public string Category { get; set; }
            public string Message { get; set; }
            public byte[] Data { get; set; }
        }

        public static DebugLevel CurrentLevel { get; set; } = DebugLevel.Verbose;
        public static bool LogToFile { get; set; } = true;
        public static string LogFilePath { get; set; } = "decryption_debug.log";

        public static void Log(string message, DebugLevel level = DebugLevel.Info, string category = "GENERAL", byte[] data = null)
        {
            if (level < CurrentLevel) return;

            lock (_lock)
            {
                var entry = new DebugEntry
                {
                    Timestamp = DateTime.Now,
                    Level = level,
                    Category = category,
                    Message = message,
                    Data = data
                };

                _entries.Add(entry);

                while (_entries.Count > _maxEntries)
                    _entries.RemoveAt(0);

                // Console output
                var color = level switch
                {
                    DebugLevel.Error => ConsoleColor.Red,
                    DebugLevel.Warning => ConsoleColor.Yellow,
                    DebugLevel.Info => ConsoleColor.White,
                    DebugLevel.Debug => ConsoleColor.Gray,
                    DebugLevel.Verbose => ConsoleColor.DarkGray,
                    _ => ConsoleColor.White
                };

                Console.ForegroundColor = color;
                Console.WriteLine($"[{entry.Timestamp:HH:mm:ss.fff}] [{level,8}] [{category,12}] {message}");
                Console.ResetColor();

                // File output
                if (LogToFile)
                {
                    try
                    {
                        File.AppendAllText(LogFilePath, $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{level,8}] [{category,12}] {message}\n");
                    }
                    catch { }
                }
            }
        }

        public static void LogVerbose(string message, string category = "GENERAL") => Log(message, DebugLevel.Verbose, category);
        public static void LogDebug(string message, string category = "GENERAL") => Log(message, DebugLevel.Debug, category);
        public static void LogInfo(string message, string category = "GENERAL") => Log(message, DebugLevel.Info, category);
        public static void LogWarning(string message, string category = "GENERAL") => Log(message, DebugLevel.Warning, category);
        public static void LogError(string message, string category = "GENERAL") => Log(message, DebugLevel.Error, category);

        public static void LogPacket(string direction, byte[] packet, string category = "PACKET")
        {
            if (packet == null || packet.Length == 0)
            {
                Log($"[{direction}] Empty/null packet", DebugLevel.Warning, category);
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"[{direction}] Packet: {packet.Length} bytes");
            sb.AppendLine($"  First byte: 0x{packet[0]:X2} ({GetHeaderType(packet[0])})");

            if (packet.Length >= 5)
            {
                uint version = (uint)((packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4]);
                sb.AppendLine($"  Version: 0x{version:X8} ({GetVersionName(version)})");
            }

            sb.AppendLine($"  Hex (first 32): {BitConverter.ToString(packet.Take(Math.Min(32, packet.Length)).ToArray()).Replace("-", " ")}");

            double entropy = CalculateEntropy(packet);
            sb.AppendLine($"  Entropy: {entropy:F2} ({(entropy > 6.5 ? "likely encrypted" : "possibly plaintext")})");

            Log(sb.ToString(), DebugLevel.Verbose, category, packet);
        }

        public static void LogKey(string source, byte[] secret, string category = "KEY")
        {
            if (secret == null)
            {
                Log($"[{source}] Null secret", DebugLevel.Error, category);
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"[{source}] Key added: {secret.Length} bytes");
            sb.AppendLine($"  Hex: {BitConverter.ToString(secret.Take(Math.Min(16, secret.Length)).ToArray()).Replace("-", " ")}...");
            sb.AppendLine($"  Cipher: {(secret.Length == 48 ? "AES-256-GCM" : secret.Length == 32 ? "AES-128-GCM" : "Unknown")}");

            Log(sb.ToString(), DebugLevel.Info, category, secret);
        }

        public static void LogDecryptionAttempt(bool success, string details, byte[] packet = null, byte[] key = null)
        {
            var level = success ? DebugLevel.Info : DebugLevel.Debug;
            var sb = new StringBuilder();
            sb.AppendLine($"Decryption {(success ? "SUCCESS" : "FAILED")}: {details}");

            if (packet != null)
                sb.AppendLine($"  Packet: {packet.Length}b, First: 0x{packet[0]:X2}");
            if (key != null)
                sb.AppendLine($"  Key: {key.Length}b, First: {BitConverter.ToString(key.Take(8).ToArray()).Replace("-", "")}...");

            Log(sb.ToString(), level, "DECRYPT");
        }

        public static void LogConnection(string clientRandom, bool hasClientKey, bool hasServerKey, string category = "CONN")
        {
            var status = hasClientKey && hasServerKey ? "COMPLETE" : hasClientKey || hasServerKey ? "PARTIAL" : "EMPTY";
            Log($"Connection {clientRandom.Substring(0, 16)}... Status: {status} (Client: {hasClientKey}, Server: {hasServerKey})", DebugLevel.Debug, category);
        }

        public static List<DebugEntry> GetEntries(DebugLevel minLevel = DebugLevel.Verbose, string category = null, int count = 1000)
        {
            lock (_lock)
            {
                var query = _entries.Where(e => e.Level >= minLevel);
                if (category != null)
                    query = query.Where(e => e.Category == category);
                return query.TakeLast(count).ToList();
            }
        }

        public static string GetLogText(DebugLevel minLevel = DebugLevel.Verbose, int count = 1000)
        {
            lock (_lock)
            {
                var entries = GetEntries(minLevel, null, count);
                var sb = new StringBuilder();
                foreach (var e in entries)
                {
                    sb.AppendLine($"[{e.Timestamp:HH:mm:ss.fff}] [{e.Level,8}] [{e.Category,12}] {e.Message}");
                }
                return sb.ToString();
            }
        }

        public static void Clear()
        {
            lock (_lock)
            {
                _entries.Clear();
                Log("Debug log cleared", DebugLevel.Info, "SYSTEM");
            }
        }

        public static void ExportToFile(string path)
        {
            lock (_lock)
            {
                try
                {
                    File.WriteAllText(path, GetLogText(DebugLevel.Verbose, _entries.Count));
                    Log($"Exported {_entries.Count} entries to {path}", DebugLevel.Info, "SYSTEM");
                }
                catch (Exception ex)
                {
                    Log($"Export failed: {ex.Message}", DebugLevel.Error, "SYSTEM");
                }
            }
        }

        private static string GetHeaderType(byte firstByte)
        {
            if ((firstByte & 0x80) != 0) return "Long Header";
            return "Short Header";
        }

        private static string GetVersionName(uint version)
        {
            return version switch
            {
                0x00000001 => "QUICv1",
                0x709A50C4 => "QUICv2",
                0xFF00001D => "Draft-29",
                0x00000000 => "Version Negotiation",
                _ => $"Unknown (0x{version:X8})"
            };
        }

        private static double CalculateEntropy(byte[] data)
        {
            var frequencies = new Dictionary<byte, int>();
            foreach (var b in data)
            {
                if (!frequencies.ContainsKey(b)) frequencies[b] = 0;
                frequencies[b]++;
            }

            double entropy = 0;
            int length = data.Length;
            foreach (var freq in frequencies.Values)
            {
                double probability = (double)freq / length;
                if (probability > 0)
                    entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }
    }
}