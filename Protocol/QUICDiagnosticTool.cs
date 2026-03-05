using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Buffers.Binary;

namespace HyForce.Frontend.Tabs
{
    /// <summary>
    /// Comprehensive diagnostic tool for QUIC decryption issues
    /// </summary>
    public class QUICDiagnosticTool
    {
        private List<string> _diagnosticLog = new();
        private Dictionary<string, ConnectionInfo> _connections = new();
        
        public class ConnectionInfo
        {
            public string ClientRandom { get; set; }
            public byte[] ClientSecret { get; set; }
            public byte[] ServerSecret { get; set; }
            public List<string> Issues { get; set; } = new();
            public Dictionary<string, byte[]> DerivedKeys { get; set; } = new();
        }
        
        public class DiagnosticResult
        {
            public bool IsValid { get; set; }
            public List<string> Issues { get; set; } = new();
            public List<string> Recommendations { get; set; } = new();
        }
        
        /// <summary>
        /// Run full diagnostic on SSL key log and packet capture
        /// </summary>
        public DiagnosticResult RunFullDiagnostic(string sslKeyLogPath, byte[] samplePacket = null)
        {
            var result = new DiagnosticResult();
            _diagnosticLog.Clear();
            
            Log("=== QUIC Decryption Diagnostic Tool ===");
            Log($"Timestamp: {DateTime.Now}");
            Log("");
            
            // Step 1: Check SSL Key Log
            Log("STEP 1: Checking SSL Key Log...");
            if (!File.Exists(sslKeyLogPath))
            {
                result.Issues.Add("SSL Key Log file not found");
                Log("❌ FAIL: SSL Key Log file not found");
                return result;
            }
            
            var keyLogContent = File.ReadAllText(sslKeyLogPath);
            ParseSSLKeyLog(keyLogContent);
            
            Log($"Found {_connections.Count} unique connections");
            
            int completeConnections = _connections.Values.Count(c => c.ClientSecret != null && c.ServerSecret != null);
            Log($"Complete connections (both client & server secrets): {completeConnections}");
            
            if (completeConnections == 0)
            {
                result.Issues.Add("No complete connections found - need both CLIENT_TRAFFIC_SECRET_0 and SERVER_TRAFFIC_SECRET_0");
                Log("❌ FAIL: No complete connections");
            }
            else
            {
                Log("✓ PASS: Found complete connections");
            }
            
            // Step 2: Verify key derivation
            Log("");
            Log("STEP 2: Verifying Key Derivation...");
            foreach (var conn in _connections.Values.Where(c => c.ClientSecret != null))
            {
                TestKeyDerivation(conn);
            }
            
            // Step 3: Check for common issues
            Log("");
            Log("STEP 3: Checking for Common Issues...");
            CheckCommonIssues();
            
            // Step 4: Analyze sample packet if provided
            if (samplePacket != null)
            {
                Log("");
                Log("STEP 4: Analyzing Sample Packet...");
                AnalyzePacket(samplePacket);
            }
            
            // Step 5: Generate recommendations
            Log("");
            Log("STEP 5: Recommendations...");
            GenerateRecommendations(result);
            
            // Save diagnostic log
            string logPath = $"quic_diagnostic_{DateTime.Now:yyyyMMdd_HHmmss}.log";
            File.WriteAllLines(logPath, _diagnosticLog);
            Log($"");
            Log($"Diagnostic log saved to: {logPath}");
            
            result.IsValid = result.Issues.Count == 0;
            return result;
        }
        
        private void ParseSSLKeyLog(string content)
        {
            var lines = content.Split('\n');
            
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;
                
                // CLIENT_TRAFFIC_SECRET_0
                var clientMatch = Regex.Match(trimmed, @"CLIENT_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (clientMatch.Success)
                {
                    var clientRandom = clientMatch.Groups[1].Value.ToLower();
                    var secret = HexToBytes(clientMatch.Groups[2].Value);
                    
                    if (!_connections.ContainsKey(clientRandom))
                    {
                        _connections[clientRandom] = new ConnectionInfo { ClientRandom = clientRandom };
                    }
                    _connections[clientRandom].ClientSecret = secret;
                    continue;
                }
                
                // SERVER_TRAFFIC_SECRET_0
                var serverMatch = Regex.Match(trimmed, @"SERVER_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                if (serverMatch.Success)
                {
                    var clientRandom = serverMatch.Groups[1].Value.ToLower();
                    var secret = HexToBytes(serverMatch.Groups[2].Value);
                    
                    if (!_connections.ContainsKey(clientRandom))
                    {
                        _connections[clientRandom] = new ConnectionInfo { ClientRandom = clientRandom };
                    }
                    _connections[clientRandom].ServerSecret = secret;
                }
            }
        }
        
        private void TestKeyDerivation(ConnectionInfo conn)
        {
            Log($"Testing connection: {conn.ClientRandom.Substring(0, 16)}...");
            
            // Test all label formats
            var formats = new[] { "quic", "tls13 quic", "quicv2" };
            
            foreach (var format in formats)
            {
                try
                {
                    byte[] key = null, iv = null, hp = null;
                    
                    if (conn.ClientSecret != null)
                    {
                        key = HkdfExpandLabel(conn.ClientSecret, $"{format} key", 16, format.StartsWith("tls13") ? "" : "tls13 ");
                        iv = HkdfExpandLabel(conn.ClientSecret, $"{format} iv", 12, format.StartsWith("tls13") ? "" : "tls13 ");
                        hp = HkdfExpandLabel(conn.ClientSecret, $"{format} hp", 16, format.StartsWith("tls13") ? "" : "tls13 ");
                    }
                    
                    if (key != null)
                    {
                        conn.DerivedKeys[$"{format}_key"] = key;
                        Log($"  {format} key: {BytesToHex(key).Substring(0, 32)}...");
                    }
                }
                catch (Exception ex)
                {
                    Log($"  ❌ Error deriving {format} keys: {ex.Message}");
                }
            }
        }
        
        private void CheckCommonIssues()
        {
            // Issue 1: Check secret length
            foreach (var conn in _connections.Values)
            {
                if (conn.ClientSecret != null && conn.ClientSecret.Length != 32 && conn.ClientSecret.Length != 48)
                {
                    conn.Issues.Add($"Unusual client secret length: {conn.ClientSecret.Length} bytes (expected 32 or 48)");
                    Log($"⚠ WARNING: Connection {conn.ClientRandom.Substring(0, 16)}... has unusual secret length: {conn.ClientSecret.Length}");
                }
            }
            
            // Issue 2: Check for duplicate client randoms
            var randoms = _connections.Values.Select(c => c.ClientRandom).ToList();
            var duplicates = randoms.GroupBy(r => r).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            if (duplicates.Any())
            {
                Log($"⚠ WARNING: Found {duplicates.Count} duplicate client randoms - this may indicate key log corruption");
            }
            
            // Issue 3: Check if secrets look random (not all zeros or repeating)
            foreach (var conn in _connections.Values)
            {
                if (conn.ClientSecret != null)
                {
                    var uniqueBytes = conn.ClientSecret.Distinct().Count();
                    if (uniqueBytes < 10)
                    {
                        conn.Issues.Add("Secret has low entropy - may be invalid");
                        Log($"⚠ WARNING: Connection {conn.ClientRandom.Substring(0, 16)}... has low entropy secret");
                    }
                }
            }
            
            // Issue 4: Check cipher suite compatibility
            Log("");
            Log("Cipher Suite Analysis:");
            Log("  - AES-128-GCM requires 16-byte keys (32-byte secrets)");
            Log("  - AES-256-GCM requires 32-byte keys (48-byte secrets)");
            
            int aes128Count = _connections.Values.Count(c => c.ClientSecret?.Length == 32);
            int aes256Count = _connections.Values.Count(c => c.ClientSecret?.Length == 48);
            
            Log($"  AES-128-GCM compatible: {aes128Count} connections");
            Log($"  AES-256-GCM compatible: {aes256Count} connections");
        }
        
        private void AnalyzePacket(byte[] packet)
        {
            if (packet == null || packet.Length < 5)
            {
                Log("❌ Invalid packet (too short)");
                return;
            }
            
            Log($"Packet length: {packet.Length} bytes");
            Log($"First byte: 0x{packet[0]:X2}");
            
            bool isLongHeader = (packet[0] & 0x80) != 0;
            Log($"Header type: {(isLongHeader ? "Long" : "Short")}");
            
            if (isLongHeader && packet.Length >= 5)
            {
                uint version = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(1));
                Log($"Version: 0x{version:X8} ({GetVersionName(version)})");
                
                if (packet.Length >= 6)
                {
                    int dcidLen = packet[5];
                    Log($"DCID Length: {dcidLen}");
                    
                    if (dcidLen > 0 && packet.Length >= 6 + dcidLen)
                    {
                        var dcid = packet.Skip(6).Take(Math.Min(dcidLen, 8)).ToArray();
                        Log($"DCID (first 8 bytes): {BytesToHex(dcid)}");
                    }
                }
            }
            else if (!isLongHeader && packet.Length >= 2)
            {
                // Short header - try to extract DCID
                int dcidLen = Math.Min(packet.Length - 1, 8);
                var dcid = packet.Skip(1).Take(dcidLen).ToArray();
                Log($"DCID (first {dcidLen} bytes): {BytesToHex(dcid)}");
            }
            
            // Check if packet looks encrypted (not plaintext)
            double entropy = CalculateEntropy(packet);
            Log($"Packet entropy: {entropy:F2} (high = likely encrypted)");
        }
        
        private void GenerateRecommendations(DiagnosticResult result)
        {
            var recommendations = new List<string>();
            
            // Check if we have any complete connections
            int completeCount = _connections.Values.Count(c => c.ClientSecret != null && c.ServerSecret != null);
            
            if (completeCount == 0)
            {
                recommendations.Add("🔴 CRITICAL: Your SSL key log is missing either CLIENT_TRAFFIC_SECRET_0 or SERVER_TRAFFIC_SECRET_0 entries.");
                recommendations.Add("   Make sure your SSLKEYLOGFILE environment variable is set BEFORE starting Hytale.");
                recommendations.Add("   Both secrets are required for decryption.");
            }
            else if (completeCount < _connections.Values.Count(c => c.ClientSecret != null || c.ServerSecret != null) / 2)
            {
                recommendations.Add("🟡 WARNING: Many connections are incomplete. This may indicate:");
                recommendations.Add("   - The proxy started after some connections were established");
                recommendations.Add("   - Some handshakes failed or were incomplete");
            }
            
            // Check cipher compatibility
            int aes128Count = _connections.Values.Count(c => c.ClientSecret?.Length == 32);
            int aes256Count = _connections.Values.Count(c => c.ClientSecret?.Length == 48);
            
            if (aes256Count > 0 && aes128Count == 0)
            {
                recommendations.Add("🟡 INFO: Only AES-256-GCM secrets found. Make sure your decryption code uses 32-byte keys.");
            }
            
            // General recommendations
            recommendations.Add("");
            recommendations.Add("📋 General Recommendations:");
            recommendations.Add("1. Verify you're capturing packets from the same time period as the keys");
            recommendations.Add("2. Check if Hytale uses a non-standard QUIC implementation");
            recommendations.Add("3. Try capturing with Wireshark and use the same SSL key log to verify");
            recommendations.Add("4. Consider that Hytale may use additional encryption layers");
            
            // Wireshark export recommendation
            recommendations.Add("");
            recommendations.Add("🔧 For Wireshark Testing:");
            recommendations.Add("Export your SSL key log in Wireshark format and test decryption there.");
            recommendations.Add("If Wireshark can't decrypt, the issue is likely with the key log, not your code.");
            
            foreach (var rec in recommendations)
            {
                Log(rec);
            }
            
            result.Recommendations = recommendations;
        }
        
        private byte[] HkdfExpandLabel(byte[] secret, string label, int length, string prefix)
        {
            string fullLabel = string.IsNullOrEmpty(prefix) ? label : $"{prefix} {label}";
            byte[] labelBytes = Encoding.ASCII.GetBytes(fullLabel);
            byte[] hash = SHA256.HashData(Array.Empty<byte>());
            
            using var ms = new MemoryStream();
            ms.WriteByte((byte)(length >> 8));
            ms.WriteByte((byte)length);
            ms.WriteByte((byte)labelBytes.Length);
            ms.Write(labelBytes, 0, labelBytes.Length);
            ms.WriteByte(0);
            byte[] hkdfLabel = ms.ToArray();
            
            return HkdfExpand(secret, hash, hkdfLabel, length);
        }
        
        private byte[] HkdfExpand(byte[] prk, byte[] hash, byte[] info, int length)
        {
            using var hmac = new HMACSHA256();
            hmac.Key = prk;
            
            byte[] okm = new byte[length];
            byte[] t = Array.Empty<byte>();
            int iterations = (length + 31) / 32;
            
            for (int i = 1; i <= iterations; i++)
            {
                hmac.Initialize();
                if (t.Length > 0) hmac.TransformBlock(t, 0, t.Length, null, 0);
                hmac.TransformBlock(info, 0, info.Length, null, 0);
                hmac.TransformFinalBlock(new[] { (byte)i }, 0, 1);
                t = hmac.Hash;
                Buffer.BlockCopy(t, 0, okm, (i - 1) * 32, Math.Min(32, length - (i - 1) * 32));
            }
            
            return okm;
        }
        
        private double CalculateEntropy(byte[] data)
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
                entropy -= probability * Math.Log(probability, 2);
            }
            
            return entropy;
        }
        
        private string GetVersionName(uint version)
        {
            return version switch
            {
                0x00000000 => "Version Negotiation",
                0x00000001 => "QUICv1",
                0x6B3343CF => "QUICv2 draft",
                0x709A50C4 => "QUICv2 RFC",
                0xFF00001D => "Draft 29",
                0x45415401 => "Hytale?",
                _ => $"Unknown (0x{version:X8})"
            };
        }
        
        private void Log(string message)
        {
            _diagnosticLog.Add(message);
            Console.WriteLine(message);
        }
        
        private byte[] HexToBytes(string hex)
        {
            hex = hex.Trim();
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        
        private string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }
}
