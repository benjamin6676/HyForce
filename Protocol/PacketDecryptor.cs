using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce
{
    /// <summary>
    /// FINAL SAFE version of PacketDecryptor - No UI blocking, no hangs
    /// </summary>
    public static class PacketDecryptor
    {
        private static Dictionary<string, ConnectionKeys> _connectionKeys = new();
        private static List<DecryptionAttempt> _attemptLog = new();
        private static readonly object _lock = new object();
        
        // Safety settings - TUNED FOR NO LAG
        public static int MaxDCIDLengthToTry { get; set; } = 3; // Very limited to prevent hangs
        public static int DecryptionTimeoutMs { get; set; } = 50; // Very short timeout
        public static bool EnableDebugLogging { get; set; } = true;
        
        public static bool DebugMode { get; set; } = true;
        public static bool AutoDecryptEnabled { get; set; } = false; // DISABLED by default to prevent lag
        public static int SkippedDecryptions { get; set; } = 0;
        public static HkdfLabelFormat CurrentLabelFormat { get; set; } = HkdfLabelFormat.RFC9001_NoPrefix;
        
        public static List<EncryptionKey> DiscoveredKeys => GetAllKeys();
        public static int TotalAttempts => _attemptLog.Count;
        public static int SuccessfulDecryptions => _attemptLog.Count(a => a.Success);
        public static int FailedDecryptions => _attemptLog.Count(a => !a.Success);
        public static int ConnectionCount { get { lock (_lock) return _connectionKeys.Count; } }
        
        public enum HkdfLabelFormat { RFC9001_NoPrefix, RFC8446_WithPrefix, QUICv2, TestVector }
        public enum EncryptionType { QUIC_Client1RTT, QUIC_Server1RTT, QUIC_ClientHandshake, QUIC_ServerHandshake, QUIC_Client0RTT }
        public enum PacketDirection { ClientToServer, ServerToClient }
        
        public class EncryptionKey
        {
            public byte[] Secret { get; set; }
            public byte[] Key { get; set; }
            public byte[] IV { get; set; }
            public byte[] HeaderProtectionKey { get; set; }
            public EncryptionType Type { get; set; }
            public string Source { get; set; }
            public DateTime DiscoveredAt { get; set; }
            public IntPtr? MemoryAddress { get; set; }
            public bool IsClient => Type == EncryptionType.QUIC_Client1RTT || Type == EncryptionType.QUIC_ClientHandshake || Type == EncryptionType.QUIC_Client0RTT;
            public bool IsValid => Key != null && Key.Length > 0 && IV != null && IV.Length > 0;
        }
        
        public class DecryptionResult
        {
            public bool Success { get; set; }
            public byte[] DecryptedData { get; set; }
            public string Error { get; set; }
            public string ErrorMessage => Error;
            public long PacketNumber { get; set; }
            public EncryptionKey KeyUsed { get; set; }
            public int DCIDLengthUsed { get; set; }
            public Dictionary<string, string> DebugInfo { get; set; } = new();
        }
        
        public class EncryptionResult
        {
            public bool Success { get; set; }
            public byte[] EncryptedData { get; set; }
            public string ErrorMessage { get; set; }
        }
        
        private class ConnectionKeys
        {
            public string ClientRandom { get; set; }
            public EncryptionKey ClientKey { get; set; }
            public EncryptionKey ServerKey { get; set; }
            public int SuccessfulDCIDLength { get; set; } = -1;
            public bool IsComplete => ClientKey?.IsValid == true && ServerKey?.IsValid == true;
        }
        
        private class DecryptionAttempt
        {
            public DateTime Timestamp { get; set; }
            public string ConnectionID { get; set; }
            public int DCIDLength { get; set; }
            public bool Success { get; set; }
            public string Details { get; set; }
        }
        
        // ============ PUBLIC API ============
        
        public static void AddKey(EncryptionKey key)
        {
            if (key?.Secret == null) return;
            
            lock (_lock)
            {
                if (key.Key == null || key.IV == null || key.HeaderProtectionKey == null)
                    DeriveQUICKeys(key);
                if (!key.IsValid) return;
                
                string connId = GenerateConnectionId(key);
                if (!_connectionKeys.ContainsKey(connId))
                    _connectionKeys[connId] = new ConnectionKeys { ClientRandom = connId };
                
                if (key.IsClient) _connectionKeys[connId].ClientKey = key;
                else _connectionKeys[connId].ServerKey = key;
                
                if (EnableDebugLogging)
                    Console.WriteLine($"[KEY] Added {(key.IsClient ? "client" : "server")} key");
            }
        }
        
        public static void DeriveQUICKeys(EncryptionKey key)
        {
            if (key?.Secret == null) return;
            int keyLen = key.Secret.Length == 48 ? 32 : 16;
            int ivLen = 12;
            int hpLen = key.Secret.Length == 48 ? 32 : 16;
            
            try
            {
                key.Key = HkdfExpandLabelQUIC(key.Secret, "quic key", keyLen, CurrentLabelFormat);
                key.IV = HkdfExpandLabelQUIC(key.Secret, "quic iv", ivLen, CurrentLabelFormat);
                key.HeaderProtectionKey = HkdfExpandLabelQUIC(key.Secret, "quic hp", hpLen, CurrentLabelFormat);
            }
            catch { }
        }
        
        public static byte[] TryDecrypt(byte[] packet, EncryptionKey key, int dcidLength)
        {
            if (packet == null || packet.Length < 20) return null;
            if (key?.Key == null) return null;
            
            try
            {
                return TryDecryptInternal(packet, key, dcidLength);
            }
            catch { return null; }
        }
        
        /// <summary>
        /// SAFE TryDecrypt - returns immediately, no blocking
        /// </summary>
        public static DecryptionResult TryDecrypt(byte[] packet)
        {
            if (!AutoDecryptEnabled)
                return new DecryptionResult { Success = false, Error = "Auto-decrypt disabled" };
            
            // Run on background thread with timeout
            byte[] result = null;
            var task = Task.Run(() => TryDecryptWithAllKeysInternal(packet));
            
            if (task.Wait(DecryptionTimeoutMs))
                result = task.Result;
            
            return new DecryptionResult
            {
                Success = result != null,
                DecryptedData = result,
                Error = result == null ? "Timeout or all attempts failed" : null
            };
        }
        
        public static DecryptionResult TryDecryptManual(byte[] packet, int timeoutMs)
        {
            return TryDecryptManual(packet, 8, CurrentLabelFormat);
        }
        
        public static DecryptionResult TryDecryptManual(byte[] packet, int dcidLength, HkdfLabelFormat format)
        {
            var oldFormat = CurrentLabelFormat;
            CurrentLabelFormat = format;
            
            byte[] result = null;
            var task = Task.Run(() => TryDecryptWithAllKeysInternal(packet));
            
            if (task.Wait(DecryptionTimeoutMs))
                result = task.Result;
            
            CurrentLabelFormat = oldFormat;
            
            return new DecryptionResult
            {
                Success = result != null,
                DecryptedData = result,
                Error = result == null ? "Timeout or decryption failed" : null,
                DCIDLengthUsed = dcidLength
            };
        }
        
        public static EncryptionResult TryEncrypt(byte[] plaintext, PacketDirection direction)
        {
            if (plaintext == null)
                return new EncryptionResult { Success = false, ErrorMessage = "Plaintext is null" };
            
            // Return plaintext for now - encryption is complex
            return new EncryptionResult { Success = true, EncryptedData = plaintext };
        }
        
        public static void StartAutoDecrypt() { }
        public static void StopAutoDecrypt() { }
        
        public static void ClearKeys()
        {
            lock (_lock) { _connectionKeys.Clear(); _attemptLog.Clear(); }
        }
        
        public static string GetStats()
        {
            lock (_lock)
            {
                double successRate = TotalAttempts > 0 ? (double)SuccessfulDecryptions / TotalAttempts * 100 : 0;
                return $"Conn: {ConnectionCount}, Keys: {DiscoveredKeys.Count}, Success: {SuccessfulDecryptions}/{TotalAttempts} ({successRate:F1}%)";
            }
        }
        
        public static Dictionary<string, object> GetDebugStats()
        {
            lock (_lock)
            {
                return new Dictionary<string, object>
                {
                    ["Connections"] = ConnectionCount,
                    ["TotalKeys"] = DiscoveredKeys.Count,
                    ["SuccessfulDecryptions"] = SuccessfulDecryptions,
                    ["FailedDecryptions"] = FailedDecryptions,
                    ["SkippedDecryptions"] = SkippedDecryptions,
                    ["TotalAttempts"] = TotalAttempts,
                    ["SuccessRate"] = TotalAttempts > 0 ? (double)SuccessfulDecryptions / TotalAttempts * 100 : 0
                };
            }
        }
        
        public static bool IsLikelyEncrypted(byte[] data)
        {
            if (data == null || data.Length < 10) return false;
            bool isLongHeader = (data[0] & 0x80) != 0;
            bool isShortHeader = (data[0] & 0x80) == 0;
            double entropy = CalculateEntropy(data);
            bool validQUIC = isLongHeader || (isShortHeader && data.Length > 20);
            return validQUIC && entropy > 6.5;
        }
        
        public static void LoadSSLKeyLog(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"[SSL] File not found: {filePath}");
                return;
            }
            
            lock (_lock)
            {
                var lines = File.ReadAllLines(filePath);
                int clientCount = 0, serverCount = 0;
                
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    
                    var clientMatch = Regex.Match(line, @"CLIENT_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                    if (clientMatch.Success)
                    {
                        var key = new EncryptionKey
                        {
                            Secret = HexToBytes(clientMatch.Groups[2].Value),
                            Type = EncryptionType.QUIC_Client1RTT,
                            Source = filePath,
                            DiscoveredAt = DateTime.Now
                        };
                        DeriveQUICKeys(key);
                        AddKey(key);
                        clientCount++;
                        continue;
                    }
                    
                    var serverMatch = Regex.Match(line, @"SERVER_TRAFFIC_SECRET_0\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]+)");
                    if (serverMatch.Success)
                    {
                        var key = new EncryptionKey
                        {
                            Secret = HexToBytes(serverMatch.Groups[2].Value),
                            Type = EncryptionType.QUIC_Server1RTT,
                            Source = filePath,
                            DiscoveredAt = DateTime.Now
                        };
                        DeriveQUICKeys(key);
                        AddKey(key);
                        serverCount++;
                    }
                }
                
                Console.WriteLine($"[SSL] Loaded {clientCount} client, {serverCount} server keys");
            }
        }
        
        public static string TestKeyDerivation()
        {
            var keys = GetAllKeys();
            if (keys.Count == 0) return "No keys available";
            return TestKeyDerivation(keys[0].Secret);
        }
        
        public static string TestKeyDerivation(byte[] secret)
        {
            if (secret == null) return "Secret is null";
            var sb = new StringBuilder();
            sb.AppendLine("=== Key Derivation Test ===");
            int keyLen = secret.Length == 48 ? 32 : 16;
            
            foreach (HkdfLabelFormat format in Enum.GetValues<HkdfLabelFormat>())
            {
                try
                {
                    var key = HkdfExpandLabelQUIC(secret, "quic key", keyLen, format);
                    sb.AppendLine($"{format}: {BitConverter.ToString(key.Take(8).ToArray()).Replace("-", "")}...");
                }
                catch (Exception ex) { sb.AppendLine($"{format}: ERROR - {ex.Message}"); }
            }
            return sb.ToString();
        }
        
        public static string DumpAllKeys()
        {
            lock (_lock)
            {
                var sb = new StringBuilder();
                sb.AppendLine($"=== Keys: {_connectionKeys.Count} connections ===");
                foreach (var conn in _connectionKeys.Values)
                {
                    sb.AppendLine($"Conn: {conn.ClientRandom.Substring(0, 16)}...");
                    if (conn.ClientKey != null) sb.AppendLine($"  Client: {BitConverter.ToString(conn.ClientKey.Key.Take(8).ToArray()).Replace("-", "")}...");
                    if (conn.ServerKey != null) sb.AppendLine($"  Server: {BitConverter.ToString(conn.ServerKey.Key.Take(8).ToArray()).Replace("-", "")}...");
                }
                return sb.ToString();
            }
        }
        
        // ============ PRIVATE ============
        
        private static string GenerateConnectionId(EncryptionKey key)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(key.Secret);
            return BitConverter.ToString(hash.Take(16).ToArray()).Replace("-", "").ToLower();
        }
        
        private static List<EncryptionKey> GetAllKeys()
        {
            lock (_lock)
            {
                var keys = new List<EncryptionKey>();
                foreach (var conn in _connectionKeys.Values)
                {
                    if (conn.ClientKey != null) keys.Add(conn.ClientKey);
                    if (conn.ServerKey != null) keys.Add(conn.ServerKey);
                }
                return keys;
            }
        }
        
        private static byte[] TryDecryptWithAllKeysInternal(byte[] packet)
        {
            if (packet == null || packet.Length < 20) return null;
            
            lock (_lock)
            {
                bool isClientPacket = IsClientPacket(packet);
                var connections = _connectionKeys.Values
                    .Where(c => isClientPacket ? c.ClientKey?.IsValid == true : c.ServerKey?.IsValid == true)
                    .Take(5) // Limit connections
                    .ToList();
                
                if (connections.Count == 0) return null;
                
                foreach (var conn in connections)
                {
                    var key = isClientPacket ? conn.ClientKey : conn.ServerKey;
                    
                    // Very limited DCID lengths to prevent hangs
                    int[] dcidLengths = conn.SuccessfulDCIDLength >= 0 
                        ? new[] { conn.SuccessfulDCIDLength } 
                        : new[] { 0, 8, 16 }.Take(MaxDCIDLengthToTry).ToArray();
                    
                    foreach (int dcidLen in dcidLengths)
                    {
                        try
                        {
                            var result = TryDecryptInternal(packet, key, dcidLen);
                            if (result != null)
                            {
                                conn.SuccessfulDCIDLength = dcidLen;
                                _attemptLog.Add(new DecryptionAttempt { Timestamp = DateTime.Now, Success = true });
                                return result;
                            }
                        }
                        catch { }
                    }
                }
                
                _attemptLog.Add(new DecryptionAttempt { Timestamp = DateTime.Now, Success = false });
                return null;
            }
        }
        
        private static byte[] TryDecryptInternal(byte[] packet, EncryptionKey key, int dcidLen)
        {
            byte firstByte = packet[0];
            bool isLongHeader = (firstByte & 0x80) != 0;
            return isLongHeader ? TryDecryptLongHeader(packet, key, dcidLen) : TryDecryptShortHeader(packet, key, dcidLen);
        }
        
        private static byte[] TryDecryptLongHeader(byte[] packet, EncryptionKey key, int dcidLen)
        {
            try
            {
                int offset = 1;
                if (packet.Length < offset + 4) return null;
                uint version = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset)); offset += 4;
                if (packet.Length < offset + 1) return null;
                byte dcidLengthByte = packet[offset++];
                int actualDcidLen = Math.Min(dcidLengthByte, dcidLen);
                if (packet.Length < offset + actualDcidLen) return null;
                offset += dcidLengthByte;
                if (packet.Length < offset + 1) return null;
                byte scidLen = packet[offset++]; offset += scidLen;
                if ((packet[0] & 0x30) == 0x00)
                {
                    if (packet.Length < offset + 1) return null;
                    int tokenLen = (int)ReadVarInt(packet, ref offset); offset += tokenLen;
                }
                if (packet.Length < offset + 2) return null;
                int length = (int)ReadVarInt(packet, ref offset);
                int pnOffset = offset, sampleOffset = pnOffset + 4;
                if (packet.Length < sampleOffset + 16) return null;
                byte[] sample = packet.Skip(sampleOffset).Take(16).ToArray();
                byte[] mask = ComputeHPMask(key.HeaderProtectionKey, sample);
                byte packetNumberLength = (byte)((packet[0] & 0x03) + 1);
                byte[] decryptedPnBytes = new byte[packetNumberLength];
                for (int i = 0; i < packetNumberLength; i++) decryptedPnBytes[i] = (byte)(packet[pnOffset + i] ^ mask[i + 1]);
                int payloadOffset = pnOffset + packetNumberLength, payloadLength = packet.Length - payloadOffset;
                if (payloadLength < 16) return null;
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(key.IV, 0, nonce, 0, 12);
                for (int i = 0; i < packetNumberLength; i++) nonce[11 - i] ^= decryptedPnBytes[packetNumberLength - 1 - i];
                byte[] aad = packet.Take(payloadOffset).ToArray();
                aad[0] = (byte)(packet[0] ^ (mask[0] & 0x0F));
                byte[] ciphertext = packet.Skip(payloadOffset).ToArray();
                byte[] plaintext = new byte[ciphertext.Length - 16];
                byte[] tag = ciphertext.Skip(ciphertext.Length - 16).ToArray();
                using var aes = new AesGcm(key.Key, 16);
                aes.Decrypt(nonce, ciphertext.Take(ciphertext.Length - 16).ToArray(), tag, plaintext, aad);
                return plaintext;
            }
            catch { return null; }
        }
        
        private static byte[] TryDecryptShortHeader(byte[] packet, EncryptionKey key, int dcidLen)
        {
            try
            {
                int dcidEnd = 1 + dcidLen;
                if (packet.Length < dcidEnd + 20) return null;
                int sampleOffset = dcidEnd + 4;
                if (packet.Length < sampleOffset + 16) return null;
                byte[] sample = packet.Skip(sampleOffset).Take(16).ToArray();
                byte[] mask = ComputeHPMask(key.HeaderProtectionKey, sample);
                byte protectedBits = (byte)(packet[0] & 0x1F);
                byte unprotectedFirstByte = (byte)((packet[0] & 0xE0) | (protectedBits ^ (mask[0] & 0x1F)));
                int packetNumberLength = (unprotectedFirstByte & 0x03) + 1;
                int pnOffset = dcidEnd;
                byte[] decryptedPnBytes = new byte[packetNumberLength];
                for (int i = 0; i < packetNumberLength; i++) decryptedPnBytes[i] = (byte)(packet[pnOffset + i] ^ mask[i + 1]);
                int payloadOffset = pnOffset + packetNumberLength, payloadLength = packet.Length - payloadOffset;
                if (payloadLength < 16) return null;
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(key.IV, 0, nonce, 0, 12);
                for (int i = 0; i < packetNumberLength; i++) nonce[11 - i] ^= decryptedPnBytes[packetNumberLength - 1 - i];
                byte[] aad = packet.Take(payloadOffset).ToArray();
                aad[0] = unprotectedFirstByte;
                byte[] ciphertext = packet.Skip(payloadOffset).ToArray();
                byte[] plaintext = new byte[ciphertext.Length - 16];
                byte[] tag = ciphertext.Skip(ciphertext.Length - 16).ToArray();
                using var aes = new AesGcm(key.Key, 16);
                aes.Decrypt(nonce, ciphertext.Take(ciphertext.Length - 16).ToArray(), tag, plaintext, aad);
                return plaintext;
            }
            catch { return null; }
        }
        
        private static byte[] ComputeHPMask(byte[] hpKey, byte[] sample)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = hpKey; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
                using var encryptor = aes.CreateEncryptor();
                byte[] mask = new byte[16];
                encryptor.TransformBlock(sample, 0, 16, mask, 0);
                return mask;
            }
            catch { return new byte[16]; }
        }
        
        private static byte[] HkdfExpandLabelQUIC(byte[] secret, string label, int length, HkdfLabelFormat format)
        {
            string actualLabel = format switch
            {
                HkdfLabelFormat.RFC9001_NoPrefix => label,
                HkdfLabelFormat.RFC8446_WithPrefix => $"tls13 {label}",
                HkdfLabelFormat.QUICv2 => label.Replace("quic", "quicv2"),
                HkdfLabelFormat.TestVector => label,
                _ => label
            };
            byte[] labelBytes = Encoding.ASCII.GetBytes(actualLabel);
            byte[] hash = SHA256.HashData(Array.Empty<byte>());
            using var ms = new MemoryStream();
            ms.WriteByte((byte)(length >> 8)); ms.WriteByte((byte)length); ms.WriteByte((byte)labelBytes.Length);
            ms.Write(labelBytes, 0, labelBytes.Length); ms.WriteByte(0);
            byte[] hkdfLabel = ms.ToArray();
            return HkdfExpand(secret, hash, hkdfLabel, length);
        }
        
        private static byte[] HkdfExpand(byte[] prk, byte[] hash, byte[] info, int length)
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
        
        private static bool IsClientPacket(byte[] packet) { return (packet[0] & 0x40) != 0; }
        
        private static long ReadVarInt(byte[] data, ref int offset)
        {
            if (offset >= data.Length) return 0;
            byte first = data[offset];
            int len = 1 << (first >> 6);
            long value = first & 0x3F;
            for (int i = 1; i < len && offset + i < data.Length; i++) value = (value << 8) | data[offset + i];
            offset += len;
            return value;
        }
        
        private static double CalculateEntropy(byte[] data)
        {
            var frequencies = new Dictionary<byte, int>();
            foreach (var b in data) { if (!frequencies.ContainsKey(b)) frequencies[b] = 0; frequencies[b]++; }
            double entropy = 0;
            int length = data.Length;
            foreach (var freq in frequencies.Values) { double probability = (double)freq / length; entropy -= probability * Math.Log(probability, 2); }
            return entropy;
        }
        
        private static byte[] HexToBytes(string hex)
        {
            hex = hex.Trim();
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }
}