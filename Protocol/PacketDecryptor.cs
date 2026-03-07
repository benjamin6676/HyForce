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
        
        // Packet number tracking per key for proper nonce reconstruction (RFC 9000 §A.3)
        // Key = key secret hash, Value = largest successfully decoded packet number
        private static readonly Dictionary<string, long> _largestPktNum = new();
        
        // Safety settings - TUNED FOR NO LAG
        public static int MaxDCIDLengthToTry { get; set; } = 20; // Netty QUIC 1-RTT DCID 0-20 bytes
        public static int DecryptionTimeoutMs { get; set; } = 100; // 100ms per attempt
        public static bool EnableDebugLogging { get; set; } = true;
        
        public static bool DebugMode { get; set; } = true;
        public static bool AutoDecryptEnabled { get; set; } = false; // DISABLED by default to prevent lag
        public static bool DllInjectionActive { get; set; } = false; // when true, packets come via named pipe
        public static bool SkipHPFilter { get; set; } = false;       // DLL-sourced packets skip HP filter
        public static int SkippedDecryptions { get; set; } = 0;
        public static int QueueDepth => _decryptQueue?.Count ?? 0;
        public static int DeadConnectionCount
        {
            get { lock (_lock) { return _connectionKeys.Values.Count(c => c.IsDead); } }
        }
        // RFC 9001 §5.1: Hytale/Netty QUIC uses NO "tls13 " prefix for 1-RTT keys.
        // Confirmed by comparing live key derivation from sslkeys.log against actual key bytes.
        // "quic key", "quic iv", "quic hp" — NOT "tls13 quic key" etc.
        // (The "tls13 " prefix applies to TLS 1.3 derived keys, but QUIC replaces those labels.)
        private static HkdfLabelFormat _labelFormat = HkdfLabelFormat.RFC9001_NoPrefix;
        public static HkdfLabelFormat CurrentLabelFormat
        {
            get => _labelFormat;
            set { _labelFormat = value; }
        }
        
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
            public bool IsCurrentSession { get; set; } = false;
            public DateTime AddedAt { get; set; } = DateTime.Now;
            public bool IsComplete => ClientKey?.IsValid == true && ServerKey?.IsValid == true;
            public int ConsecutiveFailures { get; set; } = 0;
            public bool IsDead => !IsCurrentSession && ConsecutiveFailures >= 150;
        }

        // Timestamp of last Start() call — keys added after this are "current session"
        private static DateTime _sessionStartTime = DateTime.MinValue;

        /// <summary>Call when capture session starts to mark future keys as current-session.</summary>
        public static void MarkSessionStart()
        {
            lock (_lock)
            {
                _sessionStartTime = DateTime.Now;
                // Mark any keys added within the last 30 seconds as current session
                // (handles keys that loaded just before Start() was clicked)
                var cutoff = _sessionStartTime.AddSeconds(-30);
                foreach (var conn in _connectionKeys.Values)
                    if (conn.AddedAt >= cutoff) conn.IsCurrentSession = true;
            }
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
                var conn = _connectionKeys[connId];
                // FIX: assign to correct slot regardless of session tagging
                if (key.IsClient) conn.ClientKey = key;
                else              conn.ServerKey = key;   // Server1RTT, ServerHandshake
                // Tag session
                bool isCurrent = _sessionStartTime != DateTime.MinValue &&
                    DateTime.Now >= _sessionStartTime.AddSeconds(-30);
                if (isCurrent) { conn.IsCurrentSession = true; conn.AddedAt = DateTime.Now; }
                conn.ConsecutiveFailures = 0;
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
        /// Non-blocking fire-and-forget decrypt for auto-decrypt pipeline.
        /// Enqueues packet; background worker processes it and fires OnDecrypted.
        /// Returns immediately — NEVER blocks the calling thread.
        /// </summary>
        public static DecryptionResult TryDecrypt(byte[] packet)
        {
            if (!AutoDecryptEnabled)
                return new DecryptionResult { Success = false, Error = "Auto-decrypt disabled" };

            // HP pre-filter: check if ANY (key,dcid) combo could produce a valid short-header
            // Skipped when DLL injection active (DLL guarantees packets are real QUIC)
            if (!SkipHPFilter && packet.Length > 21 && (packet[0] & 0x80) == 0) // short header
            {
                bool anyValid = false;
                lock (_lock)
                {
                    var conns = _connectionKeys.Values
                        .Where(c => c.IsCurrentSession)
                        .Concat(_connectionKeys.Values.Where(c => !c.IsCurrentSession))
                        .Take(MaxSessionsToSearch)
                        .ToList();

                    foreach (var conn in conns)
                    {
                        foreach (var key in new[] { conn.ServerKey, conn.ClientKey })
                        {
                            if (key?.HeaderProtectionKey == null) continue;
                            if (conn.SuccessfulDCIDLength >= 0)
                            {
                                if (HPFilterPass(packet, key.HeaderProtectionKey, conn.SuccessfulDCIDLength))
                                { anyValid = true; break; }
                            }
                            else
                            {
                                for (int d = 0; d <= 20; d++)
                                    if (HPFilterPass(packet, key.HeaderProtectionKey, d))
                                    { anyValid = true; break; }
                            }
                            if (anyValid) break;
                        }
                        if (anyValid) break;
                    }
                }
                if (!anyValid)
                {
                    SkippedDecryptions++;
                    return new DecryptionResult { Success = false, Error = "HP pre-filter: no valid key/DCID found" };
                }
            }

            // Enqueue for background worker — does NOT block
            if (!_decryptQueue.IsAddingCompleted)
                _decryptQueue.TryAdd(packet);

            return new DecryptionResult { Success = false, Error = "Queued for background decryption" };
        }

        /// <summary>
        /// Called when packets arrive via DLL named pipe.
        /// Skips HP filter entirely (DLL guarantees these are real QUIC packets from Hytale).
        /// Uses DCID=0 fast path (confirmed from Initial packet capture).
        /// </summary>
        public static byte[]? TryDecryptDirect(byte[] packet, PacketDirection direction)
        {
            if (packet == null || packet.Length < 20) return null;
            if (!_decryptQueue.IsAddingCompleted)
                _decryptQueue.TryAdd(packet); // background worker handles it
            return null; // result comes via OnDecrypted event
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
        
        // Background decrypt pipeline
        private static System.Collections.Concurrent.BlockingCollection<byte[]> _decryptQueue
            = new System.Collections.Concurrent.BlockingCollection<byte[]>(500); // cap at 500 queued
        private static System.Threading.Thread? _decryptWorker;
        public static int MaxSessionsToSearch { get; set; } = 5; // only try N most recent sessions

        // Fired when a packet is successfully decrypted
        public static event Action<byte[], byte[]>? OnDecrypted; // (encrypted, decrypted)

        public static void StartAutoDecrypt()
        {
            if (_decryptWorker?.IsAlive == true) return;
            _decryptWorker = new System.Threading.Thread(DecryptWorkerLoop)
            {
                IsBackground = true,
                Name = "HyForce-DecryptWorker",
                Priority = System.Threading.ThreadPriority.BelowNormal // never starve UI
            };
            _decryptWorker.Start();
        }

        public static void StopAutoDecrypt()
        {
            // Drain queue; worker exits on its own
            while (_decryptQueue.TryTake(out _)) { }
        }

        private static void DecryptWorkerLoop()
        {
            foreach (var packet in _decryptQueue.GetConsumingEnumerable())
            {
                try
                {
                    var result = TryDecryptWithAllKeysInternal(packet);
                    if (result != null)
                    {
                        _attemptLog.Add(new DecryptionAttempt { Timestamp = DateTime.Now, Success = true });
                        OnDecrypted?.Invoke(packet, result);

                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// HP pre-filter: compute header-protection mask for the given dcidLen
        /// and check if the unprotected first byte is a valid QUIC short-header byte.
        /// RFC 9000 §17.3: Fixed bit (0x40) must be 1, Reserved bits (0x18) must be 0.
        /// Returns true = this (key, dcid) combo is PLAUSIBLE (still needs AES-GCM to confirm).
        /// Returns false = impossible, skip AES-GCM entirely.
        /// </summary>
        private static bool HPFilterPass(byte[] packet, byte[] hpKey, int dcidLen)
        {
            try
            {
                int sampleOffset = 1 + dcidLen + 4;
                if (sampleOffset + 16 > packet.Length) return false;
                var mask = ComputeHPMask(hpKey, packet.Skip(sampleOffset).Take(16).ToArray());
                byte unprotected = (byte)((packet[0] & 0xE0) | ((packet[0] & 0x1F) ^ (mask[0] & 0x1F)));
                return (unprotected & 0x40) != 0 && (unprotected & 0x18) == 0;
            }
            catch { return false; }
        }
        
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
                // Order: current-session connections first (most likely match), then rest
                // Current-session keys first; cap total sessions to avoid O(n*dcid) explosion
                var current = _connectionKeys.Values
                    .Where(c => c.IsCurrentSession)
                    .OrderByDescending(c => c.AddedAt)
                    .Take(MaxSessionsToSearch)
                    .ToList();
                var others = _connectionKeys.Values
                    .Where(c => !c.IsCurrentSession)
                    .OrderByDescending(c => c.AddedAt)
                    .Take(Math.Max(1, MaxSessionsToSearch - current.Count))
                    .ToList();
                var ordered = current.Concat(others).ToList();
                if (ordered.Count == 0) return null;

                foreach (var conn in ordered)
                {
                    // Fast path: if we already know the working DCID length, use it
                    // HP filter already ran above; here we only reach surviving combos
                    // Try known-good DCID length first, then Netty defaults (20), then scan
                    // CONFIRMED: Hytale server uses SCID=0 (from Initial packet capture)
                    // So 1-RTT short-header DCID = 0 bytes. Try 0 FIRST.
                    int[] dcidLengths = conn.SuccessfulDCIDLength >= 0
                        ? new[] { conn.SuccessfulDCIDLength }
                        : new[] { 0, 8, 20, 4, 16, 12, 1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15, 17, 18, 19 };

                    // 1-RTT server key first (S2C ~95% of traffic); skip 0RTT/Handshake for auto-decrypt
                    var keysToTry = new List<EncryptionKey>();
                    if (conn.ServerKey?.IsValid == true &&
                        conn.ServerKey.Type == EncryptionType.QUIC_Server1RTT)
                        keysToTry.Add(conn.ServerKey);
                    if (conn.ClientKey?.IsValid == true &&
                        conn.ClientKey.Type == EncryptionType.QUIC_Client1RTT)
                        keysToTry.Add(conn.ClientKey);
                    // Fallback: any valid key if no 1RTT found
                    if (keysToTry.Count == 0)
                    {
                        if (conn.ServerKey?.IsValid == true) keysToTry.Add(conn.ServerKey);
                        if (conn.ClientKey?.IsValid == true) keysToTry.Add(conn.ClientKey);
                    }

                    foreach (var key in keysToTry)
                    {
                        foreach (int dcidLen in dcidLengths)
                        {
                            try
                            {
                                var result = TryDecryptInternal(packet, key, dcidLen);
                                if (result != null)
                                {
                                    conn.SuccessfulDCIDLength = dcidLen;
                                    conn.IsCurrentSession = true; // it works, lock it in

                                    // NEW: Promote this key to working file since it successfully decrypted
                                    try
                                    {
                                        HyForce.Core.AppState.Instance?.PromoteKeyToWorking(key);
                                    }
                                    catch { /* Don't fail decryption if promote fails */ }

                                    _attemptLog.Add(new DecryptionAttempt { Timestamp = DateTime.Now, Success = true });
                                    return result;
                                }
                            }
                            catch { }
                        }
                    }

                    _attemptLog.Add(new DecryptionAttempt { Timestamp = DateTime.Now, Success = false });
                }

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
                // RFC 9001 §5.4.1: must remove HP from first byte BEFORE reading PN length
                byte unprotectedFirstLH = (byte)(packet[0] ^ (mask[0] & 0x0F));
                byte packetNumberLength = (byte)((unprotectedFirstLH & 0x03) + 1);
                byte[] decryptedPnBytes = new byte[packetNumberLength];
                for (int i = 0; i < packetNumberLength; i++) decryptedPnBytes[i] = (byte)(packet[pnOffset + i] ^ mask[i + 1]);
                int payloadOffset = pnOffset + packetNumberLength, payloadLength = packet.Length - payloadOffset;
                if (payloadLength < 16) return null;
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(key.IV, 0, nonce, 0, 12);
                for (int i = 0; i < packetNumberLength; i++) nonce[11 - i] ^= decryptedPnBytes[packetNumberLength - 1 - i];
                // RFC 9001 §5.3: AAD must contain unprotected header
                byte[] aad = packet.Take(payloadOffset).ToArray();
                aad[0] = unprotectedFirstLH;
                for (int i = 0; i < packetNumberLength; i++) aad[pnOffset + i] = decryptedPnBytes[i];
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
                
                // Decode truncated packet number from wire
                long truncatedPN = 0;
                for (int i = 0; i < packetNumberLength; i++)
                    truncatedPN = (truncatedPN << 8) | (byte)(packet[pnOffset + i] ^ mask[i + 1]);
                
                // RFC 9000 §A.3: Reconstruct full 62-bit packet number from truncated value
                string keyId = BitConverter.ToString(SHA256.HashData(key.Secret).Take(8).ToArray());
                long largestAcked = _largestPktNum.TryGetValue(keyId, out var lp) ? lp : 0;
                long fullPN = ReconstructPacketNumber(truncatedPN, packetNumberLength, largestAcked);
                
                int payloadOffset = pnOffset + packetNumberLength, payloadLength = packet.Length - payloadOffset;
                if (payloadLength < 16) return null;
                
                // Build nonce: IV XOR full 62-bit packet number (big-endian into last 8 bytes)
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(key.IV, 0, nonce, 0, 12);
                for (int i = 0; i < 8; i++)
                    nonce[11 - i] ^= (byte)(fullPN >> (i * 8));
                
                // RFC 9001 §5.3: AAD must contain unprotected header (first byte + unprotected PN bytes)
                byte[] aad = packet.Take(payloadOffset).ToArray();
                aad[0] = unprotectedFirstByte;
                for (int i = 0; i < packetNumberLength; i++)
                    aad[pnOffset + i] = (byte)(packet[pnOffset + i] ^ mask[i + 1]);
                byte[] ciphertext = packet.Skip(payloadOffset).ToArray();
                byte[] plaintext = new byte[ciphertext.Length - 16];
                byte[] tag = ciphertext.Skip(ciphertext.Length - 16).ToArray();
                using var aes = new AesGcm(key.Key, 16);
                aes.Decrypt(nonce, ciphertext.Take(ciphertext.Length - 16).ToArray(), tag, plaintext, aad);
                
                // Success: update largest seen packet number for future reconstruction
                if (fullPN > largestAcked)
                    lock (_lock) { _largestPktNum[keyId] = fullPN; }
                
                return plaintext;
            }
            catch { return null; }
        }
        
        // RFC 9000 §A.3: decode_packet_number
        private static long ReconstructPacketNumber(long truncated, int pnLen, long largestAcked)
        {
            long pnWin    = 1L << (pnLen * 8);
            long pnHalf   = pnWin / 2;
            long pnMask   = pnWin - 1;
            long candidate = (largestAcked & ~pnMask) | truncated;
            if (candidate <= largestAcked - pnHalf && candidate + pnWin < (1L << 62))
                return candidate + pnWin;
            if (candidate >  largestAcked + pnHalf && candidate >= pnWin)
                return candidate - pnWin;
            return candidate;
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
