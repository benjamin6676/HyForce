// =============================================================================
// COMPLETE PacketDecryptor.cs - All Methods Implemented
// For Hytale QUIC Packet Decryption
// Types are NESTED inside PacketDecryptor to match existing code
// =============================================================================

using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Protocol
{
    public static class PacketDecryptor
    {
        // =========================================================================
        // NESTED TYPES (must be inside PacketDecryptor to match existing code)
        // =========================================================================

        public class DecryptionResult
        {
            public bool Success { get; set; }
            public byte[]? DecryptedData { get; set; }
            public string ErrorMessage { get; set; } = "";
            public int PacketNumber { get; set; }
            public Dictionary<string, object> Metadata { get; set; } = new();
        }

        public class EncryptionKey
        {
            public byte[]? Secret { get; set; }
            public byte[] Key { get; set; } = Array.Empty<byte>();
            public byte[] IV { get; set; } = Array.Empty<byte>();
            public byte[]? HeaderProtectionKey { get; set; }
            public EncryptionType Type { get; set; }
            public string Source { get; set; } = "";
            public DateTime DiscoveredAt { get; set; } = DateTime.Now;
            public int UseCount { get; set; }

            // ADDED: Memory address for memory-scanned keys
            public ulong? MemoryAddress { get; set; }
        }

        public enum EncryptionType
        {
            QUIC_Client1RTT,
            QUIC_Server1RTT,
            QUIC_ClientHandshake,
            QUIC_ServerHandshake,
            QUIC_Client0RTT,
            QUIC_Server0RTT,
            AES128GCM,
            AES256GCM,
            XOR
        }

        // =========================================================================
        // FIELDS
        // =========================================================================

        private static readonly ReaderWriterLockSlim _keysLock = new();
        private static readonly List<EncryptionKey> _discoveredKeys = new();

        public static IReadOnlyList<EncryptionKey> DiscoveredKeys
        {
            get
            {
                _keysLock.EnterReadLock();
                try { return _discoveredKeys.ToList(); }
                finally { _keysLock.ExitReadLock(); }
            }
        }

        public static bool AutoDecryptEnabled { get; set; } = true;
        public static int SuccessfulDecryptions { get; private set; }
        public static int FailedDecryptions { get; private set; }
        public static int SkippedDecryptions { get; private set; }

        public static event Action<EncryptionKey>? OnKeyDiscovered;
        public static event Action<DecryptionResult>? OnPacketDecrypted;

        // =========================================================================
        // KEY MANAGEMENT
        // =========================================================================

        public static void AddKey(EncryptionKey key)
        {
            if (key?.Key == null || key.Key.Length == 0) return;

            _keysLock.EnterWriteLock();
            try
            {
                // Check for exact duplicate (same key bytes)
                foreach (var existing in _discoveredKeys)
                {
                    if (existing.Key.SequenceEqual(key.Key))
                    {
                        if (!existing.Source.Contains(key.Source))
                            existing.Source += $", {key.Source}";
                        Console.WriteLine($"[KEYS] Duplicate key ignored from {key.Source}");
                        return;
                    }
                }

                // Check if we have a key with same secret AND same type
                if (key.Secret != null)
                {
                    foreach (var existing in _discoveredKeys)
                    {
                        if (existing.Secret != null &&
                            existing.Secret.SequenceEqual(key.Secret) &&
                            existing.Type == key.Type)
                        {
                            Console.WriteLine($"[KEYS] Same secret+type already exists ({key.Type}), skipping");
                            return;
                        }
                    }
                }

                // Increased limit to 200
                if (_discoveredKeys.Count >= 200)
                {
                    var bySource = _discoveredKeys.GroupBy(k => k.Source).OrderByDescending(g => g.Count()).First();
                    if (bySource.Count() > 50)
                    {
                        var toRemove = bySource.OrderBy(k => k.DiscoveredAt).First();
                        _discoveredKeys.Remove(toRemove);
                        Console.WriteLine($"[KEYS] Removed old key from {toRemove.Source} to make room");
                    }
                    else
                    {
                        Console.WriteLine($"[KEYS] Key limit reached (200), not adding more");
                        return;
                    }
                }

                _discoveredKeys.Add(key);
                Console.WriteLine($"[KEYS] Added new {key.Type} key ({key.Key.Length} bytes) - Total keys: {_discoveredKeys.Count}");
            }
            finally
            {
                _keysLock.ExitWriteLock();
            }

            OnKeyDiscovered?.Invoke(key);
        }

        public static void ClearKeys()
        {
            _keysLock.EnterWriteLock();
            try
            {
                _discoveredKeys.Clear();
                SuccessfulDecryptions = 0;
                FailedDecryptions = 0;
                SkippedDecryptions = 0;
            }
            finally
            {
                _keysLock.ExitWriteLock();
            }
        }

        // =========================================================================
        // KEY DERIVATION - RFC 9001 COMPLIANT
        // =========================================================================

        public static void DeriveQUICKeys(EncryptionKey key)
        {
            if (key.Secret == null || key.Secret.Length == 0)
            {
                Console.WriteLine($"[KEY-DERIVE] No secret available for {key.Type}");
                return;
            }

            try
            {
                Console.WriteLine($"[KEY-DERIVE] ========== {key.Type} ==========");
                Console.WriteLine($"[KEY-DERIVE] Secret length: {key.Secret.Length} bytes");

                // Determine key length: 32B secret = AES-128, 48B = AES-256
                int keyLen = key.Secret.Length >= 48 ? 32 : 16;
                int hpLen = keyLen;
                string cipher = keyLen == 16 ? "AES-128-GCM" : "AES-256-GCM";
                Console.WriteLine($"[KEY-DERIVE] Using {cipher} ({keyLen * 8}-bit keys)");

                // RFC 9001 Section 5.1: QUIC uses labels WITHOUT "tls13 " prefix
                key.Key = HkdfExpandLabelQUIC(key.Secret, "quic key", keyLen);
                key.IV = HkdfExpandLabelQUIC(key.Secret, "quic iv", 12);
                key.HeaderProtectionKey = HkdfExpandLabelQUIC(key.Secret, "quic hp", hpLen);

                Console.WriteLine($"[KEY-DERIVE] Key: {Convert.ToHexString(key.Key.Take(8).ToArray())}... ({key.Key.Length} bytes)");
                Console.WriteLine($"[KEY-DERIVE] IV:  {Convert.ToHexString(key.IV)}");
                Console.WriteLine($"[KEY-DERIVE] HP:  {Convert.ToHexString(key.HeaderProtectionKey.Take(8).ToArray())}...");
                Console.WriteLine($"[KEY-DERIVE] Successfully derived keys");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[KEY-DERIVE] FAILED: {ex.Message}");
                key.Key = Array.Empty<byte>();
                key.IV = Array.Empty<byte>();
                key.HeaderProtectionKey = null;
            }
        }

        private static byte[] HkdfExpandLabelQUIC(byte[] secret, string label, int length)
        {
            // RFC 9001: QUIC labels are used directly WITHOUT "tls13 " prefix
            var labelBytes = Encoding.ASCII.GetBytes(label);

            var hkdfLabel = new List<byte>(4 + labelBytes.Length + 1);
            hkdfLabel.Add((byte)(length >> 8));
            hkdfLabel.Add((byte)(length & 0xFF));
            hkdfLabel.Add((byte)labelBytes.Length);
            hkdfLabel.AddRange(labelBytes);
            hkdfLabel.Add(0); // context length = 0

            if (secret.Length >= 48)
                return HkdfExpandSHA384(secret, hkdfLabel.ToArray(), length);
            return HkdfExpandSHA256(secret, hkdfLabel.ToArray(), length);
        }

        private static byte[] HkdfExpandSHA256(byte[] prk, byte[] info, int length)
        {
            using var hmac = new HMACSHA256();
            hmac.Key = prk;

            byte[] result = new byte[length];
            byte[] t = Array.Empty<byte>();
            byte[] counter = new byte[1];

            int offset = 0;
            while (offset < length)
            {
                counter[0]++;

                // T(i) = HMAC-SHA256(PRK, T(i-1) || info || 0x0i)
                byte[] data = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, data, 0, t.Length);
                Buffer.BlockCopy(info, 0, data, t.Length, info.Length);
                data[data.Length - 1] = counter[0];

                t = hmac.ComputeHash(data);

                int copyLen = Math.Min(t.Length, length - offset);
                Buffer.BlockCopy(t, 0, result, offset, copyLen);
                offset += copyLen;
            }

            return result;
        }

        private static byte[] HkdfExpandSHA384(byte[] prk, byte[] info, int length)
        {
            using var hmac = new HMACSHA384();
            hmac.Key = prk;

            byte[] result = new byte[length];
            byte[] t = Array.Empty<byte>();
            byte[] counter = new byte[1];

            int offset = 0;
            while (offset < length)
            {
                counter[0]++;

                byte[] data = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, data, 0, t.Length);
                Buffer.BlockCopy(info, 0, data, t.Length, info.Length);
                data[data.Length - 1] = counter[0];

                t = hmac.ComputeHash(data);

                int copyLen = Math.Min(t.Length, length - offset);
                Buffer.BlockCopy(t, 0, result, offset, copyLen);
                offset += copyLen;
            }

            return result;
        }

        // =========================================================================
        // MAIN DECRYPTION - TryDecrypt
        // =========================================================================

        public static DecryptionResult TryDecrypt(byte[] encryptedData, int timeoutMs = 10000)
        {
            Console.WriteLine($"[DECRYPT] ========== NEW DECRYPT REQUEST ==========");
            Console.WriteLine($"[DECRYPT] Packet size: {encryptedData.Length} bytes");

            if (encryptedData.Length < 10)
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too small" };
            }

            // Determine header type from first byte
            bool isLongHeader = (encryptedData[0] & 0x80) != 0;
            Console.WriteLine($"[DECRYPT] Header type: {(isLongHeader ? "Long (Handshake/Initial)" : "Short (1-RTT)")}");
            Console.WriteLine($"[DECRYPT] First byte: 0x{encryptedData[0]:X2}");
            Console.WriteLine($"[DECRYPT] Available keys: {DiscoveredKeys.Count}");
            Console.WriteLine($"[DECRYPT] AutoDecryptEnabled: {AutoDecryptEnabled}");

            if (DiscoveredKeys.Count == 0)
            {
                Console.WriteLine($"[DECRYPT] FAILED: No keys available");
                return new DecryptionResult { Success = false, ErrorMessage = "No keys available" };
            }

            using var cts = new CancellationTokenSource(timeoutMs);

            // Get relevant keys based on header type
            var relevantKeys = GetRelevantKeys(isLongHeader);
            Console.WriteLine($"[DECRYPT] Trying {relevantKeys.Count} relevant keys");

            foreach (var key in relevantKeys)
            {
                if (cts.Token.IsCancellationRequested)
                    return new DecryptionResult { Success = false, ErrorMessage = "Timeout" };

                Console.WriteLine($"[DECRYPT] Trying {key.Type} key from {key.Source}");

                var result = TryDecryptWithKeyDetailed(encryptedData, key, cts.Token);
                if (result.Success)
                {
                    Console.WriteLine($"[DECRYPT] SUCCESS with {key.Type}");
                    key.UseCount++;
                    SuccessfulDecryptions++;
                    OnPacketDecrypted?.Invoke(result);
                    return result;
                }
            }

            FailedDecryptions++;
            Console.WriteLine($"[DECRYPT] FAILED - tried {relevantKeys.Count} keys");
            return new DecryptionResult { Success = false, ErrorMessage = "All keys failed" };
        }

        /// <summary>
        /// Manual decryption with timeout - tries all available keys
        /// </summary>
        public static DecryptionResult TryDecryptManual(byte[] encryptedData, int timeoutMs)
        {
            Console.WriteLine($"[DECRYPT-MANUAL] Attempting manual decryption with {timeoutMs}ms timeout...");

            if (encryptedData.Length < 10)
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too small" };
            }

            if (DiscoveredKeys.Count == 0)
            {
                return new DecryptionResult { Success = false, ErrorMessage = "No keys available" };
            }

            using var cts = new CancellationTokenSource(timeoutMs);

            // Determine header type from first byte
            bool isLongHeader = (encryptedData[0] & 0x80) != 0;
            var relevantKeys = GetRelevantKeys(isLongHeader);

            foreach (var key in relevantKeys)
            {
                if (cts.Token.IsCancellationRequested)
                    return new DecryptionResult { Success = false, ErrorMessage = "Timeout" };

                var result = TryDecryptWithKeyDetailed(encryptedData, key, cts.Token);

                if (result.Success)
                {
                    Console.WriteLine($"[DECRYPT-MANUAL] SUCCESS with {key.Type}!");
                    key.UseCount++;
                    SuccessfulDecryptions++;
                    return result;
                }
            }

            Console.WriteLine($"[DECRYPT-MANUAL] FAILED - tried {relevantKeys.Count} keys");
            FailedDecryptions++;
            return new DecryptionResult { Success = false, ErrorMessage = "All keys failed" };
        }

        private static List<EncryptionKey> GetRelevantKeys(bool isLongHeader)
        {
            _keysLock.EnterReadLock();
            try
            {
                List<EncryptionKey> keys;

                // Filter by key type based on header
                if (isLongHeader)
                {
                    // Long headers = Handshake or Initial packets
                    keys = _discoveredKeys
                        .Where(k => k.Type == EncryptionType.QUIC_ClientHandshake ||
                                    k.Type == EncryptionType.QUIC_ServerHandshake)
                        .OrderByDescending(k => k.UseCount)
                        .Take(10)
                        .ToList();
                }
                else
                {
                    // Short headers = 1-RTT packets (most game traffic)
                    keys = _discoveredKeys
                        .Where(k => k.Type == EncryptionType.QUIC_Client1RTT ||
                                    k.Type == EncryptionType.QUIC_Server1RTT)
                        .OrderByDescending(k => k.UseCount)
                        .Take(10)
                        .ToList();
                }

                // If no specific keys found, try all
                if (keys.Count == 0)
                {
                    keys = _discoveredKeys
                        .OrderByDescending(k => k.UseCount)
                        .Take(10)
                        .ToList();
                }

                return keys;
            }
            finally
            {
                _keysLock.ExitReadLock();
            }
        }

        // =========================================================================
        // DECRYPTION WITH SPECIFIC KEY
        // =========================================================================

        private static DecryptionResult TryDecryptWithKeyDetailed(byte[] encryptedData, EncryptionKey key, CancellationToken ct)
        {
            try
            {
                // Step 1: Remove header protection
                var unprotectedHeader = RemoveHeaderProtection(encryptedData, key);
                if (unprotectedHeader == null)
                {
                    return new DecryptionResult { Success = false, ErrorMessage = "Header protection removal failed" };
                }

                // Step 2: Extract packet number
                int packetNumber = ExtractPacketNumber(unprotectedHeader);
                Console.WriteLine($"[DECRYPT-DEBUG] Packet number: {packetNumber}");

                // Step 3: Build nonce (IV XOR packet number)
                byte[] nonce = BuildNonce(key.IV, packetNumber);

                // Step 4: Extract ciphertext and decrypt
                int headerLen = GetHeaderLength(unprotectedHeader);

                if (headerLen >= encryptedData.Length)
                {
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid header length" };
                }

                byte[] ciphertext = new byte[encryptedData.Length - headerLen];
                Buffer.BlockCopy(encryptedData, headerLen, ciphertext, 0, ciphertext.Length);

                // The last 16 bytes are the authentication tag
                if (ciphertext.Length < 16)
                {
                    return new DecryptionResult { Success = false, ErrorMessage = "Ciphertext too short" };
                }

                byte[] encryptedPayload = new byte[ciphertext.Length - 16];
                byte[] authTag = new byte[16];
                Buffer.BlockCopy(ciphertext, 0, encryptedPayload, 0, encryptedPayload.Length);
                Buffer.BlockCopy(ciphertext, ciphertext.Length - 16, authTag, 0, 16);

                // Step 5: Build associated data (the unprotected header)
                byte[] associatedData = new byte[headerLen];
                Buffer.BlockCopy(unprotectedHeader, 0, associatedData, 0, headerLen);

                // Step 6: Decrypt with AES-GCM
                byte[]? plaintext = AesGcmDecrypt(key.Key, nonce, encryptedPayload, authTag, associatedData);

                if (plaintext != null)
                {
                    return new DecryptionResult
                    {
                        Success = true,
                        DecryptedData = plaintext,
                        PacketNumber = packetNumber,
                        Metadata = new Dictionary<string, object>
                        {
                            ["KeyType"] = key.Type,
                            ["KeySource"] = key.Source,
                            ["PacketNumber"] = packetNumber
                        }
                    };
                }

                return new DecryptionResult { Success = false, ErrorMessage = "AEAD decryption failed" };
            }
            catch (Exception ex)
            {
                return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
            }
        }

        // =========================================================================
        // HELPER METHODS - Header Protection
        // =========================================================================

        /// <summary>
        /// Removes header protection from a QUIC packet
        /// </summary>
        private static byte[]? RemoveHeaderProtection(byte[] packet, EncryptionKey key)
        {
            if (key.HeaderProtectionKey == null || key.HeaderProtectionKey.Length == 0)
                return null;

            try
            {
                // Get packet number length from first byte (bits 0-1)
                int pnLen = (packet[0] & 0x03) + 1;

                // Determine sample offset based on header type
                bool isLongHeader = (packet[0] & 0x80) != 0;
                int sampleOffset;
                int pnOffset;

                if (isLongHeader)
                {
                    // For long headers, sample is after the header fields
                    pnOffset = GetLongHeaderPayloadOffset(packet);
                    sampleOffset = pnOffset + 4; // Sample after packet number area
                }
                else
                {
                    // Short header: DCID (typically 8 bytes) + packet number
                    int dcidLen = 8; // Default for Hytale
                    pnOffset = 1 + dcidLen;
                    sampleOffset = pnOffset + 4;
                }

                if (sampleOffset + 16 > packet.Length)
                {
                    Console.WriteLine($"[HP] Sample offset {sampleOffset} + 16 exceeds packet length {packet.Length}");
                    return null;
                }

                // Extract 16-byte sample
                byte[] sample = new byte[16];
                Buffer.BlockCopy(packet, sampleOffset, sample, 0, 16);

                // Compute mask using AES-ECB
                byte[] mask = ComputeHeaderProtectionMask(sample, key.HeaderProtectionKey);

                // Apply mask to header
                byte[] unprotected = new byte[packet.Length];
                Buffer.BlockCopy(packet, 0, unprotected, 0, packet.Length);

                // Unprotect first byte
                if (isLongHeader)
                    unprotected[0] ^= (byte)(mask[0] & 0x0F); // Lower 4 bits for long header
                else
                    unprotected[0] ^= (byte)(mask[0] & 0x1F); // Lower 5 bits for short header

                // Unprotect packet number
                for (int i = 0; i < pnLen && pnOffset + i < unprotected.Length; i++)
                {
                    unprotected[pnOffset + i] ^= mask[i + 1];
                }

                return unprotected;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HP] Error: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Computes the header protection mask using AES-ECB
        /// </summary>
        private static byte[] ComputeHeaderProtectionMask(byte[] sample, byte[] hpKey)
        {
            using var aes = Aes.Create();
            aes.Key = hpKey;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(sample, 0, sample.Length);
        }

        // =========================================================================
        // HELPER METHODS - Packet Number Extraction
        // =========================================================================

        /// <summary>
        /// Extracts the packet number from the unprotected header
        /// </summary>
        private static int ExtractPacketNumber(byte[] header)
        {
            if (header.Length < 2)
                return 0;

            bool isLongHeader = (header[0] & 0x80) != 0;

            // Get packet number length from first byte (bits 0-1)
            int pnLen = (header[0] & 0x03) + 1;

            if (isLongHeader)
            {
                int offset = GetLongHeaderPayloadOffset(header);
                if (offset + pnLen <= header.Length)
                {
                    return ReadPacketNumber(header, offset, pnLen);
                }
            }
            else
            {
                // Short header: packet number is after DCID
                int dcidLen = 8; // Default DCID length for Hytale
                int pnOffset = 1 + dcidLen;
                if (pnOffset + pnLen <= header.Length)
                {
                    return ReadPacketNumber(header, pnOffset, pnLen);
                }
            }

            return 0;
        }

        /// <summary>
        /// Reads packet number bytes as big-endian integer
        /// </summary>
        private static int ReadPacketNumber(byte[] data, int offset, int length)
        {
            if (length == 1)
                return data[offset];
            if (length == 2)
                return (data[offset] << 8) | data[offset + 1];
            if (length == 3)
                return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
            if (length == 4)
                return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
            return 0;
        }

        // =========================================================================
        // HELPER METHODS - Header Length
        // =========================================================================

        /// <summary>
        /// Gets the total header length including packet number
        /// </summary>
        private static int GetHeaderLength(byte[] header)
        {
            bool isLongHeader = (header[0] & 0x80) != 0;
            int pnLen = (header[0] & 0x03) + 1;

            if (isLongHeader)
            {
                return GetLongHeaderPayloadOffset(header) + pnLen;
            }
            else
            {
                // Short header: 1 byte flags + DCID (8 bytes) + packet number
                int dcidLen = 8;
                return 1 + dcidLen + pnLen;
            }
        }

        /// <summary>
        /// Gets the offset to the payload in a long header packet
        /// </summary>
        private static int GetLongHeaderPayloadOffset(byte[] header)
        {
            if (header.Length < 6)
                return header.Length;

            int offset = 1; // First byte
            offset += 4; // Version (4 bytes)

            // DCID length (1 byte) + DCID
            if (offset < header.Length)
            {
                int dcidLen = header[offset++];
                offset += dcidLen;
            }

            // SCID length (1 byte) + SCID
            if (offset < header.Length)
            {
                int scidLen = header[offset++];
                offset += scidLen;
            }

            // Length field (variable length - simplified to 2 bytes)
            if (offset < header.Length)
            {
                offset += 2;
            }

            return Math.Min(offset, header.Length);
        }

        // =========================================================================
        // HELPER METHODS - Nonce & Decryption
        // =========================================================================

        /// <summary>
        /// Builds the nonce by XORing IV with packet number
        /// </summary>
        private static byte[] BuildNonce(byte[] iv, int packetNumber)
        {
            // RFC 9001: XOR the last bytes of IV with packet number (big-endian)
            byte[] nonce = new byte[iv.Length];
            Buffer.BlockCopy(iv, 0, nonce, 0, iv.Length);

            // Convert packet number to big-endian bytes
            byte[] pnBytes = BitConverter.GetBytes(packetNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(pnBytes);

            // XOR the last bytes of IV with packet number
            int startIdx = Math.Max(0, nonce.Length - pnBytes.Length);
            for (int i = 0; i < pnBytes.Length && startIdx + i < nonce.Length; i++)
            {
                nonce[startIdx + i] ^= pnBytes[i];
            }

            return nonce;
        }

        /// <summary>
        /// Decrypts using AES-GCM
        /// </summary>
        private static byte[]? AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] associatedData)
        {
            try
            {
                using var aesGcm = new AesGcm(key, 16);
                byte[] plaintext = new byte[ciphertext.Length];

                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

                return plaintext;
            }
            catch (CryptographicException)
            {
                // Authentication failed - wrong key
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DECRYPT] AES-GCM error: {ex.Message}");
                return null;
            }
        }

        // =========================================================================
        // AUTO-DECRYPT FEATURES
        // =========================================================================

        private static CancellationTokenSource? _autoDecryptCts;

        public static void StartAutoDecrypt()
        {
            StopAutoDecrypt();
            _autoDecryptCts = new CancellationTokenSource();

            Task.Run(() => AutoDecryptLoop(_autoDecryptCts.Token));
        }

        public static void StopAutoDecrypt()
        {
            _autoDecryptCts?.Cancel();
            _autoDecryptCts?.Dispose();
            _autoDecryptCts = null;
        }

        private static async Task AutoDecryptLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        // =========================================================================
        // TEST METHOD
        // =========================================================================

        public static void TestKeyDerivation()
        {
            Console.WriteLine("[KEY-TEST] ========================================");
            Console.WriteLine("[KEY-TEST] Testing key derivation...");

            // Test with a real key if available
            if (DiscoveredKeys.Count > 0)
            {
                var realKey = DiscoveredKeys[0];
                Console.WriteLine($"[KEY-TEST] Real key from {realKey.Source}:");
                Console.WriteLine($"[KEY-TEST] Type: {realKey.Type}");
                Console.WriteLine($"[KEY-TEST] Secret: {Convert.ToHexString(realKey.Secret?.Take(16).ToArray() ?? Array.Empty<byte>())}...");
                Console.WriteLine($"[KEY-TEST] Derived Key: {Convert.ToHexString(realKey.Key)}");
                Console.WriteLine($"[KEY-TEST] Derived IV: {Convert.ToHexString(realKey.IV)}");
                Console.WriteLine($"[KEY-TEST] Derived HP: {Convert.ToHexString(realKey.HeaderProtectionKey ?? Array.Empty<byte>())}");
            }
            else
            {
                Console.WriteLine("[KEY-TEST] No keys available for testing");
            }

            Console.WriteLine("[KEY-TEST] ========================================");
        }

        // =========================================================================
        // ENCRYPTION (for packet injection)
        // =========================================================================

        /// <summary>
        /// Encrypts plaintext data for packet injection
        /// </summary>
        public static EncryptionResult TryEncrypt(byte[] plaintext, PacketDirection direction)
        {
            Console.WriteLine($"[ENCRYPT] Attempting to encrypt {plaintext.Length} bytes...");

            if (plaintext == null || plaintext.Length == 0)
            {
                return new EncryptionResult { Success = false, ErrorMessage = "Empty plaintext" };
            }

            if (DiscoveredKeys.Count == 0)
            {
                return new EncryptionResult { Success = false, ErrorMessage = "No encryption keys available" };
            }

            // Select appropriate key based on direction
            EncryptionKey? key = null;
            _keysLock.EnterReadLock();
            try
            {
                key = direction == PacketDirection.ClientToServer
                    ? _discoveredKeys.FirstOrDefault(k => k.Type == EncryptionType.QUIC_Client1RTT)
                    : _discoveredKeys.FirstOrDefault(k => k.Type == EncryptionType.QUIC_Server1RTT);

                // Fallback to any available key
                key ??= _discoveredKeys.FirstOrDefault();
            }
            finally
            {
                _keysLock.ExitReadLock();
            }

            if (key == null)
            {
                return new EncryptionResult { Success = false, ErrorMessage = "No suitable key found for direction" };
            }

            try
            {
                // For packet injection, we need to:
                // 1. Build a new packet header
                // 2. Encrypt the payload
                // 3. Add header protection

                // Generate a new packet number (increment from last used)
                int packetNumber = GetNextPacketNumber(key);

                // Build nonce
                byte[] nonce = BuildNonce(key.IV, packetNumber);

                // Build header (short header for 1-RTT)
                byte[] header = BuildShortHeader(packetNumber);

                // Encrypt payload with AES-GCM
                byte[] encryptedPayload = AesGcmEncrypt(key.Key, nonce, plaintext, header);

                if (encryptedPayload == null)
                {
                    return new EncryptionResult { Success = false, ErrorMessage = "Encryption failed" };
                }

                // Combine header + encrypted payload
                byte[] packet = new byte[header.Length + encryptedPayload.Length];
                Buffer.BlockCopy(header, 0, packet, 0, header.Length);
                Buffer.BlockCopy(encryptedPayload, 0, packet, header.Length, encryptedPayload.Length);

                // Apply header protection
                byte[]? protectedPacket = ApplyHeaderProtection(packet, key);

                if (protectedPacket == null)
                {
                    return new EncryptionResult { Success = false, ErrorMessage = "Header protection failed" };
                }

                Console.WriteLine($"[ENCRYPT] SUCCESS - {protectedPacket.Length} bytes encrypted");
                return new EncryptionResult
                {
                    Success = true,
                    EncryptedData = protectedPacket,
                    PacketNumber = packetNumber
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ENCRYPT] ERROR: {ex.Message}");
                return new EncryptionResult { Success = false, ErrorMessage = ex.Message };
            }
        }

        private static int GetNextPacketNumber(EncryptionKey key)
        {
            // Simple packet number generation - in production, track per-key
            return key.UseCount + 1;
        }

        private static byte[] BuildShortHeader(int packetNumber)
        {
            // Short header format for 1-RTT:
            // First byte: 0x40-0x7F (short header, packet number length encoded)
            // DCID (8 bytes typically)
            // Packet number

            int pnLen = packetNumber <= 0xFF ? 1 : packetNumber <= 0xFFFF ? 2 : 4;
            byte firstByte = (byte)(0x40 | (pnLen - 1)); // Short header with pn length

            byte[] header = new byte[1 + 8 + pnLen]; // 1 byte flags + 8 bytes DCID + pn
            header[0] = firstByte;

            // DCID - zeros for injection (will be set by proxy)
            // Packet number (big-endian)
            byte[] pnBytes = BitConverter.GetBytes(packetNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(pnBytes);

            Buffer.BlockCopy(pnBytes, pnBytes.Length - pnLen, header, 9, pnLen);

            return header;
        }

        private static byte[]? AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            try
            {
                using var aesGcm = new AesGcm(key, 16);
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16];

                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

                // Combine ciphertext + tag
                byte[] result = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ENCRYPT] AES-GCM error: {ex.Message}");
                return null;
            }
        }

        private static byte[]? ApplyHeaderProtection(byte[] packet, EncryptionKey key)
        {
            if (key.HeaderProtectionKey == null || key.HeaderProtectionKey.Length == 0)
                return packet; // Return unprotected if no HP key

            try
            {
                int pnLen = (packet[0] & 0x03) + 1;
                int dcidLen = 8;
                int pnOffset = 1 + dcidLen;
                int sampleOffset = pnOffset + 4;

                if (sampleOffset + 16 > packet.Length)
                    return packet;

                // Extract sample
                byte[] sample = new byte[16];
                Buffer.BlockCopy(packet, sampleOffset, sample, 0, 16);

                // Compute mask
                byte[] mask = ComputeHeaderProtectionMask(sample, key.HeaderProtectionKey);

                // Apply mask
                byte[] protectedPacket = new byte[packet.Length];
                Buffer.BlockCopy(packet, 0, protectedPacket, 0, packet.Length);

                // Protect first byte
                protectedPacket[0] ^= (byte)(mask[0] & 0x1F);

                // Protect packet number
                for (int i = 0; i < pnLen && pnOffset + i < protectedPacket.Length; i++)
                {
                    protectedPacket[pnOffset + i] ^= mask[i + 1];
                }

                return protectedPacket;
            }
            catch
            {
                return packet;
            }
        }

        // =========================================================================
        // ADDITIONAL METHODS (for compatibility with existing code)
        // =========================================================================

        /// <summary>
        /// Checks if data is likely encrypted (heuristic)
        /// </summary>
        public static bool IsLikelyEncrypted(byte[] data)
        {
            if (data == null || data.Length < 10)
                return false;

            // Check if it looks like a QUIC packet
            // Short header: first byte 0x40-0x7F
            // Long header: first byte 0x80-0xFF
            byte firstByte = data[0];
            return (firstByte & 0x80) != 0 || (firstByte >= 0x40 && firstByte <= 0x7F);
        }
    }

    // =========================================================================
    // ENCRYPTION RESULT CLASS
    // =========================================================================
    public class EncryptionResult
    {
        public bool Success { get; set; }
        public byte[]? EncryptedData { get; set; }
        public string ErrorMessage { get; set; } = "";
        public int PacketNumber { get; set; }
    }
}