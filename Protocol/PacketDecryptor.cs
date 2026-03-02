// FILE: Protocol/PacketDecryptor.cs - FIXED: Key limits and deduplication
using System.Security.Cryptography;
using System.Text;

namespace HyForce.Protocol;

public static class PacketDecryptor
{
    public enum EncryptionType
    {
        None,
        AES128GCM,
        AES256GCM,
        ChaCha20Poly1305,
        XOR,
        Custom
    }

    public class DecryptionResult
    {
        public bool Success { get; set; }
        public byte[]? DecryptedData { get; set; }
        public EncryptionType DetectedType { get; set; }
        public string ErrorMessage { get; set; } = "";
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class EncryptionKey
    {
        public byte[] Key { get; set; } = Array.Empty<byte>();
        public byte[] IV { get; set; } = Array.Empty<byte>();
        public EncryptionType Type { get; set; }
        public string Source { get; set; } = "";
        public IntPtr? MemoryAddress { get; set; }
        public DateTime DiscoveredAt { get; set; } = DateTime.Now;
        public int UseCount { get; set; } = 0; // Track successful uses
    }

    // FIXED: Thread-safe backing fields with strict limits
    private static readonly List<EncryptionKey> _discoveredKeys = new();
    private static readonly ReaderWriterLockSlim _keysLock = new(LockRecursionPolicy.SupportsRecursion);
    private static int _successfulDecryptions = 0;
    private static int _failedDecryptions = 0;

    // FIXED: Hard limits to prevent memory/performance issues
    private const int MAX_KEYS = 50; // Maximum keys to store
    private const int MAX_KEYS_PER_SOURCE = 10; // Max per file/source

    // Public accessors
    public static IReadOnlyList<EncryptionKey> DiscoveredKeys
    {
        get
        {
            _keysLock.EnterReadLock();
            try { return _discoveredKeys.ToList(); }
            finally { _keysLock.ExitReadLock(); }
        }
    }

    public static event Action<EncryptionKey>? OnKeyDiscovered;

    public static int SuccessfulDecryptions
    {
        get => Interlocked.CompareExchange(ref _successfulDecryptions, 0, 0);
        private set => Interlocked.Exchange(ref _successfulDecryptions, value);
    }

    public static int FailedDecryptions
    {
        get => Interlocked.CompareExchange(ref _failedDecryptions, 0, 0);
        private set => Interlocked.Exchange(ref _failedDecryptions, value);
    }

    // Auto-extraction settings
    public static bool AutoExtractFromMemory { get; set; } = true;
    public static bool AutoExtractFromSSLLog { get; set; } = true;

    public static DecryptionResult TryDecrypt(byte[] encryptedData, byte[]? associatedData = null)
    {
        if (encryptedData == null || encryptedData.Length < 16)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };
        }

        // FIXED: Get keys sorted by success rate (most used first)
        List<EncryptionKey> keysCopy;
        _keysLock.EnterReadLock();
        try
        {
            // Only try top 10 most successful keys for performance
            keysCopy = _discoveredKeys
                .OrderByDescending(k => k.UseCount)
                .ThenByDescending(k => k.DiscoveredAt)
                .Take(10)
                .ToList();
        }
        finally
        {
            _keysLock.ExitReadLock();
        }

        if (keysCopy.Count == 0)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "No keys available" };
        }

        // Try each key with validation
        foreach (var key in keysCopy)
        {
            var result = TryDecryptWithKey(encryptedData, key, associatedData);

            if (result.Success && result.DecryptedData != null)
            {
                if (IsValidDecryptedData(result.DecryptedData))
                {
                    // Increment use count for this key
                    _keysLock.EnterWriteLock();
                    try
                    {
                        key.UseCount++;
                    }
                    finally
                    {
                        _keysLock.ExitWriteLock();
                    }

                    Interlocked.Increment(ref _successfulDecryptions);
                    return result;
                }
            }
        }

        Interlocked.Increment(ref _failedDecryptions);
        return new DecryptionResult { Success = false, ErrorMessage = "No valid decryption key found" };
    }

    public static DecryptionResult TryDecryptQUIC(byte[] packetData, EncryptionKey key)
    {
        const int TAG_LENGTH = 16;
        const int NONCE_LENGTH = 12;
        const int MIN_PACKET_SIZE = 21;

        if (packetData == null || packetData.Length < MIN_PACKET_SIZE)
            return new DecryptionResult { Success = false, ErrorMessage = "Packet too small for QUIC" };

        if (key?.Key == null || (key.Key.Length != 32 && key.Key.Length != 16))
            return new DecryptionResult { Success = false, ErrorMessage = "Invalid key" };

        try
        {
            bool isLongHeader = (packetData[0] & 0x80) != 0;
            int headerLen;

            if (isLongHeader)
            {
                if (packetData.Length < 7)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid long header" };

                int dcidLen = packetData[5];
                if (packetData.Length < 6 + dcidLen + 1)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid DCID length" };

                int scidLen = packetData[6 + dcidLen];
                headerLen = 7 + dcidLen + scidLen + 2 + 4;

                if (headerLen > packetData.Length - TAG_LENGTH)
                    headerLen = Math.Min(16, packetData.Length - TAG_LENGTH);
            }
            else
            {
                headerLen = Math.Min(1 + 8, packetData.Length - TAG_LENGTH);
            }

            headerLen = Math.Max(1, Math.Min(headerLen, packetData.Length - TAG_LENGTH));

            byte[] headerBytes = new byte[headerLen];
            Buffer.BlockCopy(packetData, 0, headerBytes, 0, headerLen);

            int ciphertextLength = packetData.Length - headerLen - TAG_LENGTH;
            if (ciphertextLength < 1)
                return new DecryptionResult { Success = false, ErrorMessage = "No ciphertext" };

            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(packetData, headerLen, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[TAG_LENGTH];
            Buffer.BlockCopy(packetData, packetData.Length - TAG_LENGTH, tag, 0, TAG_LENGTH);

            byte[] nonce = new byte[NONCE_LENGTH];
            if (key.IV != null && key.IV.Length >= NONCE_LENGTH)
            {
                Buffer.BlockCopy(key.IV, 0, nonce, 0, NONCE_LENGTH);
            }

            if (headerLen >= 4 && packetData.Length > headerLen)
            {
                for (int i = 0; i < 4 && i < (packetData.Length - headerLen); i++)
                {
                    if (8 + i < NONCE_LENGTH)
                        nonce[8 + i] ^= packetData[headerLen - 4 + i];
                }
            }

            using var aes = new AesGcm(key.Key, TAG_LENGTH);
            byte[] plaintext = new byte[ciphertextLength];

            aes.Decrypt(nonce, ciphertext, tag, plaintext, headerBytes);

            if (!IsValidDecryptedData(plaintext))
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Decrypted data validation failed" };
            }

            return new DecryptionResult
            {
                Success = true,
                DecryptedData = plaintext,
                DetectedType = EncryptionType.AES256GCM,
                Metadata =
                {
                    ["algorithm"] = "AES-256-GCM",
                    ["original_size"] = packetData.Length,
                    ["decrypted_size"] = plaintext.Length,
                    ["header_len"] = headerLen,
                    ["quic_header_type"] = isLongHeader ? "Long" : "Short"
                }
            };
        }
        catch (CryptographicException ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = $"Decryption failed: {ex.Message}" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult TryDecryptWithKey(byte[] data, EncryptionKey key, byte[]? associatedData)
    {
        try
        {
            bool looksLikeQuic = (data.Length > 0 && (data[0] & 0x80) != 0) || data.Length > 1000;

            if (looksLikeQuic)
            {
                var quicResult = TryDecryptQUIC(data, key);
                if (quicResult.Success) return quicResult;
            }

            return key.Type switch
            {
                EncryptionType.AES128GCM or EncryptionType.AES256GCM =>
                    DecryptAESGCM(data, key.Key, key.IV, associatedData),
                EncryptionType.ChaCha20Poly1305 =>
                    DecryptChaCha20(data, key.Key, key.IV, associatedData),
                EncryptionType.XOR =>
                    DecryptXOR(data, key.Key),
                _ => new DecryptionResult { Success = false, ErrorMessage = "Unknown key type" }
            };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult DecryptAESGCM(byte[] data, byte[] key, byte[] iv, byte[]? associatedData)
    {
        const int NONCE_LENGTH = 12;
        const int TAG_LENGTH = 16;

        try
        {
            if (data.Length < NONCE_LENGTH + 1 + TAG_LENGTH)
                return new DecryptionResult { Success = false, ErrorMessage = "Data too short for AES-GCM" };

            if (key.Length != 16 && key.Length != 32)
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid key length" };

            using var aes = new AesGcm(key, TAG_LENGTH);

            byte[] nonce = new byte[NONCE_LENGTH];
            Buffer.BlockCopy(data, 0, nonce, 0, NONCE_LENGTH);

            int ciphertextLength = data.Length - NONCE_LENGTH - TAG_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(data, NONCE_LENGTH, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[TAG_LENGTH];
            Buffer.BlockCopy(data, data.Length - TAG_LENGTH, tag, 0, TAG_LENGTH);

            byte[] plaintext = new byte[ciphertextLength];

            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            if (!IsValidDecryptedData(plaintext))
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Validation failed" };
            }

            return new DecryptionResult
            {
                Success = true,
                DecryptedData = plaintext,
                DetectedType = key.Length == 32 ? EncryptionType.AES256GCM : EncryptionType.AES128GCM,
                Metadata =
                {
                    ["algorithm"] = "AES-GCM",
                    ["original_size"] = data.Length,
                    ["decrypted_size"] = plaintext.Length
                }
            };
        }
        catch (CryptographicException)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Authentication failed" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult DecryptChaCha20(byte[] data, byte[] key, byte[] iv, byte[]? associatedData)
    {
        return new DecryptionResult
        {
            Success = false,
            ErrorMessage = "ChaCha20 requires BouncyCastle library"
        };
    }

    private static DecryptionResult DecryptXOR(byte[] data, byte[] key)
    {
        if (key == null || key.Length == 0)
            return new DecryptionResult { Success = false, ErrorMessage = "Empty XOR key" };

        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }

        double entropy = CalculateEntropy(result);
        bool looksValid = entropy < 6.0 && ContainsPrintableStrings(result);

        return new DecryptionResult
        {
            Success = looksValid,
            DecryptedData = result,
            DetectedType = EncryptionType.XOR,
            Metadata =
            {
                ["entropy"] = entropy,
                ["key_length"] = key.Length
            }
        };
    }

    private static DecryptionResult TryCommonKeys(byte[] data, byte[]? associatedData)
    {
        var zeroKey32 = new byte[32];

        var result = TryDecryptWithKey(data, new EncryptionKey
        {
            Key = zeroKey32,
            IV = new byte[12],
            Type = EncryptionType.AES256GCM,
            Source = "Common Debug Key"
        }, associatedData);

        if (result.Success) return result;

        var debugKeys = new[]
        {
            "HYTALE_DEBUG_KEY_32_BYTES_LONG!!",
            "0123456789abcdef0123456789abcdef",
            "hytalehytalehytalehytalehytale12",
            "QUIC_DEBUG_KEY_32_BYTES_LONG!!",
            "HytaleHytaleHytaleHytaleHytale!!"
        };

        foreach (var debugKey in debugKeys)
        {
            var keyBytes = Encoding.ASCII.GetBytes(debugKey);
            if (keyBytes.Length == 32)
            {
                result = TryDecryptWithKey(data, new EncryptionKey
                {
                    Key = keyBytes,
                    IV = new byte[12],
                    Type = EncryptionType.AES256GCM,
                    Source = "Common Debug Key"
                }, associatedData);

                if (result.Success)
                {
                    result.Metadata["key_source"] = "common_debug";
                    return result;
                }
            }
        }

        return new DecryptionResult { Success = false };
    }

    private static bool IsValidDecryptedData(byte[] data)
    {
        if (data.Length < 2) return false;

        double entropy = CalculateEntropy(data);
        if (entropy > 7.9) return false;

        byte firstByte = data[0];

        bool hasValidFrame = firstByte <= 0x20 ||
                            (firstByte >= 0x40 && firstByte <= 0x7F) ||
                            (firstByte >= 0x80 && firstByte <= 0xBF);

        bool hasStrings = ContainsPrintableStrings(data, 4);
        bool hasStructure = data.Any(b => b != 0) && data.Distinct().Count() > 4;

        return hasValidFrame || hasStrings || (entropy < 6.0 && hasStructure);
    }

    // FIXED: Smart deduplication and limits
    public static void AddKey(EncryptionKey key)
    {
        if (key?.Key == null || key.Key.Length == 0) return;

        _keysLock.EnterWriteLock();
        try
        {
            // Check for exact duplicate
            foreach (var existing in _discoveredKeys)
            {
                if (existing.Key.SequenceEqual(key.Key))
                {
                    // Update source if new info
                    if (!existing.Source.Contains(key.Source))
                    {
                        existing.Source += $", {key.Source}";
                    }
                    return; // Don't add duplicate
                }
            }

            // Check per-source limit
            var sourceCount = _discoveredKeys.Count(k => k.Source.StartsWith(key.Source.Split(':')[0]));
            if (sourceCount >= MAX_KEYS_PER_SOURCE)
            {
                // Remove oldest from this source
                var oldest = _discoveredKeys
                    .Where(k => k.Source.StartsWith(key.Source.Split(':')[0]))
                    .OrderBy(k => k.DiscoveredAt)
                    .First();
                _discoveredKeys.Remove(oldest);
            }

            // Check global limit
            if (_discoveredKeys.Count >= MAX_KEYS)
            {
                // Remove least used key
                var leastUsed = _discoveredKeys.OrderBy(k => k.UseCount).ThenBy(k => k.DiscoveredAt).First();
                _discoveredKeys.Remove(leastUsed);
            }

            _discoveredKeys.Add(key);

            // Invoke outside lock
            var handler = OnKeyDiscovered;
            _keysLock.ExitWriteLock();
            handler?.Invoke(key);
            return;
        }
        finally
        {
            if (_keysLock.IsWriteLockHeld)
                _keysLock.ExitWriteLock();
        }
    }

    public static void AddKeyFromMemory(IntPtr address, byte[] keyData, EncryptionType type, string source)
    {
        AddKey(new EncryptionKey
        {
            Key = keyData,
            IV = new byte[12],
            Type = type,
            Source = source,
            MemoryAddress = address
        });
    }

    public static void AutoExtractKeysFromMemory(IntPtr processHandle)
    {
        if (!AutoExtractFromMemory) return;
    }

    public static void AutoExtractFromSSLLogFile(string path)
    {
        if (!AutoExtractFromSSLLog || !File.Exists(path)) return;

        try
        {
            var lines = File.ReadAllLines(path);
            foreach (var line in lines)
            {
                var parts = line.Split(' ');
                if (parts.Length >= 3 &&
                    (parts[0].Contains("TRAFFIC_SECRET") || parts[0].Contains("HANDSHAKE_TRAFFIC_SECRET")))
                {
                    try
                    {
                        var secret = Convert.FromHexString(parts[2]);
                        if (secret.Length == 32 || secret.Length == 48)
                        {
                            AddKey(new EncryptionKey
                            {
                                Key = secret,
                                IV = new byte[12],
                                Type = secret.Length == 32 ? EncryptionType.AES256GCM : EncryptionType.ChaCha20Poly1305,
                                Source = $"SSLLog:{Path.GetFileName(path)}"
                            });
                        }
                    }
                    catch (FormatException) { }
                }
            }
        }
        catch { }
    }

    public static void ClearKeys()
    {
        _keysLock.EnterWriteLock();
        try
        {
            _discoveredKeys.Clear();
            Interlocked.Exchange(ref _successfulDecryptions, 0);
            Interlocked.Exchange(ref _failedDecryptions, 0);
        }
        finally
        {
            _keysLock.ExitWriteLock();
        }
    }

    public static EncryptionType DetectEncryptionType(byte[] packetData)
    {
        if (packetData == null || packetData.Length < 4)
            return EncryptionType.None;

        if ((packetData[0] & 0x80) != 0)
        {
            return EncryptionType.AES256GCM;
        }

        double entropy = CalculateEntropy(packetData);
        if (entropy > 7.8)
            return EncryptionType.AES256GCM;

        if (entropy > 6.5)
            return EncryptionType.XOR;

        return EncryptionType.None;
    }

    public static bool IsLikelyEncrypted(byte[] data)
    {
        if (data.Length < 16) return false;
        double entropy = CalculateEntropy(data);
        return entropy > 7.5;
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0;

        var freq = new int[256];
        foreach (var b in data) freq[b]++;

        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool ContainsPrintableStrings(byte[] data, int minLength = 4)
    {
        if (data == null) return false;

        int currentLength = 0;
        foreach (var b in data)
        {
            if (b >= 32 && b <= 126)
            {
                currentLength++;
                if (currentLength >= minLength) return true;
            }
            else
            {
                currentLength = 0;
            }
        }
        return false;
    }

    public static string GetStats()
    {
        int keys, success, failed;

        _keysLock.EnterReadLock();
        try { keys = _discoveredKeys.Count; }
        finally { _keysLock.ExitReadLock(); }

        success = SuccessfulDecryptions;
        failed = FailedDecryptions;

        return $"Keys: {keys}, Success: {success}, Failed: {failed}";
    }
}