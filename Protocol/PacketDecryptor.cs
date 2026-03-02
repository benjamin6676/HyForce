// FILE: Protocol/PacketDecryptor.cs - ENHANCED WITH AUTO-EXTRACTION AND VALIDATION
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
    }

    public static List<EncryptionKey> DiscoveredKeys { get; } = new();
    public static event Action<EncryptionKey>? OnKeyDiscovered;
    public static int SuccessfulDecryptions { get; private set; }
    public static int FailedDecryptions { get; private set; }

    // Auto-extraction settings
    public static bool AutoExtractFromMemory { get; set; } = true;
    public static bool AutoExtractFromSSLLog { get; set; } = true;

    public static DecryptionResult TryDecrypt(byte[] encryptedData, byte[]? associatedData = null)
    {
        if (encryptedData == null || encryptedData.Length < 16)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };
        }

        // Try each discovered key with validation
        foreach (var key in DiscoveredKeys.OrderByDescending(k => k.DiscoveredAt))
        {
            var result = TryDecryptWithKey(encryptedData, key, associatedData);

            // Validate decrypted data looks reasonable
            if (result.Success && result.DecryptedData != null)
            {
                if (IsValidDecryptedData(result.DecryptedData))
                {
                    SuccessfulDecryptions++;
                    return result;
                }
                else
                {
                    result.Success = false;
                    result.ErrorMessage = "Key produced invalid data";
                }
            }
        }

        // Try common/default keys as last resort
        var defaultResult = TryCommonKeys(encryptedData, associatedData);
        if (defaultResult.Success)
        {
            SuccessfulDecryptions++;
            return defaultResult;
        }

        FailedDecryptions++;
        return new DecryptionResult { Success = false, ErrorMessage = "No valid decryption key found" };
    }

    // NEW: QUIC-specific decryption handling
    public static DecryptionResult TryDecryptQUIC(byte[] packetData, EncryptionKey key)
    {
        if (packetData.Length < 21) // Minimum QUIC packet size
            return new DecryptionResult { Success = false, ErrorMessage = "Packet too small for QUIC" };

        try
        {
            bool isLongHeader = (packetData[0] & 0x80) != 0;
            int headerLen;
            byte[]? headerBytes = null;

            if (isLongHeader)
            {
                // Long header: type(1) + version(4) + DCID len(1) + DCID + SCID len(1) + SCID + len(2) + PN
                if (packetData.Length < 7) return new DecryptionResult { Success = false };
                int dcidLen = packetData[5];
                int scidLen = packetData[6 + dcidLen];
                headerLen = 7 + dcidLen + scidLen + 2 + 4; // Approximate
                if (headerLen > packetData.Length) headerLen = 16; // Fallback
            }
            else
            {
                // Short header: type(1) + DCID (4-8 bytes typically) + PN (1-4 bytes)
                headerLen = 1 + 8; // Assume 8-byte DCID for Hytale
            }

            headerLen = Math.Min(headerLen, packetData.Length - 16);
            headerBytes = packetData[..headerLen];

            var ciphertext = packetData[headerLen..^16];
            var tag = packetData[^16..];

            // Build nonce from IV + packet number (simplified)
            var nonce = new byte[12];
            Array.Copy(key.IV, 0, nonce, 0, 12);

            // XOR packet number into nonce last bytes if available
            if (headerLen >= 4 && packetData.Length > headerLen)
            {
                for (int i = 0; i < 4 && i < (packetData.Length - headerLen); i++)
                {
                    nonce[8 + i] ^= packetData[headerLen - 4 + i];
                }
            }

            using var aes = new AesGcm(key.Key, 16);
            var plaintext = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintext, headerBytes);

            // Validate result
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
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult TryDecryptWithKey(byte[] data, EncryptionKey key, byte[]? associatedData)
    {
        try
        {
            // Try QUIC-specific handling first for UDP packets
            if (data.Length > 0 && (data[0] & 0x80) != 0 || data.Length > 1000)
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
        try
        {
            // Check minimum size: nonce(12) + ciphertext(1+) + tag(16)
            if (data.Length < 29)
                return new DecryptionResult { Success = false, ErrorMessage = "Data too short for AES-GCM" };

            using var aes = new AesGcm(key, 16);

            var nonce = data[..12];
            var ciphertext = data[12..^16];
            var tag = data[^16..];
            var plaintext = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            // Validate it looks like valid data
            if (!IsValidDecryptedData(plaintext))
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Validation failed" };
            }

            return new DecryptionResult
            {
                Success = true,
                DecryptedData = plaintext,
                DetectedType = EncryptionType.AES256GCM,
                Metadata =
                {
                    ["algorithm"] = "AES-GCM",
                    ["original_size"] = data.Length,
                    ["decrypted_size"] = plaintext.Length
                }
            };
        }
        catch
        {
            return new DecryptionResult { Success = false };
        }
    }

    private static DecryptionResult DecryptChaCha20(byte[] data, byte[] key, byte[] iv, byte[]? associatedData)
    {
        try
        {
            // ChaCha20-Poly1305: nonce(12) + ciphertext + tag(16)
            if (data.Length < 29 || key.Length != 32)
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid ChaCha20 data" };

            // Note: .NET 5+ doesn't have built-in ChaCha20, would need BouncyCastle
            // For now, return failure but mark as potential ChaCha20
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "ChaCha20 requires BouncyCastle library"
            };
        }
        catch
        {
            return new DecryptionResult { Success = false };
        }
    }

    private static DecryptionResult DecryptXOR(byte[] data, byte[] key)
    {
        if (key.Length == 0) return new DecryptionResult { Success = false, ErrorMessage = "Empty XOR key" };

        var result = new byte[data.Length];
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
        // Try all-zero keys (debug builds sometimes use these)
        var zeroKey16 = new byte[16];
        var zeroKey32 = new byte[32];

        var result = TryDecryptWithKey(data, new EncryptionKey
        {
            Key = zeroKey32,
            IV = new byte[12],
            Type = EncryptionType.AES256GCM,
            Source = "Common Debug Key"
        }, associatedData);

        if (result.Success) return result;

        // Try common debug keys
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

    // NEW: Validate decrypted data looks like valid protocol data
    private static bool IsValidDecryptedData(byte[] data)
    {
        if (data.Length < 2) return false;

        // Check for reasonable entropy (not too random, not too structured)
        double entropy = CalculateEntropy(data);
        if (entropy > 7.9) return false; // Still looks encrypted

        // Look for common QUIC/Hytale frame types
        byte firstByte = data[0];

        // Valid QUIC short header frame types
        bool hasValidFrame = firstByte <= 0x20 || // Common frames
                            (firstByte >= 0x40 && firstByte <= 0x7F) || // ACK frames
                            (firstByte >= 0x80 && firstByte <= 0xBF); // Stream frames

        // Or check for printable strings (protocol often contains strings)
        bool hasStrings = ContainsPrintableStrings(data, 4);

        // Or reasonable structure (not all zeros, not all same byte)
        bool hasStructure = data.Any(b => b != 0) && data.Distinct().Count() > 4;

        return hasValidFrame || hasStrings || (entropy < 6.0 && hasStructure);
    }

    public static void AddKey(EncryptionKey key)
    {
        if (key.Key == null || key.Key.Length == 0) return;

        // Check for duplicates
        if (!DiscoveredKeys.Any(k => k.Key.SequenceEqual(key.Key)))
        {
            DiscoveredKeys.Add(key);
            OnKeyDiscovered?.Invoke(key);
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

    // AUTO-EXTRACTION: Scan for TLS secrets in memory
    public static void AutoExtractKeysFromMemory(IntPtr processHandle)
    {
        if (!AutoExtractFromMemory) return;

        try
        {
            // This is called from MemoryTab - actual scanning happens there
            // This method is for external triggers
        }
        catch { }
    }

    // AUTO-EXTRACTION: Load from SSLKEYLOGFILE
    public static void AutoExtractFromSSLLogFile(string path)
    {
        if (!AutoExtractFromSSLLog || !File.Exists(path)) return;

        try
        {
            var lines = File.ReadAllLines(path);
            foreach (var line in lines)
            {
                // Parse: CLIENT_TRAFFIC_SECRET_0 <client_random> <secret_hex>
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
                    catch (FormatException) { /* Invalid hex */ }
                }
            }
        }
        catch { }
    }

    public static void ClearKeys()
    {
        DiscoveredKeys.Clear();
        SuccessfulDecryptions = 0;
        FailedDecryptions = 0;
    }

    public static EncryptionType DetectEncryptionType(byte[] packetData)
    {
        if (packetData == null || packetData.Length < 4)
            return EncryptionType.None;

        // Check for QUIC long header (0x80-0xFF first byte)
        if ((packetData[0] & 0x80) != 0)
        {
            return EncryptionType.AES256GCM; // QUIC uses AES-GCM or ChaCha20
        }

        // High entropy check
        double entropy = CalculateEntropy(packetData);
        if (entropy > 7.8)
            return EncryptionType.AES256GCM;

        if (entropy > 6.5)
            return EncryptionType.XOR; // Weak obfuscation

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
        if (data.Length == 0) return 0;

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
        return $"Keys: {DiscoveredKeys.Count}, Success: {SuccessfulDecryptions}, Failed: {FailedDecryptions}";
    }
}