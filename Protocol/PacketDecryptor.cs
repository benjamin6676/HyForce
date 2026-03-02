using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace HyForce.Protocol;

public static class PacketDecryptor
{
    public enum EncryptionType
    {
        None,
        AES128GCM,
        AES256GCM,
        ChaCha20Poly1305,
        QUIC_ClientHandshake,
        QUIC_ServerHandshake,
        QUIC_Client0RTT,
        QUIC_Server0RTT,
        QUIC_Client1RTT,
        QUIC_Server1RTT,
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
        public int UseCount { get; set; }
        public byte[]? Secret { get; set; }
    }

    private static readonly List<EncryptionKey> _discoveredKeys = new();
    private static readonly ReaderWriterLockSlim _keysLock = new(LockRecursionPolicy.SupportsRecursion);
    private static int _successfulDecryptions = 0;
    private static int _failedDecryptions = 0;

    public static bool AutoDecryptEnabled { get; set; } = false;

    private static DateTime _lastDecryptAttempt = DateTime.MinValue;
    private static readonly TimeSpan _decryptCooldown = TimeSpan.FromSeconds(2);

    private const int MAX_KEYS = 20;

    // RFC 9001 QUIC-TLS labels
    private static readonly byte[] QUIC_CLIENT_HANDSHAKE_LABEL = Encoding.ASCII.GetBytes("client hs");
    private static readonly byte[] QUIC_SERVER_HANDSHAKE_LABEL = Encoding.ASCII.GetBytes("server hs");
    private static readonly byte[] QUIC_CLIENT_TRAFFIC_LABEL = Encoding.ASCII.GetBytes("client in");
    private static readonly byte[] QUIC_SERVER_TRAFFIC_LABEL = Encoding.ASCII.GetBytes("server in");
    private static readonly byte[] QUIC_KEY_LABEL = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QUIC_IV_LABEL = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] TLS13_LABEL_PREFIX = Encoding.ASCII.GetBytes("tls13 ");

    public static DecryptionResult TryDecrypt(byte[] encryptedData, byte[]? associatedData = null)
    {
        if (!AutoDecryptEnabled)
        {
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "Auto-decrypt disabled"
            };
        }

        if (DateTime.Now - _lastDecryptAttempt < _decryptCooldown)
        {
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "Throttled"
            };
        }
        _lastDecryptAttempt = DateTime.Now;

        if (encryptedData == null || encryptedData.Length < 16)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };
        }

        return TryDecryptInternal(encryptedData);
    }

    public static DecryptionResult TryDecryptManual(byte[] encryptedData)
    {
        if (encryptedData == null || encryptedData.Length < 16)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };
        }

        return TryDecryptInternal(encryptedData);
    }

    private static DecryptionResult TryDecryptInternal(byte[] encryptedData)
    {
        List<EncryptionKey> keysCopy;
        _keysLock.EnterReadLock();
        try
        {
            keysCopy = _discoveredKeys
                .Where(k => k.Key.Length >= 16)  // Must have actual key bytes
                .OrderByDescending(k => k.UseCount)
                .ThenByDescending(k => k.DiscoveredAt)
                .Take(5)
                .ToList();
        }
        finally
        {
            _keysLock.ExitReadLock();
        }

        if (keysCopy.Count == 0)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "No valid keys available" };
        }

        foreach (var key in keysCopy)
        {
            try
            {
                var result = TryDecryptWithKey(encryptedData, key);

                if (result.Success && result.DecryptedData != null && IsValidDecryptedData(result.DecryptedData))
                {
                    _keysLock.EnterWriteLock();
                    try { key.UseCount++; }
                    finally { _keysLock.ExitWriteLock(); }

                    Interlocked.Increment(ref _successfulDecryptions);
                    return result;
                }
            }
            catch { }
        }

        Interlocked.Increment(ref _failedDecryptions);
        return new DecryptionResult { Success = false, ErrorMessage = "No valid key found" };
    }

    /// <summary>
    /// FIXED: Derive QUIC packet keys from TLS 1.3 secrets using RFC 9001 HKDF-Expand-Label
    /// </summary>
    public static void DeriveQUICKeys(EncryptionKey key)
    {
        if (key.Secret == null || key.Secret.Length == 0) return;

        try
        {
            byte[] label;
            int keyLength = 16; // AES-128-GCM default

            // CRITICAL FIX: Only derive for QUIC types
            switch (key.Type)
            {
                case EncryptionType.QUIC_ClientHandshake:
                    label = QUIC_CLIENT_HANDSHAKE_LABEL;
                    break;
                case EncryptionType.QUIC_ServerHandshake:
                    label = QUIC_SERVER_HANDSHAKE_LABEL;
                    break;
                case EncryptionType.QUIC_Client1RTT:
                case EncryptionType.QUIC_Client0RTT:
                    label = QUIC_CLIENT_TRAFFIC_LABEL;
                    break;
                case EncryptionType.QUIC_Server1RTT:
                case EncryptionType.QUIC_Server0RTT:
                    label = QUIC_SERVER_TRAFFIC_LABEL;
                    break;
                default:
                    // Not a QUIC type, skip derivation
                    return;
            }

            // FIXED: Derive 16-byte AES-128-GCM key (QUIC uses 16 bytes, not 32!)
            key.Key = HkdfExpandLabel(key.Secret, QUIC_KEY_LABEL, Array.Empty<byte>(), keyLength);

            // FIXED: Derive 12-byte IV
            key.IV = HkdfExpandLabel(key.Secret, QUIC_IV_LABEL, Array.Empty<byte>(), 12);

            // Verify derivation succeeded
            if (key.Key.Length != keyLength || key.IV.Length != 12)
            {
                throw new CryptographicException("Key derivation produced invalid length");
            }

            Console.WriteLine($"[KEY-DERIVE] Derived {key.Type} keys: Key={BitConverter.ToString(key.Key).Replace("-", "")[..16]}..., IV={BitConverter.ToString(key.IV).Replace("-", "")}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KEY-DERIVE] Failed: {ex.Message}");
            key.Key = Array.Empty<byte>();
            key.IV = Array.Empty<byte>();
        }
    }

    private static byte[] HkdfExpandLabel(byte[] secret, byte[] label, byte[] context, int length)
    {
        var fullLabel = new List<byte>();

        fullLabel.Add((byte)(length >> 8));
        fullLabel.Add((byte)(length & 0xFF));

        fullLabel.Add((byte)(TLS13_LABEL_PREFIX.Length + label.Length));
        fullLabel.AddRange(TLS13_LABEL_PREFIX);
        fullLabel.AddRange(label);

        fullLabel.Add((byte)context.Length);
        fullLabel.AddRange(context);

        return HkdfExpand(secret, fullLabel.ToArray(), length);
    }

    private static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        var result = new List<byte>();
        var counter = 1;
        var previous = Array.Empty<byte>();

        using var hmac = new HMACSHA256(prk);

        while (result.Count < length)
        {
            var data = new List<byte>();
            data.AddRange(previous);
            data.AddRange(info);
            data.Add((byte)counter);

            var hash = hmac.ComputeHash(data.ToArray());
            result.AddRange(hash);

            previous = hash;
            counter++;
        }

        return result.Take(length).ToArray();
    }

    private static DecryptionResult TryDecryptWithKey(byte[] data, EncryptionKey key)
    {
        if (key?.Key == null || key.Key.Length != 16)
            return new DecryptionResult { Success = false, ErrorMessage = "Invalid key length" };

        if (data.Length < 50)
            return new DecryptionResult { Success = false, ErrorMessage = "Too small for QUIC" };

        return TryDecryptQUIC(data, key);
    }

    private static DecryptionResult TryDecryptQUIC(byte[] packetData, EncryptionKey key)
    {
        const int TAG_LENGTH = 16;
        const int NONCE_LENGTH = 12;

        try
        {
            bool isLongHeader = (packetData[0] & 0x80) != 0;
            int headerLen;

            if (isLongHeader)
            {
                if (packetData.Length < 6)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid long header" };

                int dcidLen = packetData[5];
                int offset = 6 + dcidLen;

                if (packetData.Length <= offset)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid DCID" };

                int scidLen = packetData[offset];
                offset += 1 + scidLen;
                offset += 2;

                int pnLen = 4;
                headerLen = Math.Min(offset + pnLen, packetData.Length - TAG_LENGTH);
                if (headerLen < 1) headerLen = Math.Min(20, packetData.Length - TAG_LENGTH);
            }
            else
            {
                headerLen = Math.Min(1 + 8 + 4, packetData.Length - TAG_LENGTH);
            }

            if (headerLen < 1 || headerLen > packetData.Length - TAG_LENGTH)
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid header length" };

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
            Buffer.BlockCopy(key.IV, 0, nonce, 0, NONCE_LENGTH);

            if (headerLen >= 4)
            {
                for (int i = 0; i < 4 && i < NONCE_LENGTH; i++)
                {
                    nonce[NONCE_LENGTH - 4 + i] ^= headerBytes[headerLen - 4 + i];
                }
            }

            using var aes = new AesGcm(key.Key, TAG_LENGTH);
            byte[] plaintext = new byte[ciphertextLength];
            aes.Decrypt(nonce, ciphertext, tag, plaintext, headerBytes);

            if (!IsValidDecryptedData(plaintext))
                return new DecryptionResult { Success = false, ErrorMessage = "Validation failed" };

            return new DecryptionResult
            {
                Success = true,
                DecryptedData = plaintext,
                DetectedType = EncryptionType.AES128GCM,
                Metadata = new Dictionary<string, object>
                {
                    ["algorithm"] = "AES-128-GCM",
                    ["original_size"] = packetData.Length,
                    ["decrypted_size"] = plaintext.Length,
                    ["header_type"] = isLongHeader ? "Long" : "Short"
                }
            };
        }
        catch (CryptographicException)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Auth failed" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static bool IsValidDecryptedData(byte[] data)
    {
        if (data.Length < 2) return false;

        double entropy = CalculateEntropy(data);
        if (entropy > 7.9) return false;

        bool hasValidHeader = data[0] <= 0x50;
        bool hasStrings = ContainsPrintableStrings(data, 4);

        return hasValidHeader || hasStrings || entropy < 6.0;
    }

    /// <summary>
    /// CRITICAL FIX: Parse SSLKEYLOGFILE and IMMEDIATELY derive QUIC keys
    /// </summary>
    public static void AddKeyFromSSLLog(string line, string sourceFile)
    {
        try
        {
            var parts = line.Split(' ');
            if (parts.Length < 3) return;

            string label = parts[0];
            string clientRandom = parts[1];
            string secretHex = parts[2];

            var secret = Convert.FromHexString(secretHex);

            if (secret.Length != 32 && secret.Length != 48) return;

            EncryptionType keyType;

            if (label.Contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
                keyType = EncryptionType.QUIC_ClientHandshake;
            else if (label.Contains("SERVER_HANDSHAKE_TRAFFIC_SECRET"))
                keyType = EncryptionType.QUIC_ServerHandshake;
            else if (label.Contains("CLIENT_TRAFFIC_SECRET_0"))
                keyType = EncryptionType.QUIC_Client1RTT;
            else if (label.Contains("SERVER_TRAFFIC_SECRET_0"))
                keyType = EncryptionType.QUIC_Server1RTT;
            else
                return;

            // CRITICAL FIX: Create key with secret, derive immediately, then add
            var key = new EncryptionKey
            {
                Secret = secret,
                Key = Array.Empty<byte>(),
                IV = Array.Empty<byte>(),
                Type = keyType,
                Source = $"{sourceFile}:{line.Length}"
            };

            // DERIVE KEYS BEFORE ADDING
            DeriveQUICKeys(key);

            // Only add if derivation succeeded
            if (key.Key.Length == 16 && key.IV.Length == 12)
            {
                AddKey(key);
                Console.WriteLine($"[SSL-LOG] Added derived {keyType} key from {sourceFile}");
            }
            else
            {
                Console.WriteLine($"[SSL-LOG] Failed to derive keys for {keyType}");
            }
        }
        catch (FormatException) { }
        catch (Exception ex)
        {
            Console.WriteLine($"[SSL-LOG] Error: {ex.Message}");
        }
    }

    public static void AddKey(EncryptionKey key)
    {
        if (key?.Key == null || key.Key.Length == 0) return;

        _keysLock.EnterWriteLock();
        try
        {
            // Check for duplicate keys
            foreach (var existing in _discoveredKeys)
            {
                if (existing.Key.SequenceEqual(key.Key))
                {
                    if (!existing.Source.Contains(key.Source))
                        existing.Source += $", {key.Source}";
                    return;
                }
            }

            if (_discoveredKeys.Count >= MAX_KEYS)
            {
                var leastUsed = _discoveredKeys.OrderBy(k => k.UseCount).First();
                _discoveredKeys.Remove(leastUsed);
            }

            _discoveredKeys.Add(key);
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
            Interlocked.Exchange(ref _successfulDecryptions, 0);
            Interlocked.Exchange(ref _failedDecryptions, 0);
        }
        finally
        {
            _keysLock.ExitWriteLock();
        }
    }

    // CRITICAL FIX: Deep copy under lock to prevent race conditions
    public static IReadOnlyList<EncryptionKey> DiscoveredKeys
    {
        get
        {
            _keysLock.EnterReadLock();
            try
            {
                // Return deep copies to prevent external modification
                return _discoveredKeys.Select(k => new EncryptionKey
                {
                    Key = k.Key.ToArray(),
                    IV = k.IV.ToArray(),
                    Type = k.Type,
                    Source = k.Source,
                    MemoryAddress = k.MemoryAddress,
                    DiscoveredAt = k.DiscoveredAt,
                    UseCount = k.UseCount,
                    Secret = k.Secret?.ToArray()
                }).ToList();
            }
            finally { _keysLock.ExitReadLock(); }
        }
    }

    public static int SuccessfulDecryptions => Interlocked.CompareExchange(ref _successfulDecryptions, 0, 0);
    public static int FailedDecryptions => Interlocked.CompareExchange(ref _failedDecryptions, 0, 0);

    public static event Action<EncryptionKey>? OnKeyDiscovered;

    public static bool IsLikelyEncrypted(byte[] data)
    {
        if (data.Length < 16) return false;
        return CalculateEntropy(data) > 7.5;
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
            else currentLength = 0;
        }
        return false;
    }
}