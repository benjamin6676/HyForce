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
        public ulong PacketNumber { get; set; }
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
    private static readonly TimeSpan _decryptCooldown = TimeSpan.FromSeconds(1);
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
            return new DecryptionResult { Success = false, ErrorMessage = "Auto-decrypt disabled" };

        if (DateTime.Now - _lastDecryptAttempt < _decryptCooldown)
            return new DecryptionResult { Success = false, ErrorMessage = "Throttled" };

        _lastDecryptAttempt = DateTime.Now;

        if (encryptedData == null || encryptedData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };

        return TryDecryptInternal(encryptedData);
    }

    public static DecryptionResult TryDecryptManual(byte[] encryptedData)
    {
        if (encryptedData == null || encryptedData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };

        return TryDecryptInternal(encryptedData);
    }

    private static DecryptionResult TryDecryptInternal(byte[] encryptedData)
    {
        List<EncryptionKey> keysCopy;
        _keysLock.EnterReadLock();
        try
        {
            keysCopy = _discoveredKeys
                .Where(k => k.Key.Length >= 16)
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
            return new DecryptionResult { Success = false, ErrorMessage = "No valid keys available" };

        // Try each key with brute-force packet number search
        foreach (var key in keysCopy)
        {
            try
            {
                // FIX 1: Use brute-force PN search first (0-5000 range)
                var result = TryDecryptWithBruteForcePN(encryptedData, key);

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

    // FIX 1: Brute-force packet number search (0-5000)
    private static DecryptionResult TryDecryptWithBruteForcePN(byte[] packetData, EncryptionKey key)
    {
        const int MAX_PN = 5000;

        // Try common packet numbers first (0-100 are most common)
        for (ulong pn = 0; pn < 100; pn++)
        {
            var result = TryDecryptQUIC(packetData, key, pn);
            if (result.Success) return result;
        }

        // Try packet numbers 100-5000
        for (ulong pn = 100; pn < MAX_PN; pn++)
        {
            var result = TryDecryptQUIC(packetData, key, pn);
            if (result.Success)
            {
                Console.WriteLine($"[DECRYPT] Success with packet number {pn}");
                return result;
            }
        }

        return new DecryptionResult { Success = false, ErrorMessage = "Brute force failed" };
    }

    // FIX 1: RFC 9001 compliant QUIC decryption with correct nonce construction
    private static DecryptionResult TryDecryptQUIC(byte[] packetData, EncryptionKey key, ulong packetNumber)
    {
        const int TAG_LENGTH = 16;
        const int NONCE_LENGTH = 12;

        try
        {
            if (packetData.Length < 20)
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too small" };

            // Parse header
            byte firstByte = packetData[0];
            bool isLongHeader = (firstByte & 0x80) != 0;

            int headerLen;
            byte[] headerBytes;
            byte[] payload;

            if (isLongHeader)
            {
                // Long header parsing
                if (packetData.Length < 7)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid long header" };

                int offset = 5; // After flags + version
                int dcidLen = packetData[offset];
                offset += 1 + dcidLen;
                if (packetData.Length <= offset)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid DCID" };

                int scidLen = packetData[offset];
                offset += 1 + scidLen;
                if (packetData.Length <= offset + 2)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid SCID" };

                offset += 2;

                headerLen = Math.Min(offset + 4, packetData.Length - TAG_LENGTH - 1);
                if (headerLen < 1)
                    return new DecryptionResult { Success = false, ErrorMessage = "Header too short" };

                headerBytes = new byte[headerLen];
                Buffer.BlockCopy(packetData, 0, headerBytes, 0, headerLen);

                int payloadLen = packetData.Length - headerLen - TAG_LENGTH;
                if (payloadLen < 0)
                    return new DecryptionResult { Success = false, ErrorMessage = "Negative payload" };

                payload = new byte[payloadLen];
                Buffer.BlockCopy(packetData, headerLen, payload, 0, payloadLen);
            }
            else
            {
                // Short header
                int dcidLen = 8;
                headerLen = 1 + dcidLen + 2;

                if (packetData.Length < headerLen + TAG_LENGTH)
                    return new DecryptionResult { Success = false, ErrorMessage = "Short packet" };

                headerBytes = new byte[headerLen];
                Buffer.BlockCopy(packetData, 0, headerBytes, 0, headerLen);

                int payloadLen = packetData.Length - headerLen - TAG_LENGTH;
                payload = new byte[payloadLen];
                Buffer.BlockCopy(packetData, headerLen, payload, 0, payloadLen);
            }

            // FIX 1: RFC 9001 compliant nonce construction
            // "The 62 bits of the reconstructed QUIC packet number in network byte order 
            //  are left-padded with zeros to the size of the IV. The exclusive OR of the 
            //  padded packet number and the IV forms the AEAD nonce."

            byte[] nonce = new byte[NONCE_LENGTH];
            Buffer.BlockCopy(key.IV, 0, nonce, 0, NONCE_LENGTH);

            // Left-pad packet number (62 bits) to 96 bits (12 bytes)
            // Packet number goes in the LAST bytes, big-endian
            // We use bytes 4-11 (8 bytes) for the 62-bit packet number
            // Bytes 0-3 remain as IV (32 bits of padding)

            byte[] pnBytes = new byte[8];
            pnBytes[0] = (byte)(packetNumber >> 56);
            pnBytes[1] = (byte)(packetNumber >> 48);
            pnBytes[2] = (byte)(packetNumber >> 40);
            pnBytes[3] = (byte)(packetNumber >> 32);
            pnBytes[4] = (byte)(packetNumber >> 24);
            pnBytes[5] = (byte)(packetNumber >> 16);
            pnBytes[6] = (byte)(packetNumber >> 8);
            pnBytes[7] = (byte)(packetNumber);

            // XOR with IV starting at byte 4 (leaving 4 bytes = 32 bits padding)
            for (int i = 0; i < 8; i++)
            {
                nonce[4 + i] ^= pnBytes[i];
            }

            // Extract authentication tag
            byte[] tag = new byte[TAG_LENGTH];
            Buffer.BlockCopy(packetData, packetData.Length - TAG_LENGTH, tag, 0, TAG_LENGTH);

            // Decrypt
            using var aes = new AesGcm(key.Key, TAG_LENGTH);
            byte[] plaintext = new byte[payload.Length];
            aes.Decrypt(nonce, payload, tag, plaintext, headerBytes);

            // Validate
            if (!IsValidDecryptedData(plaintext))
                return new DecryptionResult { Success = false, ErrorMessage = "Validation failed" };

            return new DecryptionResult
            {
                Success = true,
                DecryptedData = plaintext,
                DetectedType = EncryptionType.AES128GCM,
                PacketNumber = packetNumber,
                Metadata = new Dictionary<string, object>
                {
                    ["algorithm"] = "AES-128-GCM",
                    ["original_size"] = packetData.Length,
                    ["decrypted_size"] = plaintext.Length,
                    ["header_type"] = isLongHeader ? "Long" : "Short",
                    ["packet_number"] = packetNumber
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

    public static void DeriveQUICKeys(EncryptionKey key)
    {
        if (key.Secret == null || key.Secret.Length == 0) return;

        try
        {
            byte[] label;
            int keyLength = 16; // AES-128-GCM

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
                    return;
            }

            key.Key = HkdfExpandLabel(key.Secret, QUIC_KEY_LABEL, Array.Empty<byte>(), keyLength);
            key.IV = HkdfExpandLabel(key.Secret, QUIC_IV_LABEL, Array.Empty<byte>(), 12);

            Console.WriteLine($"[KEY-DERIVE] {key.Type}: Key={BitConverter.ToString(key.Key)[..16]}..., IV={BitConverter.ToString(key.IV)}");
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

    private static bool IsValidDecryptedData(byte[] data)
    {
        if (data.Length < 2) return false;

        double entropy = CalculateEntropy(data);

        bool hasPrintable = data.Any(b => b >= 32 && b <= 126);
        bool reasonableLength = data.Length >= 4 && data.Length < 10000;
        bool reasonableEntropy = entropy > 2.0 && entropy < 7.8;
        bool hasOpcodePattern = data.Length >= 2 && data[0] < 0x50;

        return reasonableLength && reasonableEntropy && (hasPrintable || hasOpcodePattern);
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

    public static void AddKey(EncryptionKey key)
    {
        if (key?.Key == null || key.Key.Length == 0) return;

        _keysLock.EnterWriteLock();
        try
        {
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

    public static IReadOnlyList<EncryptionKey> DiscoveredKeys
    {
        get
        {
            _keysLock.EnterReadLock();
            try
            {
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
}