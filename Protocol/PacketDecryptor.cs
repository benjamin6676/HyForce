// FILE: Protocol/PacketDecryptor.cs - FIXED: Proper async decryption without blocking UI
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;
using System.Threading.Channels;

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
        public TimeSpan Duration { get; set; }
    }

    public class EncryptionKey
    {
        public byte[] Key { get; set; } = Array.Empty<byte>();
        public byte[] IV { get; set; } = Array.Empty<byte>();
        public byte[]? HeaderProtectionKey { get; set; }
        public EncryptionType Type { get; set; }
        public string Source { get; set; } = "";
        public IntPtr? MemoryAddress { get; set; }
        public DateTime DiscoveredAt { get; set; } = DateTime.Now;
        public int UseCount { get; set; }
        public byte[]? Secret { get; set; }
        public ulong HighestReceivedPN { get; set; }
    }

    private static readonly List<EncryptionKey> _discoveredKeys = new();
    private static readonly ReaderWriterLockSlim _keysLock = new(LockRecursionPolicy.SupportsRecursion);
    private static long _successfulDecryptions = 0;
    private static long _failedDecryptions = 0;
    private static long _skippedDecryptions = 0;

    // FIXED: Auto-decrypt disabled by default to prevent lag
    public static bool AutoDecryptEnabled { get; set; } = false;

    // FIXED: Throttling settings - much more conservative
    public static int MaxDecryptsPerSecond { get; set; } = 2; // Reduced from 10
    private static readonly RateLimiter _rateLimiter = new RateLimiter(2, TimeSpan.FromSeconds(1));

    // FIXED: Background processing channel with bounded capacity
    private static Channel<DecryptJob>? _decryptChannel;
    private static CancellationTokenSource? _autoDecryptCts;
    private static Task? _autoDecryptWorker;

    // Statistics for UI
    public static long QueueLength => _decryptChannel?.Reader.Count ?? 0;
    public static bool IsProcessing { get; private set; }

    // RFC 9001 labels
    private static readonly byte[] QUIC_CLIENT_HANDSHAKE_LABEL = Encoding.ASCII.GetBytes("client hs");
    private static readonly byte[] QUIC_SERVER_HANDSHAKE_LABEL = Encoding.ASCII.GetBytes("server hs");
    private static readonly byte[] QUIC_CLIENT_TRAFFIC_LABEL = Encoding.ASCII.GetBytes("client in");
    private static readonly byte[] QUIC_SERVER_TRAFFIC_LABEL = Encoding.ASCII.GetBytes("server in");
    private static readonly byte[] QUIC_KEY_LABEL = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QUIC_IV_LABEL = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QUIC_HP_LABEL = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] TLS13_LABEL_PREFIX = Encoding.ASCII.GetBytes("tls13 ");

    private const int AES_GCM_TAG_LENGTH = 16;
    private const int MAX_PN_BRUTE_FORCE = 20; // REDUCED from 100 to prevent lag

    // FIXED: Job struct for channel
    private readonly struct DecryptJob
    {
        public byte[] Data { get; }
        public TaskCompletionSource<DecryptionResult> Completion { get; }
        public DateTime Enqueued { get; }

        public DecryptJob(byte[] data)
        {
            Data = data;
            Completion = new TaskCompletionSource<DecryptionResult>();
            Enqueued = DateTime.Now;
        }
    }

    // FIXED: Start/stop auto-decrypt worker with proper cleanup
    public static void StartAutoDecrypt()
    {
        if (_autoDecryptWorker != null) return; // Already running

        _autoDecryptCts = new CancellationTokenSource();

        // FIXED: Use bounded channel to prevent memory buildup
        _decryptChannel = Channel.CreateBounded<DecryptJob>(new BoundedChannelOptions(50)
        {
            FullMode = BoundedChannelFullMode.DropOldest, // Drop old jobs if full
            SingleReader = true,
            SingleWriter = false
        });

        _autoDecryptWorker = Task.Run(() => AutoDecryptWorker(_autoDecryptCts.Token));
        AutoDecryptEnabled = true;
    }

    public static void StopAutoDecrypt()
    {
        AutoDecryptEnabled = false;

        try
        {
            _autoDecryptCts?.Cancel();
        }
        catch { }

        // Complete the channel to stop the worker
        try
        {
            _decryptChannel?.Writer.Complete();
        }
        catch { }

        // Wait for worker to finish (with short timeout)
        if (_autoDecryptWorker != null)
        {
            try
            {
                _autoDecryptWorker.Wait(TimeSpan.FromMilliseconds(500));
            }
            catch { }
        }

        _autoDecryptWorker = null;
        _autoDecryptCts = null;
        _decryptChannel = null;
        IsProcessing = false;
    }

    // FIXED: Background worker that processes decrypt jobs without throwing
    private static async Task AutoDecryptWorker(CancellationToken ct)
    {
        if (_decryptChannel == null) return;

        IsProcessing = true;
        try
        {
            await foreach (var job in _decryptChannel.Reader.ReadAllAsync(ct))
            {
                // FIXED: Check cancellation without throwing
                if (ct.IsCancellationRequested)
                {
                    job.Completion.TrySetCanceled();
                    continue;
                }

                if (!_rateLimiter.TryAcquire())
                {
                    Interlocked.Increment(ref _skippedDecryptions);
                    job.Completion.TrySetResult(new DecryptionResult
                    {
                        Success = false,
                        ErrorMessage = "Rate limited"
                    });
                    continue;
                }

                // FIXED: Run decryption with proper exception handling - NO THROWING
                try
                {
                    var result = await Task.Run(() => TryDecryptInternalSafe(job.Data, ct), ct);
                    job.Completion.TrySetResult(result);
                }
                catch (OperationCanceledException)
                {
                    job.Completion.TrySetCanceled();
                }
                catch (Exception ex)
                {
                    job.Completion.TrySetResult(new DecryptionResult
                    {
                        Success = false,
                        ErrorMessage = ex.Message
                    });
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown, ignore
        }
        catch (ChannelClosedException)
        {
            // Normal shutdown, ignore
        }
        finally
        {
            IsProcessing = false;
        }
    }

    // FIXED: Safe version that doesn't throw OperationCanceledException
    private static DecryptionResult TryDecryptInternalSafe(byte[] encryptedData, CancellationToken ct)
    {
        try
        {
            return TryDecryptInternal(encryptedData, ct);
        }
        catch (OperationCanceledException)
        {
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "Cancelled"
            };
        }
        catch (Exception ex)
        {
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = ex.Message
            };
        }
    }

    // BACKWARD COMPATIBILITY: Old synchronous TryDecrypt - now non-blocking
    public static DecryptionResult TryDecrypt(byte[] encryptedData)
    {
        if (!AutoDecryptEnabled)
            return new DecryptionResult { Success = false, ErrorMessage = "Auto-decrypt disabled" };

        // If auto-decrypt is running, enqueue and return immediately with pending status
        if (_decryptChannel != null)
        {
            var job = new DecryptJob(encryptedData);
            var written = _decryptChannel.Writer.TryWrite(job);

            if (!written)
            {
                Interlocked.Increment(ref _skippedDecryptions);
                return new DecryptionResult
                {
                    Success = false,
                    ErrorMessage = "Queue full"
                };
            }

            // Return immediately - don't wait for result (non-blocking)
            // The result will be processed in background
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "Queued for background processing"
            };
        }

        // Fallback to manual decrypt if auto-decrypt not started
        return TryDecryptManual(encryptedData);
    }

    // FIXED: Manual decrypt - synchronous but with timeout
    public static DecryptionResult TryDecryptManual(byte[] encryptedData, int timeoutMs = 2000) // Reduced from 5000
    {
        if (encryptedData == null || encryptedData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };

        var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            // Run on thread pool with timeout
            var task = Task.Run(() => TryDecryptInternalSafe(encryptedData, cts.Token), cts.Token);

            if (task.Wait(timeoutMs))
            {
                return task.Result;
            }
            else
            {
                cts.Cancel();
                return new DecryptionResult { Success = false, ErrorMessage = "Timeout" };
            }
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
        finally
        {
            cts.Dispose();
        }
    }

    // FIXED: Async manual decrypt for UI
    public static async Task<DecryptionResult> TryDecryptManualAsync(byte[] encryptedData, int timeoutMs = 2000, CancellationToken ct = default)
    {
        if (encryptedData == null || encryptedData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };

        using var timeoutCts = new CancellationTokenSource(timeoutMs);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token, ct);

        try
        {
            return await Task.Run(() => TryDecryptInternalSafe(encryptedData, linkedCts.Token), linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            return new DecryptionResult { Success = false, ErrorMessage = "Cancelled or timeout" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult TryDecryptInternal(byte[] encryptedData, CancellationToken ct)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        List<EncryptionKey> keysCopy;
        _keysLock.EnterReadLock();
        try
        {
            keysCopy = _discoveredKeys
                .Where(k => k.Key.Length >= 16 && k.IV.Length == 12)
                .OrderByDescending(k => k.UseCount)
                .Take(2) // Further reduced from 3
                .ToList();
        }
        finally
        {
            _keysLock.ExitReadLock();
        }

        if (keysCopy.Count == 0)
        {
            stopwatch.Stop();
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "No valid keys",
                Duration = stopwatch.Elapsed
            };
        }

        foreach (var key in keysCopy)
        {
            // FIXED: Check cancellation without throwing
            if (ct.IsCancellationRequested)
            {
                stopwatch.Stop();
                return new DecryptionResult
                {
                    Success = false,
                    ErrorMessage = "Cancelled",
                    Duration = stopwatch.Elapsed
                };
            }

            try
            {
                var result = TryDecryptQuicPacketSafe(encryptedData, key, ct);
                if (result.Success && result.DecryptedData != null && IsValidDecryptedData(result.DecryptedData))
                {
                    UpdateKeyStats(key, result.PacketNumber);
                    Interlocked.Increment(ref _successfulDecryptions);
                    result.Duration = stopwatch.Elapsed;
                    return result;
                }
            }
            catch (OperationCanceledException)
            {
                throw; // Re-throw to be caught by caller
            }
            catch { }
        }

        Interlocked.Increment(ref _failedDecryptions);
        stopwatch.Stop();
        return new DecryptionResult
        {
            Success = false,
            ErrorMessage = "Decryption failed",
            Duration = stopwatch.Elapsed
        };
    }

    // FIXED: Safe version that doesn't throw
    private static DecryptionResult TryDecryptQuicPacketSafe(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        try
        {
            if (packetData.Length < 20)
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too short" };

            bool isLongHeader = (packetData[0] & 0x80) != 0;

            int headerLen;

            if (isLongHeader)
            {
                headerLen = EstimateLongHeaderLength(packetData);
                if (headerLen <= 0 || headerLen >= packetData.Length - 16)
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid long header" };
            }
            else
            {
                // Short header: try common DCID lengths
                int pnLen = (packetData[0] & 0x03) + 1;
                int[] dcidLengths = { 8, 4, 0, 16, 12 };

                foreach (int dcidLen in dcidLengths)
                {
                    // FIXED: Check cancellation without throwing
                    if (ct.IsCancellationRequested)
                        return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

                    headerLen = 1 + dcidLen + pnLen;
                    if (headerLen >= packetData.Length - 16) continue;

                    var result = TryDecryptWithHeaderLenSafe(packetData, key, headerLen, pnLen, isLongHeader, ct);
                    if (result.Success) return result;
                }

                return new DecryptionResult { Success = false, ErrorMessage = "Short header decrypt failed" };
            }

            // For long headers, try different packet number lengths
            for (int pnLen = 1; pnLen <= 4; pnLen++)
            {
                // FIXED: Check cancellation without throwing
                if (ct.IsCancellationRequested)
                    return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

                var result = TryDecryptWithHeaderLenSafe(packetData, key, headerLen, pnLen, isLongHeader, ct);
                if (result.Success) return result;
            }

            return new DecryptionResult { Success = false, ErrorMessage = "All decrypt attempts failed" };
        }
        catch (OperationCanceledException)
        {
            // FIXED: Return instead of throwing
            return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    private static DecryptionResult TryDecryptWithHeaderLenSafe(byte[] packetData, EncryptionKey key, int headerLen, int pnLen, bool isLongHeader, CancellationToken ct)
    {
        try
        {
            int payloadLen = packetData.Length - headerLen - AES_GCM_TAG_LENGTH;
            if (payloadLen <= 0) return new DecryptionResult { Success = false };

            byte[] header = new byte[headerLen];
            Buffer.BlockCopy(packetData, 0, header, 0, headerLen);

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, headerLen, payload, 0, payloadLen);

            byte[] tag = new byte[AES_GCM_TAG_LENGTH];
            Buffer.BlockCopy(packetData, packetData.Length - AES_GCM_TAG_LENGTH, tag, 0, AES_GCM_TAG_LENGTH);

            // Determine packet number from header
            ulong basePacketNumber = 0;
            int pnOffset = headerLen - pnLen;
            if (pnOffset >= 0 && pnOffset + pnLen <= headerLen)
            {
                for (int i = 0; i < pnLen && i < 8; i++)
                {
                    basePacketNumber = (basePacketNumber << 8) | header[pnOffset + i];
                }
            }

            // Build candidate packet numbers - REDUCED for performance
            var pnCandidates = new List<ulong> { basePacketNumber };

            if (key.HighestReceivedPN > 0)
            {
                for (ulong i = 0; i < 3; i++) // Reduced from 5
                    pnCandidates.Add(key.HighestReceivedPN + i);
            }

            for (ulong i = 0; i < Math.Min(10UL, (ulong)MAX_PN_BRUTE_FORCE); i++) // Reduced from 50
                if (!pnCandidates.Contains(i)) pnCandidates.Add(i);

            foreach (var pn in pnCandidates.Take(10)) // Reduced from 20
            {
                // FIXED: Check cancellation without throwing
                if (ct.IsCancellationRequested)
                    return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

                try
                {
                    byte[] nonce = ConstructQUICNonce(key.IV, pn);

                    using var aes = new AesGcm(key.Key, AES_GCM_TAG_LENGTH);
                    byte[] plaintext = new byte[payloadLen];
                    aes.Decrypt(nonce, payload, tag, plaintext, header);

                    if (IsValidDecryptedData(plaintext))
                    {
                        return new DecryptionResult
                        {
                            Success = true,
                            DecryptedData = plaintext,
                            DetectedType = key.Key.Length == 16 ? EncryptionType.AES128GCM : EncryptionType.AES256GCM,
                            PacketNumber = pn,
                            Metadata = new Dictionary<string, object>
                            {
                                ["algorithm"] = key.Key.Length == 16 ? "AES-128-GCM" : "AES-256-GCM",
                                ["packet_number"] = pn,
                                ["header_type"] = isLongHeader ? "long" : "short",
                                ["header_length"] = headerLen
                            }
                        };
                    }
                }
                catch (CryptographicException) { /* Expected for wrong PN */ }
                catch { }
            }

            return new DecryptionResult { Success = false };
        }
        catch (OperationCanceledException)
        {
            // FIXED: Return instead of throwing
            return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };
        }
        catch
        {
            return new DecryptionResult { Success = false };
        }
    }

    private static int EstimateLongHeaderLength(byte[] data)
    {
        if (data.Length < 7) return -1;

        int offset = 6; // flags + version + dcid len byte

        byte dcidLen = data[5];
        offset += dcidLen;

        if (offset >= data.Length) return -1;

        byte scidLen = data[offset];
        offset += 1 + scidLen;

        if (offset >= data.Length) return -1;

        offset += 2; // Length field

        return offset + 1;
    }

    private static byte[] ConstructQUICNonce(byte[] iv, ulong packetNumber)
    {
        byte[] nonce = new byte[12];
        Buffer.BlockCopy(iv, 0, nonce, 0, Math.Min(iv.Length, 12));

        byte[] pnBytes = new byte[8];
        pnBytes[0] = (byte)(packetNumber >> 56);
        pnBytes[1] = (byte)(packetNumber >> 48);
        pnBytes[2] = (byte)(packetNumber >> 40);
        pnBytes[3] = (byte)(packetNumber >> 32);
        pnBytes[4] = (byte)(packetNumber >> 24);
        pnBytes[5] = (byte)(packetNumber >> 16);
        pnBytes[6] = (byte)(packetNumber >> 8);
        pnBytes[7] = (byte)(packetNumber);

        for (int i = 0; i < 8; i++)
        {
            nonce[4 + i] ^= pnBytes[i];
        }

        return nonce;
    }

    private static void UpdateKeyStats(EncryptionKey key, ulong packetNumber)
    {
        _keysLock.EnterWriteLock();
        try
        {
            key.UseCount++;
            if (packetNumber > key.HighestReceivedPN)
                key.HighestReceivedPN = packetNumber;
        }
        finally
        {
            _keysLock.ExitWriteLock();
        }
    }

    public static void DeriveQUICKeys(EncryptionKey key)
    {
        if (key.Secret == null || key.Secret.Length == 0) return;

        try
        {
            byte[] label;
            int keyLength = 16;

            switch (key.Type)
            {
                case EncryptionType.QUIC_ClientHandshake:
                    label = QUIC_CLIENT_HANDSHAKE_LABEL;
                    keyLength = 16;
                    break;
                case EncryptionType.QUIC_ServerHandshake:
                    label = QUIC_SERVER_HANDSHAKE_LABEL;
                    keyLength = 16;
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
            key.HeaderProtectionKey = HkdfExpandLabel(key.Secret, QUIC_HP_LABEL, Array.Empty<byte>(), keyLength);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KEY-DERIVE] Failed: {ex.Message}");
            key.Key = Array.Empty<byte>();
            key.IV = Array.Empty<byte>();
            key.HeaderProtectionKey = null;
        }
    }

    private static byte[] HkdfExpandLabel(byte[] secret, byte[] label, byte[] context, int length)
    {
        var fullLabel = new List<byte>();
        fullLabel.AddRange(TLS13_LABEL_PREFIX);
        fullLabel.AddRange(label);

        var hkdfLabel = new List<byte>();
        hkdfLabel.Add((byte)(length >> 8));
        hkdfLabel.Add((byte)(length & 0xFF));
        hkdfLabel.Add((byte)fullLabel.Count);
        hkdfLabel.AddRange(fullLabel);
        hkdfLabel.Add((byte)context.Length);
        hkdfLabel.AddRange(context);

        return HkdfExpand(secret, hkdfLabel.ToArray(), length);
    }

    private static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        var result = new List<byte>();
        var counter = 1;
        byte[] previous = Array.Empty<byte>();

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

        return reasonableLength && reasonableEntropy && hasPrintable;
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

            if (_discoveredKeys.Count >= 20)
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
            Interlocked.Exchange(ref _skippedDecryptions, 0);
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
                    HeaderProtectionKey = k.HeaderProtectionKey?.ToArray(),
                    Type = k.Type,
                    Source = k.Source,
                    MemoryAddress = k.MemoryAddress,
                    DiscoveredAt = k.DiscoveredAt,
                    UseCount = k.UseCount,
                    Secret = k.Secret?.ToArray(),
                    HighestReceivedPN = k.HighestReceivedPN
                }).ToList();
            }
            finally { _keysLock.ExitReadLock(); }
        }
    }

    public static long SuccessfulDecryptions => Interlocked.Read(ref _successfulDecryptions);
    public static long FailedDecryptions => Interlocked.Read(ref _failedDecryptions);
    public static long SkippedDecryptions => Interlocked.Read(ref _skippedDecryptions);

    public static event Action<EncryptionKey>? OnKeyDiscovered;

    public static bool IsLikelyEncrypted(byte[] data)
    {
        if (data.Length < 16) return false;
        return CalculateEntropy(data) > 7.5;
    }
}

// FIXED: Rate limiter helper class
public class RateLimiter
{
    private readonly int _maxPerPeriod;
    private readonly TimeSpan _period;
    private readonly Queue<DateTime> _timestamps = new();
    private readonly object _lock = new();

    public RateLimiter(int maxPerPeriod, TimeSpan period)
    {
        _maxPerPeriod = maxPerPeriod;
        _period = period;
    }

    public bool TryAcquire()
    {
        lock (_lock)
        {
            var now = DateTime.Now;

            // Remove old timestamps
            while (_timestamps.Count > 0 && now - _timestamps.Peek() > _period)
            {
                _timestamps.Dequeue();
            }

            if (_timestamps.Count < _maxPerPeriod)
            {
                _timestamps.Enqueue(now);
                return true;
            }

            return false;
        }
    }
}