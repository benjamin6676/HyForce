// FILE: Protocol/PacketDecryptor.cs - FIXED: Proper async decryption without blocking UI
using HyForce.Networking;
using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
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
    private static readonly byte[] TLS13_LABEL_PREFIX = Encoding.ASCII.GetBytes("tls13");

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


    // This removes header protection according to RFC 9001 Section 5.4
    // This removes header protection according to RFC 9001 Section 5.4
    // REPLACE the entire TryRemoveHeaderProtection method with this:

    private static bool TryRemoveHeaderProtection(byte[] packet, EncryptionKey key, out byte[] unprotectedHeader, out int pnOffset, out int pnLength)
    {
        unprotectedHeader = (byte[])packet.Clone();
        pnOffset = 0;
        pnLength = 0;

        if (key.HeaderProtectionKey == null || key.HeaderProtectionKey.Length == 0)
            return false;

        bool isLongHeader = (packet[0] & 0x80) != 0;

        // For Hytale/Netty: Try multiple approaches
        int[] pnOffsetsToTry;

        if (isLongHeader)
        {
            // Long header: PN starts after version(4) + DCID len(1) + DCID + SCID len(1) + SCID
            // But this varies by packet type - try common offsets
            pnOffsetsToTry = new[] { 6, 7, 8, 10, 12, 14, 16, 18, 20, 22 };
        }
        else
        {
            // Short header: PN starts after flags(1) + DCID
            // Hytale often uses 0-length DCID in 1-RTT, so PN is at offset 1
            // But try various DCID lengths
            pnOffsetsToTry = new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20, 21 };
        }

        // Try each potential PN offset
        foreach (int testPnOffset in pnOffsetsToTry)
        {
            if (testPnOffset >= packet.Length - 4) continue;

            // Calculate sample offset (16 bytes after PN start, per RFC 9001)
            int sampleOffset = testPnOffset + 4;
            if (sampleOffset + 16 > packet.Length) continue;

            // Extract sample
            byte[] sample = new byte[16];
            Buffer.BlockCopy(packet, sampleOffset, sample, 0, 16);

            // Generate mask
            byte[] mask;
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = key.HeaderProtectionKey;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        mask = encryptor.TransformFinalBlock(sample, 0, 16);
                    }
                }
            }
            catch { continue; }

            // Apply mask to first byte
            byte unprotectedFirstByte;
            if (isLongHeader)
                unprotectedFirstByte = (byte)(packet[0] ^ (mask[0] & 0x0F));
            else
                unprotectedFirstByte = (byte)(packet[0] ^ (mask[0] & 0x1F));

            // Validate: reserved bits must be 0, version must be valid for long header
            bool valid = true;
            if (isLongHeader)
            {
                // Long header: bits 4-5 must be 0 for some versions, or check version field
                if ((unprotectedFirstByte & 0x30) != 0 && (unprotectedFirstByte & 0x30) != 0x10)
                    valid = false; // Allow some flexibility for different packet types

                // Check version field if we have enough bytes
                if (packet.Length >= 5)
                {
                    uint version = (uint)((packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4]);
                    // Version 0 or 0x00000001 are valid, or negotiation versions
                    if (version != 0 && version != 1 && version != 0x51303530) // Q050 for gQUIC
                        valid = false;
                }
            }
            else
            {
                // Short header: spin bit (bit 2) can be 0 or 1, reserved bits (3-4) must be 0
                if ((unprotectedFirstByte & 0x18) != 0)
                    valid = false;
            }

            if (!valid) continue;

            // Get PN length from unprotected first byte
            int testPnLength = (unprotectedFirstByte & 0x03) + 1;
            if (testPnOffset + testPnLength > packet.Length) continue;

            // Apply mask to PN bytes
            Buffer.BlockCopy(packet, 0, unprotectedHeader, 0, packet.Length);

            if (isLongHeader)
                unprotectedHeader[0] = (byte)(packet[0] ^ (mask[0] & 0x0F));
            else
                unprotectedHeader[0] = (byte)(packet[0] ^ (mask[0] & 0x1F));

            for (int i = 0; i < testPnLength && i < 4; i++)
            {
                unprotectedHeader[testPnOffset + i] = (byte)(packet[testPnOffset + i] ^ mask[1 + i]);
            }

            // Validate PN is reasonable (not all 0xFF, not huge)
            ulong pn = 0;
            for (int i = 0; i < testPnLength; i++)
            {
                pn = (pn << 8) | unprotectedHeader[testPnOffset + i];
            }

            // Sanity check: PN should be reasonable
            if (pn > 0xFFFFFF) continue; // Too large, probably wrong

            pnOffset = testPnOffset;
            pnLength = testPnLength;
            return true;
        }

        return false;
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

    /// CRITICAL FIX: TryDecrypt must actually wait for and return the result
    public static DecryptionResult TryDecrypt(byte[] encryptedData, int timeoutMs = 10000)
    {
        // CRITICAL: Don't even try if we have no keys
        if (DiscoveredKeys.Count == 0)
        {
            return new DecryptionResult
            {
                Success = false,
                ErrorMessage = "No keys available"
            };
        }

        if (!AutoDecryptEnabled)
            return TryDecryptManual(encryptedData, timeoutMs);

        // If auto-decrypt is running, enqueue and WAIT for result
        if (_decryptChannel != null && _autoDecryptWorker != null)
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

            // CRITICAL: Actually wait for the background worker to complete the job
            try
            {
                // Wait for completion with timeout
                var completed = job.Completion.Task.Wait(TimeSpan.FromMilliseconds(timeoutMs));

                if (completed)
                {
                    var result = job.Completion.Task.Result;
                    // Update stats based on actual result
                    if (result.Success)
                        Interlocked.Increment(ref _successfulDecryptions);
                    else
                        Interlocked.Increment(ref _failedDecryptions);
                    return result;
                }
                else
                {
                    // Timeout - try to cancel the job
                    Interlocked.Increment(ref _failedDecryptions);
                    return new DecryptionResult
                    {
                        Success = false,
                        ErrorMessage = "Decryption timeout"
                    };
                }
            }
            catch (AggregateException ex) when (ex.InnerException is OperationCanceledException)
            {
                return new DecryptionResult
                {
                    Success = false,
                    ErrorMessage = "Cancelled"
                };
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failedDecryptions);
                return new DecryptionResult
                {
                    Success = false,
                    ErrorMessage = $"Decryption error: {ex.Message}"
                };
            }
        }

        // Fallback to manual decrypt if auto-decrypt not started
        return TryDecryptManual(encryptedData, timeoutMs);
    }

    // FIXED: Manual decrypt - synchronous but with timeout
    // FIXED: Manual decrypt with detailed logging
    public static DecryptionResult TryDecryptManual(byte[] encryptedData, int timeoutMs = 5000)
    {
        if (encryptedData == null || encryptedData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Data too short" };

        var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            // Run on thread pool with timeout
            var task = Task.Run(() =>
            {
                var result = TryDecryptInternalDetailed(encryptedData, cts.Token);
                return result;
            }, cts.Token);

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

    // NEW: Detailed version that logs every attempt
    private static DecryptionResult TryDecryptInternalDetailed(byte[] encryptedData, CancellationToken ct)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        List<EncryptionKey> keysCopy;
        _keysLock.EnterReadLock();
        try
        {
            // CRITICAL FIX: Prioritize keys based on header type
            bool isLongHeader = (encryptedData[0] & 0x80) != 0;

            keysCopy = _discoveredKeys
                .Where(k => k.Key.Length >= 16 && k.IV.Length == 12)
                .OrderBy(k =>
                {
                    // Prioritize correct key types for header type
                    if (!isLongHeader) // Short header = 1-RTT
                    {
                        if (k.Type == EncryptionType.QUIC_Client1RTT || k.Type == EncryptionType.QUIC_Server1RTT)
                            return 0; // Highest priority
                        if (k.Type == EncryptionType.QUIC_Client0RTT || k.Type == EncryptionType.QUIC_Server0RTT)
                            return 1;
                    }
                    else // Long header = Handshake
                    {
                        if (k.Type == EncryptionType.QUIC_ClientHandshake || k.Type == EncryptionType.QUIC_ServerHandshake)
                            return 0; // Highest priority
                    }
                    return 2; // Lowest priority (wrong key type)
                })
                .ThenByDescending(k => k.UseCount)
                .Take(5)
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

        // Log packet info
        bool packetIsLongHeader = (encryptedData[0] & 0x80) != 0;
        Console.WriteLine($"[DECRYPT-DEBUG] ========== NEW DECRYPT ATTEMPT ==========");
        Console.WriteLine($"[DECRYPT-DEBUG] Packet size: {encryptedData.Length} bytes");
        Console.WriteLine($"[DECRYPT-DEBUG] First 16 bytes: {BitConverter.ToString(encryptedData.Take(16).ToArray())}");
        Console.WriteLine($"[DECRYPT-DEBUG] IsLongHeader: {packetIsLongHeader}");
        Console.WriteLine($"[DECRYPT-DEBUG] Available keys: {keysCopy.Count}");
        Console.WriteLine($"[DECRYPT-DEBUG] Key types available: {string.Join(", ", keysCopy.Select(k => k.Type).Distinct())}");

        foreach (var key in keysCopy)
        {
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

            Console.WriteLine($"[DECRYPT-DEBUG] ----------------------------------------");
            Console.WriteLine($"[DECRYPT-DEBUG] Trying key: {key.Type} (priority based on header type)");
            Console.WriteLine($"[DECRYPT-DEBUG] Key bytes: {BitConverter.ToString(key.Key.Take(8).ToArray())}... ({key.Key.Length} bytes)");
            Console.WriteLine($"[DECRYPT-DEBUG] IV bytes: {BitConverter.ToString(key.IV)}");
            Console.WriteLine($"[DECRYPT-DEBUG] Has HP key: {key.HeaderProtectionKey != null}");
            if (key.HeaderProtectionKey != null)
                Console.WriteLine($"[DECRYPT-DEBUG] HP key: {BitConverter.ToString(key.HeaderProtectionKey.Take(8).ToArray())}...");

            try
            {
                // Try with header protection first
                if (key.HeaderProtectionKey != null && key.HeaderProtectionKey.Length > 0)
                {
                    Console.WriteLine("[DECRYPT-DEBUG] Attempting header protection removal...");
                    var result = TryDecryptQuicPacketDetailed(encryptedData, key, ct);
                    if (result.Success)
                    {
                        UpdateKeyStats(key, result.PacketNumber);
                        Interlocked.Increment(ref _successfulDecryptions);
                        result.Duration = stopwatch.Elapsed;
                        Console.WriteLine($"[DECRYPT-DEBUG] SUCCESS with header protection removal!");
                        return result;
                    }
                    Console.WriteLine($"[DECRYPT-DEBUG] Header protection removal failed: {result.ErrorMessage}");
                }

                // Try brute force without header protection
                Console.WriteLine("[DECRYPT-DEBUG] Attempting brute force...");
                var bruteResult = TryDecryptWithBruteForceDetailed(encryptedData, key, ct);
                if (bruteResult.Success)
                {
                    UpdateKeyStats(key, bruteResult.PacketNumber);
                    Interlocked.Increment(ref _successfulDecryptions);
                    bruteResult.Duration = stopwatch.Elapsed;
                    Console.WriteLine($"[DECRYPT-DEBUG] SUCCESS with brute force!");
                    return bruteResult;
                }
                Console.WriteLine($"[DECRYPT-DEBUG] Brute force failed: {bruteResult.ErrorMessage}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DECRYPT-DEBUG] Exception with key {key.Type}: {ex.Message}");
            }
        }

        Interlocked.Increment(ref _failedDecryptions);
        stopwatch.Stop();
        return new DecryptionResult
        {
            Success = false,
            ErrorMessage = $"All {keysCopy.Count} keys failed. Check console output for details.",
            Duration = stopwatch.Elapsed
        };
    }

    // NEW: Detailed QUIC decrypt with logging
    private static DecryptionResult TryDecryptQuicPacketDetailed(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        try
        {
            if (packetData.Length < 20)
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too short" };

            Console.WriteLine($"[DECRYPT-DEBUG] TryRemoveHeaderProtection starting...");

            if (!TryRemoveHeaderProtection(packetData, key, out var unprotectedHeader, out int pnOffset, out int pnLength))
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Header protection removal failed" };
            }

            Console.WriteLine($"[DECRYPT-DEBUG] Header protection removed. pnOffset={pnOffset}, pnLength={pnLength}");
            Console.WriteLine($"[DECRYPT-DEBUG] Unprotected header: {BitConverter.ToString(unprotectedHeader.Take(pnOffset + pnLength + 4).ToArray())}");

            // CRITICAL FIX: Extract packet number from unprotected header
            ulong packetNumber = 0;
            for (int i = 0; i < pnLength && i < 8; i++)
            {
                packetNumber = (packetNumber << 8) | unprotectedHeader[pnOffset + i];
            }

            // CRITICAL FIX: Sanity check packet number
            if (packetNumber > 10000000)  // Sanity check - too large indicates corruption
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid packet number from header protection" };
            }

            Console.WriteLine($"[DECRYPT-DEBUG] Extracted packet number: {packetNumber}");

            // CRITICAL FIX: Build header for AEAD - MUST include first byte through packet number
            int headerLength = pnOffset + pnLength;
            byte[] header = new byte[headerLength];
            Buffer.BlockCopy(unprotectedHeader, 0, header, 0, headerLength);
            Console.WriteLine($"[DECRYPT-DEBUG] Header for AEAD ({headerLength} bytes): {BitConverter.ToString(header)}");

            // Extract payload (everything after packet number, excluding auth tag)
            int payloadOffset = pnOffset + pnLength;
            int payloadLen = packetData.Length - payloadOffset - 16; // -16 for auth tag

            if (payloadLen <= 0)
                return new DecryptionResult { Success = false, ErrorMessage = $"Invalid payload length: {payloadLen}" };

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, payloadOffset, payload, 0, payloadLen);
            Console.WriteLine($"[DECRYPT-DEBUG] Payload offset: {payloadOffset}, length: {payloadLen}");

            byte[] tag = new byte[16];
            Buffer.BlockCopy(packetData, packetData.Length - 16, tag, 0, 16);
            Console.WriteLine($"[DECRYPT-DEBUG] Auth tag: {BitConverter.ToString(tag)}");

            // Construct nonce
            byte[] nonce = ConstructQUICNonce(key.IV, packetNumber);
            Console.WriteLine($"[DECRYPT-DEBUG] Nonce: {BitConverter.ToString(nonce)}");

            // Decrypt
            try
            {
                using var aes = new AesGcm(key.Key, 16);
                byte[] plaintext = new byte[payloadLen];
                aes.Decrypt(nonce, payload, tag, plaintext, header);

                if (IsValidDecryptedData(plaintext))
                {
                    Console.WriteLine($"[DECRYPT-DEBUG] Decryption successful! Plaintext length: {plaintext.Length}");
                    Console.WriteLine($"[DECRYPT-DEBUG] First 32 bytes plaintext: {BitConverter.ToString(plaintext.Take(32).ToArray())}");

                    return new DecryptionResult
                    {
                        Success = true,
                        DecryptedData = plaintext,
                        DetectedType = key.Type,
                        PacketNumber = packetNumber,
                        Metadata = new Dictionary<string, object>
                        {
                            ["algorithm"] = key.Key.Length == 16 ? "AES-128-GCM" : "AES-256-GCM",
                            ["packet_number"] = packetNumber,
                            ["header_type"] = (packetData[0] & 0x80) != 0 ? "long" : "short",
                            ["header_protection_removed"] = true,
                            ["header_length"] = headerLength,
                            ["payload_length"] = payloadLen
                        }
                    };
                }
                else
                {
                    Console.WriteLine($"[DECRYPT-DEBUG] Decryption produced invalid data (entropy check failed)");
                    return new DecryptionResult { Success = false, ErrorMessage = "Invalid decrypted data" };
                }
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"[DECRYPT-DEBUG] CryptographicException: {ex.Message}");
                return new DecryptionResult { Success = false, ErrorMessage = $"Crypto error: {ex.Message}" };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DECRYPT-DEBUG] Exception in TryDecryptQuicPacketDetailed: {ex.Message}");
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }
    // NEW: Detailed brute force with logging
    // REPLACE TryDecryptWithBruteForceDetailed with this:

    private static DecryptionResult TryDecryptWithBruteForceDetailed(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        Console.WriteLine($"[DECRYPT-DEBUG] Brute force starting for key {key.Type}");

        bool isLongHeader = (packetData[0] & 0x80) != 0;
        Console.WriteLine($"[DECRYPT-DEBUG] IsLongHeader: {isLongHeader}");

        // EXPANDED: More DCID lengths to try including common Netty values
        int[] dcidLengths = isLongHeader
            ? new[] { 0 }
            : new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20 };

        int attempts = 0;
        int maxAttempts = 5000; // Increased from 1000

        foreach (int dcidLen in dcidLengths)
        {
            if (ct.IsCancellationRequested)
                return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

            // For short header: headerLen = 1 (flags) + dcidLen
            int headerLen = isLongHeader ? 0 : 1 + dcidLen;

            // Try different PN lengths (1-4 bytes)
            for (int pnLen = 1; pnLen <= 4; pnLen++)
            {
                int pnOffset = headerLen;
                int payloadOffset = pnOffset + pnLen;

                if (payloadOffset + 16 > packetData.Length) continue;

                // Extract base packet number from packet bytes
                ulong basePN = 0;
                for (int i = 0; i < pnLen && i < 8; i++)
                {
                    basePN = (basePN << 8) | packetData[pnOffset + i];
                }

                // EXPANDED: Try much larger range of packet numbers
                // Hytale may have high packet numbers due to long sessions
                ulong[] pnDeltas = new ulong[100];
                for (int i = 0; i < 50; i++) pnDeltas[i] = (ulong)i; // 0-49
                for (int i = 50; i < 70; i++) pnDeltas[i] = (ulong)(50 + (i - 50) * 5); // 50, 55, 60... 145
                for (int i = 70; i < 85; i++) pnDeltas[i] = (ulong)(100 + (i - 70) * 10); // 100, 110... 240
                for (int i = 85; i < 100; i++) pnDeltas[i] = (ulong)(250 + (i - 85) * 50); // 250, 300... 1000

                foreach (ulong pnDelta in pnDeltas)
                {
                    attempts++;
                    if (attempts > maxAttempts)
                    {
                        Console.WriteLine($"[DECRYPT-DEBUG] Brute force hit max attempts ({maxAttempts})");
                        return new DecryptionResult { Success = false, ErrorMessage = $"Max attempts reached ({maxAttempts})" };
                    }

                    // Try incrementing from base
                    var result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN + pnDelta, pnOffset, ct);
                    if (result.Success)
                    {
                        Console.WriteLine($"[DECRYPT-DEBUG] Brute force success after {attempts} attempts! PN={basePN + pnDelta}, dcidLen={dcidLen}, pnLen={pnLen}");
                        return result;
                    }

                    // Try decrementing (if not zero)
                    if (basePN >= pnDelta && pnDelta > 0)
                    {
                        result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN - pnDelta, pnOffset, ct);
                        if (result.Success)
                        {
                            Console.WriteLine($"[DECRYPT-DEBUG] Brute force success after {attempts} attempts! PN={basePN - pnDelta}, dcidLen={dcidLen}, pnLen={pnLen}");
                            return result;
                        }
                    }

                    // Also try common fixed values regardless of base
                    ulong[] commonPNs = { 0, 1, 2, 3, 4, 5, 10, 20, 50, 100, 200, 500, 1000 };
                    foreach (ulong commonPn in commonPNs)
                    {
                        if (commonPn != basePN + pnDelta && commonPn != basePN - pnDelta)
                        {
                            result = TryDecryptAtPN(packetData, key, headerLen, pnLen, commonPn, pnOffset, ct);
                            if (result.Success)
                            {
                                Console.WriteLine($"[DECRYPT-DEBUG] Brute force success with common PN {commonPn}!");
                                return result;
                            }
                        }
                    }
                }
            }
        }

        Console.WriteLine($"[DECRYPT-DEBUG] Brute force failed after {attempts} attempts");
        return new DecryptionResult { Success = false, ErrorMessage = $"Brute force failed. Tried {attempts} combinations." };
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

    /// Replace TryDecryptWithBruteForce with this enhanced version
    private static DecryptionResult TryDecryptWithBruteForce(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        if (packetData.Length < 20)
            return new DecryptionResult { Success = false, ErrorMessage = "Packet too short" };

        bool isLongHeader = (packetData[0] & 0x80) != 0;

        // For short headers (1-RTT), try different DCID lengths and PN offsets
        int[] dcidLengths = isLongHeader ? new[] { 0 } : new[] { 0, 4, 8, 12, 16, 20 };

        foreach (int dcidLen in dcidLengths)
        {
            if (ct.IsCancellationRequested)
                return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

            int headerLen = isLongHeader ? 0 : 1 + dcidLen; // Short header: 1 byte flags + DCID

            // Try different PN lengths (1-4 bytes)
            for (int pnLen = 1; pnLen <= 4; pnLen++)
            {
                int pnOffset = headerLen;
                int payloadOffset = pnOffset + pnLen;

                if (payloadOffset + 16 > packetData.Length) continue; // Need at least 16 bytes for tag

                // Extract packet number candidates
                ulong basePN = 0;
                for (int i = 0; i < pnLen && i < 8; i++)
                {
                    basePN = (basePN << 8) | packetData[pnOffset + i];
                }

                // Try base PN and nearby values (Hytale may use sequential PNs)
                for (ulong pnDelta = 0; pnDelta < 50; pnDelta++)
                {
                    // Try incrementing
                    var result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN + pnDelta, pnOffset, ct);
                    if (result.Success) return result;

                    // Try decrementing (if not zero)
                    if (basePN >= pnDelta && pnDelta > 0)
                    {
                        result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN - pnDelta, pnOffset, ct);
                        if (result.Success) return result;
                    }
                }
            }
        }

        return new DecryptionResult { Success = false, ErrorMessage = "Brute force failed - tried all PN combinations" };
    }

    // REPLACE TryDecryptAtPN with this corrected version:

    private static DecryptionResult TryDecryptAtPN(byte[] packetData, EncryptionKey key, int headerLen, int pnLen, ulong packetNumber, int pnOffset, CancellationToken ct)
    {
        try
        {
            if (ct.IsCancellationRequested)
                return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

            // Build header: everything from start through PN
            int fullHeaderLen = pnOffset + pnLen;
            byte[] header = new byte[fullHeaderLen];
            Buffer.BlockCopy(packetData, 0, header, 0, fullHeaderLen);

            // CRITICAL: For short headers, we need to reconstruct what the header SHOULD look like
            // The original packet has encrypted PN bytes, but for AEAD we need the "true" header
            // with the actual PN values (not the encrypted ones)

            // Replace PN bytes in header with actual packet number (big-endian for QUIC)
            for (int i = 0; i < pnLen; i++)
            {
                header[pnOffset + (pnLen - 1 - i)] = (byte)(packetNumber >> (i * 8));
            }

            // Extract ciphertext (everything after PN, excluding auth tag)
            int payloadOffset = pnOffset + pnLen;
            int payloadLen = packetData.Length - payloadOffset - 16; // 16 bytes for AES-GCM tag

            if (payloadLen <= 0)
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid payload length" };

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, payloadOffset, payload, 0, payloadLen);

            byte[] tag = new byte[16];
            Buffer.BlockCopy(packetData, packetData.Length - 16, tag, 0, 16);

            // Construct nonce using packet number
            byte[] nonce = ConstructQUICNonce(key.IV, packetNumber);

            // Attempt decryption
            try
            {
                using var aes = new AesGcm(key.Key, 16);
                byte[] plaintext = new byte[payloadLen];
                aes.Decrypt(nonce, payload, tag, plaintext, header);

                if (IsValidDecryptedData(plaintext))
                {
                    return new DecryptionResult
                    {
                        Success = true,
                        DecryptedData = plaintext,
                        DetectedType = key.Type,
                        PacketNumber = packetNumber,
                        Metadata = new Dictionary<string, object>
                        {
                            ["algorithm"] = key.Key.Length == 16 ? "AES-128-GCM" : "AES-256-GCM",
                            ["packet_number"] = packetNumber,
                            ["header_type"] = (packetData[0] & 0x80) != 0 ? "long" : "short",
                            ["brute_force"] = true,
                            ["dcid_length"] = headerLen > 0 ? headerLen - 1 : 0,
                            ["pn_length"] = pnLen,
                            ["header_bytes"] = BitConverter.ToString(header)
                        }
                    };
                }
            }
            catch (CryptographicException)
            {
                // Expected for wrong PN - continue trying
            }

            return new DecryptionResult { Success = false, ErrorMessage = "Decryption failed" };
        }
        catch (Exception ex)
        {
            return new DecryptionResult { Success = false, ErrorMessage = ex.Message };
        }
    }

    // Helper method for specific packet number
    private static DecryptionResult TryDecryptWithSpecificPN(byte[] packetData, EncryptionKey key, int headerLen, int pnLen, ulong packetNumber, bool isLongHeader, CancellationToken ct)
    {
        if (ct.IsCancellationRequested)
            return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

        try
        {
            int payloadLen = packetData.Length - headerLen - 16; // 16 = AES-GCM tag
            if (payloadLen <= 0) return new DecryptionResult { Success = false };

            byte[] header = new byte[headerLen];
            Buffer.BlockCopy(packetData, 0, header, 0, headerLen);

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, headerLen, payload, 0, payloadLen);

            byte[] tag = new byte[16];
            Buffer.BlockCopy(packetData, packetData.Length - 16, tag, 0, 16);

            byte[] nonce = ConstructQUICNonce(key.IV, packetNumber);

            using var aes = new AesGcm(key.Key, 16);
            byte[] plaintext = new byte[payloadLen];
            aes.Decrypt(nonce, payload, tag, plaintext, header);

            if (IsValidDecryptedData(plaintext))
            {
                return new DecryptionResult
                {
                    Success = true,
                    DecryptedData = plaintext,
                    DetectedType = key.Key.Length == 16 ? EncryptionType.AES128GCM : EncryptionType.AES256GCM,
                    PacketNumber = packetNumber,
                    Metadata = new Dictionary<string, object>
                    {
                        ["algorithm"] = key.Key.Length == 16 ? "AES-128-GCM" : "AES-256-GCM",
                        ["packet_number"] = packetNumber,
                        ["header_type"] = isLongHeader ? "long" : "short",
                        ["brute_force"] = true
                    }
                };
            }
        }
        catch { }

        return new DecryptionResult { Success = false };
    }

    // REPLACE your current TryDecryptQuicPacketSafe with this:

    private static DecryptionResult TryDecryptQuicPacketSafe(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        try
        {
            if (packetData.Length < 20)
                return new DecryptionResult { Success = false, ErrorMessage = "Packet too short" };

            // First, try to remove header protection
            if (!TryRemoveHeaderProtection(packetData, key, out var unprotectedHeader, out int pnOffset, out int pnLength))
            {
                // Fall back to simple brute force if header protection removal fails
                return TryDecryptWithBruteForce(packetData, key, ct);
            }

            // Extract packet number from unprotected header
            ulong packetNumber = 0;
            for (int i = 0; i < pnLength && i < 8; i++)
            {
                packetNumber = (packetNumber << 8) | unprotectedHeader[pnOffset + i];
            }

            // CORRECT - for short headers:
            int headerLen = pnOffset + pnLength; // This should be 1 + pnLength for short header
            byte[] header = new byte[headerLen];
            Buffer.BlockCopy(unprotectedHeader, 0, header, 0, headerLen);

            // Extract payload (everything after packet number)
            int payloadOffset = pnOffset + pnLength;
            int payloadLen = packetData.Length - payloadOffset - 16; // -16 for auth tag

            if (payloadLen <= 0)
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid payload length" };

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, payloadOffset, payload, 0, payloadLen);

            byte[] tag = new byte[16];
            Buffer.BlockCopy(packetData, packetData.Length - 16, tag, 0, 16);

            // Construct nonce
            byte[] nonce = ConstructQUICNonce(key.IV, packetNumber);

            // Decrypt
            try
            {
                using var aes = new AesGcm(key.Key, 16);
                byte[] plaintext = new byte[payloadLen];
                aes.Decrypt(nonce, payload, tag, plaintext, header);

                if (IsValidDecryptedData(plaintext))
                {
                    return new DecryptionResult
                    {
                        Success = true,
                        DecryptedData = plaintext,
                        DetectedType = key.Type,
                        PacketNumber = packetNumber,
                        Metadata = new Dictionary<string, object>
                        {
                            ["algorithm"] = key.Key.Length == 16 ? "AES-128-GCM" : "AES-256-GCM",
                            ["packet_number"] = packetNumber,
                            ["header_type"] = (packetData[0] & 0x80) != 0 ? "long" : "short",
                            ["header_protection_removed"] = true
                        }
                    };
                }
            }
            catch (CryptographicException) { /* Expected for wrong key */ }

            return new DecryptionResult { Success = false, ErrorMessage = "Decryption failed after header protection removal" };
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

    // REPLACE ConstructQUICNonce with this verified version:

    private static byte[] ConstructQUICNonce(byte[] iv, ulong packetNumber)
    {
        // RFC 9001: XOR the packet number (left-padded to IV length) with the IV
        byte[] nonce = new byte[12]; // 96-bit nonce for AES-GCM
        Buffer.BlockCopy(iv, 0, nonce, 0, Math.Min(iv.Length, 12));

        // XOR packet number into last 8 bytes of nonce (big-endian)
        // This matches how TLS 1.3 / QUIC construct the nonce
        for (int i = 0; i < 8; i++)
        {
            byte pnByte = (byte)(packetNumber >> (i * 8));
            nonce[11 - i] ^= pnByte; // XOR from the end (little-endian PN to big-endian position)
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
        if (key.Secret == null || key.Secret.Length == 0)
        {
            Console.WriteLine($"[KEY-DERIVE] No secret available for {key.Type}");
            return;
        }

        try
        {
            Console.WriteLine($"[KEY-DERIVE] ========== {key.Type} ==========");
            Console.WriteLine($"[KEY-DERIVE] Secret length: {key.Secret.Length} bytes");

            int secretLength = key.Secret.Length;

            // RFC 9001 uses different key lengths based on cipher
            // For TLS_AES_128_GCM_SHA256: key=16, iv=12, hp=16
            // For TLS_AES_256_GCM_SHA384: key=32, iv=12, hp=32

            // 32B secret = AES-128/SHA-256 (Hytale standard); 48B = AES-256
            int keyLen = secretLength >= 48 ? 32 : 16;
            int hpLen  = keyLen;
            string cipher = keyLen == 16 ? "AES-128-GCM (Hytale)" : "AES-256-GCM";
            Console.WriteLine($"[KEY-DERIVE] Using {cipher}");

            // CRITICAL FIX: Use correct RFC 9001 labels WITHOUT "tls13 " prefix
            key.Key = HkdfExpandLabelRFC9001(key.Secret, "quic key", keyLen);
            key.IV = HkdfExpandLabelRFC9001(key.Secret, "quic iv", 12);
            key.HeaderProtectionKey = HkdfExpandLabelRFC9001(key.Secret, "quic hp", hpLen);

            Console.WriteLine($"[KEY-DERIVE] Derived key: {Convert.ToHexString(key.Key)}");
            Console.WriteLine($"[KEY-DERIVE] Derived IV:  {Convert.ToHexString(key.IV)}");
            Console.WriteLine($"[KEY-DERIVE] Derived HP:  {Convert.ToHexString(key.HeaderProtectionKey)}");
            Console.WriteLine($"[KEY-DERIVE] ? Successfully derived {key.Key.Length * 8}-bit keys");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KEY-DERIVE] ? FAILED: {ex.Message}");
            key.Key = Array.Empty<byte>();
            key.IV = Array.Empty<byte>();
            key.HeaderProtectionKey = null;
        }
    }

    // CRITICAL FIX: Correct RFC 9001 HKDF-Expand-Label (NO "tls13 " prefix!)
    private static byte[] HkdfExpandLabelRFC9001(byte[] secret, string label, int length)
    {
        // RFC 9001 Section 5.1: labels are "quic key", "quic iv", "quic hp" (NOT "tls13 quic key")

        var labelBytes = Encoding.ASCII.GetBytes(label);

        // Build HkdfLabel: length(2) + label_len(1) + label + context_len(1) + context
        // Context is always empty for QUIC key derivation
        var hkdfLabel = new List<byte>(128);

        // Length of derived key (16 bits, big-endian)
        hkdfLabel.Add((byte)(length >> 8));
        hkdfLabel.Add((byte)(length & 0xFF));

        // Label length and label
        hkdfLabel.Add((byte)labelBytes.Length);
        hkdfLabel.AddRange(labelBytes);

        // Context length (0) and empty context
        hkdfLabel.Add(0);

        return HkdfExpand(secret, hkdfLabel.ToArray(), length);
    }

    // Standard HKDF-Expand (RFC 5869)
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

    // In PacketDecryptor.cs, REPLACE the AddKey method with this:

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
                    // Just update source if different, don't add duplicate
                    if (!existing.Source.Contains(key.Source))
                        existing.Source += $", {key.Source}";
                    return;
                }
            }

            // Also check if we have a key with same secret (different derivation)
            if (key.Secret != null)
            {
                foreach (var existing in _discoveredKeys)
                {
                    if (existing.Secret != null && existing.Secret.SequenceEqual(key.Secret))
                    {
                        // Same TLS secret, already derived
                        return;
                    }
                }
            }

            // Limit total keys to prevent memory bloat
            if (_discoveredKeys.Count >= 20)
            {
                // Remove least recently used (lowest UseCount)
                var leastUsed = _discoveredKeys.OrderBy(k => k.UseCount).First();
                _discoveredKeys.Remove(leastUsed);
                Console.WriteLine($"[KEYS] Removed least used key to make room");
            }

            _discoveredKeys.Add(key);
            Console.WriteLine($"[KEYS] Added new {key.Type} key ({key.Key.Length} bytes)");
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

    public class EncryptionResult
    {
        public bool Success { get; set; }
        public byte[]? EncryptedData { get; set; }
        public ulong PacketNumber { get; set; }
        public string ErrorMessage { get; set; } = "";
        public static EncryptionResult Fail(string msg) => new() { Success = false, ErrorMessage = msg };
    }

    public static EncryptionResult TryEncrypt(byte[] plaintext, PacketDirection direction)
    {
        if (plaintext?.Length == 0) return EncryptionResult.Fail("Empty data");
        if (DiscoveredKeys.Count == 0) return EncryptionResult.Fail("No keys");

        var key = DiscoveredKeys.First();
        try
        {
            ulong pn = (ulong)DateTime.UtcNow.Ticks;
            byte[] header = { 0x40, (byte)(pn >> 24), (byte)(pn >> 16), (byte)(pn >> 8), (byte)pn };
            byte[] nonce = ConstructQUICNonce(key.IV, pn);

            using var aes = new AesGcm(key.Key, 16);
            byte[] cipher = new byte[plaintext.Length], tag = new byte[16];
            aes.Encrypt(nonce, plaintext, cipher, tag, header);

            byte[] result = new byte[header.Length + cipher.Length + tag.Length];
            Buffer.BlockCopy(header, 0, result, 0, header.Length);
            Buffer.BlockCopy(cipher, 0, result, header.Length, cipher.Length);
            Buffer.BlockCopy(tag, 0, result, header.Length + cipher.Length, tag.Length);

            return new EncryptionResult { Success = true, EncryptedData = result, PacketNumber = pn };
        }
        catch (Exception ex)
        {
            return EncryptionResult.Fail(ex.Message);
        }
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