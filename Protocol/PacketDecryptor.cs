// FILE: Protocol/PacketDecryptor.cs - FIXED: Proper async decryption without blocking UI
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Runtime.ExceptionServices;

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
    private static bool TryRemoveHeaderProtection(byte[] packet, EncryptionKey key, out byte[] unprotectedHeader, out int pnOffset, out int pnLength)
    {
        unprotectedHeader = (byte[])packet.Clone();
        pnOffset = 0;
        pnLength = 0;

        if (key.HeaderProtectionKey == null || key.HeaderProtectionKey.Length == 0)
            return false;

        bool isLongHeader = (packet[0] & 0x80) != 0;

        // Find the packet number offset
        int sampleOffset;
        if (isLongHeader)
        {
            // Long header: pn_offset = 6 + dcid_len + scid_len + token_len_field + length_field + 4
            // Simplified: estimate based on typical structure
            int offset = 6; // flags(1) + version(4) + dcid_len(1)
            if (offset >= packet.Length) return false;
            byte dcidLen = packet[5];
            offset += dcidLen + 1; // +1 for scid_len
            if (offset >= packet.Length) return false;
            byte scidLen = packet[offset - 1];
            offset += scidLen;

            // Skip token length (varint) and token if present
            if (offset < packet.Length && (packet[0] & 0x30) == 0x00) // Initial packet type
            {
                // Token length varint
                int tokenLen = packet[offset];
                if ((tokenLen & 0x80) != 0)
                {
                    tokenLen = ((tokenLen & 0x7F) << 8) | packet[offset + 1];
                    offset += 2;
                }
                else
                {
                    offset += 1;
                }
                offset += tokenLen;
            }

            // Skip length field (varint)
            if (offset >= packet.Length) return false;
            int lengthField = packet[offset];
            if ((lengthField & 0x80) != 0)
            {
                offset += 2;
            }
            else
            {
                offset += 1;
            }

            pnOffset = offset;
            sampleOffset = pnOffset + 4; // Sample starts 4 bytes after assumed PN start
        }
        else
        {
            // Short header: pn_offset = 1 + dcid_len
            // For 1-RTT packets, DCID length is typically 0 after handshake completes
            // However, it could be up to 20 bytes. We need to try different lengths.
            int dcidLen = 0; // Default assumption for 1-RTT

            // Try to infer DCID length from packet structure
            // If packet is very short, DCID is likely 0
            if (packet.Length < 10)
            {
                dcidLen = 0;
            }
            else
            {
                // Check if this looks like a valid 1-RTT packet with 0-length DCID
                // The spin bit and reserved bits should be 0 in most implementations
                if ((packet[0] & 0x04) == 0) // Spin bit check
                {
                    dcidLen = 0;
                }
            }

            pnOffset = 1 + dcidLen;
            sampleOffset = pnOffset + 4; // Sample starts 4 bytes after PN start
        }

        if (sampleOffset + 16 > packet.Length)
            return false; // Not enough data for sample

        // Extract 16-byte sample from ciphertext
        byte[] sample = new byte[16];
        Buffer.BlockCopy(packet, sampleOffset, sample, 0, 16);

        // Generate mask using AES-ECB
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
        catch
        {
            return false;
        }

        // Apply mask to header
        if (isLongHeader)
        {
            // Long header: mask 4 bits of first byte
            unprotectedHeader[0] ^= (byte)(mask[0] & 0x0F);
        }
        else
        {
            // Short header: mask 5 bits of first byte
            unprotectedHeader[0] ^= (byte)(mask[0] & 0x1F);
        }

        // Get actual packet number length from unmasked header
        pnLength = (unprotectedHeader[0] & 0x03) + 1;

        if (pnOffset + pnLength > packet.Length)
            return false;

        // Unmask packet number
        for (int i = 0; i < pnLength; i++)
        {
            unprotectedHeader[pnOffset + i] ^= mask[1 + i];
        }

        return true;
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
            keysCopy = _discoveredKeys
                .Where(k => k.Key.Length >= 16 && k.IV.Length == 12)
                .OrderByDescending(k => k.UseCount)
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
        Console.WriteLine($"[DECRYPT-DEBUG] Packet size: {encryptedData.Length} bytes");
        Console.WriteLine($"[DECRYPT-DEBUG] First 16 bytes: {BitConverter.ToString(encryptedData.Take(16).ToArray())}");
        Console.WriteLine($"[DECRYPT-DEBUG] IsLongHeader: {(encryptedData[0] & 0x80) != 0}");
        Console.WriteLine($"[DECRYPT-DEBUG] Available keys: {keysCopy.Count}");

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

            Console.WriteLine($"[DECRYPT-DEBUG] Trying key: {key.Type}");
            Console.WriteLine($"[DECRYPT-DEBUG] Key bytes: {BitConverter.ToString(key.Key)}");
            Console.WriteLine($"[DECRYPT-DEBUG] IV bytes: {BitConverter.ToString(key.IV)}");
            Console.WriteLine($"[DECRYPT-DEBUG] Has HP key: {key.HeaderProtectionKey != null}");
            if (key.HeaderProtectionKey != null)
                Console.WriteLine($"[DECRYPT-DEBUG] HP key: {BitConverter.ToString(key.HeaderProtectionKey)}");

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

            // Extract packet number from unprotected header
            ulong packetNumber = 0;  // <-- DECLARE IT HERE FIRST
            for (int i = 0; i < pnLength && i < 8; i++)
            {
                packetNumber = (packetNumber << 8) | unprotectedHeader[pnOffset + i];
            }

            // NOW do the sanity check after extraction
            if (packetNumber > 1000000)  // Sanity check
            {
                return new DecryptionResult { Success = false, ErrorMessage = "Invalid packet number from header protection" };
            }

            Console.WriteLine($"[DECRYPT-DEBUG] Extracted packet number: {packetNumber}");

            // Build header for AEAD (everything up to and including packet number)
            byte[] header = new byte[pnOffset + pnLength];
            Buffer.BlockCopy(unprotectedHeader, 0, header, 0, header.Length);
            Console.WriteLine($"[DECRYPT-DEBUG] Header for AEAD: {BitConverter.ToString(header)}");

            // Extract payload (everything after packet number)
            int payloadOffset = pnOffset + pnLength;
            int payloadLen = packetData.Length - payloadOffset - 16; // -16 for auth tag

            if (payloadLen <= 0)
                return new DecryptionResult { Success = false, ErrorMessage = $"Invalid payload length: {payloadLen}" };

            byte[] payload = new byte[payloadLen];
            Buffer.BlockCopy(packetData, payloadOffset, payload, 0, payloadLen);
            Console.WriteLine($"[DECRYPT-DEBUG] Payload length: {payloadLen}");

            byte[] tag = new byte[16];
            Buffer.BlockCopy(packetData, packetData.Length - 16, tag, 0, 16);

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
    private static DecryptionResult TryDecryptWithBruteForceDetailed(byte[] packetData, EncryptionKey key, CancellationToken ct)
    {
        Console.WriteLine($"[DECRYPT-DEBUG] Brute force starting for key {key.Type}");

        bool isLongHeader = (packetData[0] & 0x80) != 0;
        Console.WriteLine($"[DECRYPT-DEBUG] IsLongHeader: {isLongHeader}");

        // For short headers, try different DCID lengths
        int[] dcidLengths = isLongHeader ? new[] { 0 } : new[] { 0, 4, 8, 12, 16 };

        int attempts = 0;

        foreach (int dcidLen in dcidLengths)
        {
            if (ct.IsCancellationRequested)
                return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

            int headerLen = isLongHeader ? 0 : 1 + dcidLen;

            // Try different PN lengths (1-4 bytes)
            for (int pnLen = 1; pnLen <= 4; pnLen++)
            {
                int pnOffset = headerLen;
                int payloadOffset = pnOffset + pnLen;

                if (payloadOffset + 16 > packetData.Length) continue;

                // Extract base packet number
                ulong basePN = 0;
                for (int i = 0; i < pnLen && i < 8; i++)
                {
                    basePN = (basePN << 8) | packetData[pnOffset + i];
                }

                // Try nearby packet numbers
                for (ulong pnDelta = 0; pnDelta < 30; pnDelta++)
                {
                    attempts++;

                    // Try incrementing
                    var result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN + pnDelta, pnOffset, ct);
                    if (result.Success)
                    {
                        Console.WriteLine($"[DECRYPT-DEBUG] Brute force success after {attempts} attempts! PN={basePN + pnDelta}");
                        return result;
                    }

                    // Try decrementing
                    if (basePN >= pnDelta && pnDelta > 0)
                    {
                        result = TryDecryptAtPN(packetData, key, headerLen, pnLen, basePN - pnDelta, pnOffset,ct);
                        if (result.Success)
                        {
                            Console.WriteLine($"[DECRYPT-DEBUG] Brute force success after {attempts} attempts! PN={basePN - pnDelta}");
                            return result;
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

    private static DecryptionResult TryDecryptAtPN(byte[] packetData, EncryptionKey key, int headerLen, int pnLen, ulong packetNumber, int pnOffset, CancellationToken ct)
    {
        try
        {
            if (ct.IsCancellationRequested)
                return new DecryptionResult { Success = false, ErrorMessage = "Cancelled" };

            // Build header for AEAD (everything up to and including packet number)
            byte[] header = new byte[headerLen + pnLen];
            Buffer.BlockCopy(packetData, 0, header, 0, header.Length);

            // Extract payload (everything after packet number, excluding auth tag)
            int payloadOffset = headerLen + pnLen;
            int payloadLen = packetData.Length - payloadOffset - 16; // 16 bytes for AES-GCM tag

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
                            ["brute_force"] = true
                        }
                    };
                }
            }
            catch (CryptographicException)
            {
                // Expected for wrong PN - ignore and return failure below
            }

            // Return failure if we get here
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

            // Build header for AEAD (everything up to and including packet number)
            byte[] header = new byte[pnOffset + pnLength];
            Buffer.BlockCopy(unprotectedHeader, 0, header, 0, header.Length);

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
        if (key.Secret == null || key.Secret.Length == 0)
        {
            Console.WriteLine($"[KEY-DERIVE] No secret available for {key.Type}");
            return;
        }

        try
        {
            Console.WriteLine($"[KEY-DERIVE] ========== {key.Type} ==========");
            Console.WriteLine($"[KEY-DERIVE] Secret length: {key.Secret.Length} bytes");
            Console.WriteLine($"[KEY-DERIVE] Secret (first 16 bytes): {BitConverter.ToString(key.Secret.Take(16).ToArray())}");

            int secretLength = key.Secret.Length;

            // Handle different secret lengths
            if (secretLength == 32)
            {
                // 32-byte secret (likely TLS 1.2 or custom) - use direct derivation
                Console.WriteLine($"[KEY-DERIVE] Detected 32-byte secret (TLS 1.2 style)");
                Console.WriteLine($"[KEY-DERIVE] Using DIRECT derivation (no HKDF)");

                key.Key = key.Secret.Take(16).ToArray();
                key.IV = key.Secret.Skip(16).Take(12).ToArray();
                key.HeaderProtectionKey = key.Key.ToArray(); // Copy of key

                Console.WriteLine($"[KEY-DERIVE] Key (first 16 bytes of secret): {Convert.ToHexString(key.Key)}");
                Console.WriteLine($"[KEY-DERIVE] IV (bytes 16-27 of secret): {Convert.ToHexString(key.IV)}");
                Console.WriteLine($"[KEY-DERIVE] HP (same as key): {Convert.ToHexString(key.HeaderProtectionKey)}");
            }
            else if (secretLength == 48)
            {
                // 48-byte secret (standard TLS 1.3) - use RFC 9001 HKDF
                Console.WriteLine($"[KEY-DERIVE] Detected 48-byte secret (TLS 1.3 style)");
                Console.WriteLine($"[KEY-DERIVE] Using RFC 9001 HKDF derivation");

                int keyLength = 32; // AES-256 for 48-byte secrets

                Console.WriteLine($"[KEY-DERIVE] --- RFC 9001 (no 'tls13 ' prefix) ---");
                var rfcKey = HkdfExpandLabelQUIC(key.Secret, QUIC_KEY_LABEL, Array.Empty<byte>(), keyLength);
                var rfcIV = HkdfExpandLabelQUIC(key.Secret, QUIC_IV_LABEL, Array.Empty<byte>(), 12);
                var rfcHP = HkdfExpandLabelQUIC(key.Secret, QUIC_HP_LABEL, Array.Empty<byte>(), keyLength);

                Console.WriteLine($"[KEY-DERIVE] Key: {Convert.ToHexString(rfcKey)}");
                Console.WriteLine($"[KEY-DERIVE] IV:  {Convert.ToHexString(rfcIV)}");
                Console.WriteLine($"[KEY-DERIVE] HP:  {Convert.ToHexString(rfcHP)}");

                Console.WriteLine($"[KEY-DERIVE] --- TLS 1.3 style (with 'tls13 ' prefix) ---");
                var tlsKey = HkdfExpandLabel(key.Secret, QUIC_KEY_LABEL, Array.Empty<byte>(), keyLength);
                var tlsIV = HkdfExpandLabel(key.Secret, QUIC_IV_LABEL, Array.Empty<byte>(), 12);
                var tlsHP = HkdfExpandLabel(key.Secret, QUIC_HP_LABEL, Array.Empty<byte>(), keyLength);

                Console.WriteLine($"[KEY-DERIVE] Key: {Convert.ToHexString(tlsKey)}");
                Console.WriteLine($"[KEY-DERIVE] IV:  {Convert.ToHexString(tlsIV)}");
                Console.WriteLine($"[KEY-DERIVE] HP:  {Convert.ToHexString(tlsHP)}");

                // Use RFC 9001 version
                key.Key = rfcKey;
                key.IV = rfcIV;
                key.HeaderProtectionKey = rfcHP;
            }
            else
            {
                // Unknown secret length - try HKDF anyway
                Console.WriteLine($"[KEY-DERIVE] Unknown secret length {secretLength}, trying standard HKDF");

                key.Key = HkdfExpandLabelQUIC(key.Secret, QUIC_KEY_LABEL, Array.Empty<byte>(), 16);
                key.IV = HkdfExpandLabelQUIC(key.Secret, QUIC_IV_LABEL, Array.Empty<byte>(), 12);
                key.HeaderProtectionKey = HkdfExpandLabelQUIC(key.Secret, QUIC_HP_LABEL, Array.Empty<byte>(), 16);
            }

            // Validate derived keys
            if (key.Key.Length == 0 || key.IV.Length == 0)
            {
                throw new InvalidOperationException("Derived keys are empty");
            }

            Console.WriteLine($"[KEY-DERIVE] ✓ Successfully derived {key.Key.Length * 8}-bit keys");
            Console.WriteLine($"[KEY-DERIVE] ====================================");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KEY-DERIVE] ✗ FAILED: {ex.Message}");
            Console.WriteLine($"[KEY-DERIVE] Stack trace: {ex.StackTrace}");
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

    // RFC 9001 QUIC-TLS key derivation (NO "tls13 " prefix!)
    private static byte[] HkdfExpandLabelQUIC(byte[] secret, byte[] label, byte[] context, int length)
    {
        // Build label: length(2) + label_len(1) + label + context_len(1) + context
        var hkdfLabel = new List<byte>(128);

        // Length of derived key (16 bits, big-endian)
        hkdfLabel.Add((byte)(length >> 8));
        hkdfLabel.Add((byte)(length & 0xFF));

        // Label length and label
        hkdfLabel.Add((byte)label.Length);
        hkdfLabel.AddRange(label);

        // Context length and context
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