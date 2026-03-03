// FILE: Networking/PacketInjector.cs
// Inject packets back into the proxy — towards the server (C2S) or the client (S2C).
//
// Flow:
//   1. Take a plaintext payload (already modified by the user in InjectTab).
//   2. Re-encrypt with the current session key via PacketDecryptor.Encrypt().
//   3. Send via the UdpProxy socket.
//
// Safety:
//   - Injected packets are flagged so the feed shows [INJ] and they are excluded
//     from correlation/fuzzing loops to prevent recursive injection.
//   - Rate limiter: max 50 packets/sec to avoid disconnect.

using System.Net;
using HyForce.Core;
using HyForce.Protocol;

namespace HyForce.Networking;

public class PacketInjector
{
    private readonly AppState  _state;
    private readonly object    _rateLock  = new();
    private          DateTime  _windowStart = DateTime.UtcNow;
    private          int       _windowCount  = 0;

    public const int MaxPerSecond = 50;

    // History of injected packets (capped at 200)
    public List<InjectedPacket> History { get; } = new();
    public int TotalInjected { get; private set; }

    public PacketInjector(AppState state)
    {
        _state = state;
    }

    // ── Inject to server (C2S) ────────────────────────────────────────────

    /// <summary>
    /// Re-encrypt <paramref name="plaintextPayload"/> with the current 1-RTT client key
    /// and send it through the UdpProxy server socket.
    /// </summary>
    public async Task<InjectionResult> InjectToServerAsync(
        byte[] plaintextPayload,
        uint   overridePacketId = 0,
        CancellationToken ct    = default)
    {
        return await InjectCoreAsync(plaintextPayload, PacketDirection.ClientToServer, overridePacketId, ct);
    }

    /// <summary>Send raw (already-encrypted) bytes to the server with no re-encryption.</summary>
    public async Task<InjectionResult> InjectRawToServerAsync(byte[] encryptedBytes, CancellationToken ct = default)
    {
        if (!CheckRateLimit())
            return InjectionResult.Fail("Rate limit exceeded");

        if (!_state.UdpProxy.IsRunning)
            return InjectionResult.Fail("UDP proxy not running");

        try
        {
            await _state.UdpProxy.InjectToServerAsync(encryptedBytes);
            RecordInjection(encryptedBytes, PacketDirection.ClientToServer, 0, true);
            return InjectionResult.Ok(encryptedBytes.Length);
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(ex.Message);
        }
    }

    // ── Inject to client (S2C) ────────────────────────────────────────────

    /// <summary>Re-encrypt and send to the local game client.</summary>
    public async Task<InjectionResult> InjectToClientAsync(
        byte[] plaintextPayload,
        uint   overridePacketId = 0,
        CancellationToken ct    = default)
    {
        return await InjectCoreAsync(plaintextPayload, PacketDirection.ServerToClient, overridePacketId, ct);
    }

    // ── Batch injection ───────────────────────────────────────────────────

    public async Task<List<InjectionResult>> InjectBatchAsync(
        IEnumerable<InjectionRequest> requests,
        TimeSpan                      delayBetween = default,
        CancellationToken             ct           = default)
    {
        var results = new List<InjectionResult>();
        foreach (var req in requests)
        {
            if (ct.IsCancellationRequested) break;

            var result = req.IsRaw
                ? await InjectRawToServerAsync(req.Bytes, ct)
                : await InjectToServerAsync(req.Bytes, req.OverridePacketId, ct);

            results.Add(result);
            _state.AddInGameLog($"[INJ] Batch {results.Count}: {result}");

            if (delayBetween > TimeSpan.Zero)
                await Task.Delay(delayBetween, ct);
        }
        return results;
    }

    // ── Replay ────────────────────────────────────────────────────────────

    /// <summary>Replay a list of captured packets at original or scaled timing.</summary>
    public async Task ReplayAsync(
        IList<Data.PacketLogEntry> packets,
        double speedMultiplier    = 1.0,
        bool   onlyClientToServer = true,
        CancellationToken ct      = default)
    {
        if (!packets.Any()) return;

        _state.AddInGameLog($"[INJ] Replaying {packets.Count} packets at {speedMultiplier}x");
        var origin = packets[0].Timestamp;

        foreach (var pkt in packets)
        {
            if (ct.IsCancellationRequested) break;
            if (onlyClientToServer && pkt.Direction != PacketDirection.ClientToServer) continue;

            var delay = (pkt.Timestamp - origin) / speedMultiplier;
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, ct);

            byte[] bytes = pkt.DecryptedBytes ?? pkt.RawBytes;
            var result = await InjectRawToServerAsync(bytes, ct);
            _state.AddInGameLog($"[REPLAY] 0x{pkt.ParsedPacketId ?? pkt.OpcodeDecimal:X4}: {result}");
        }

        _state.AddInGameLog("[INJ] Replay complete");
    }

    // ── Internal ──────────────────────────────────────────────────────────

    private async Task<InjectionResult> InjectCoreAsync(
        byte[] payload, PacketDirection dir, uint overridePacketId, CancellationToken ct)
    {
        if (!CheckRateLimit())
            return InjectionResult.Fail("Rate limit exceeded");

        if (!_state.UdpProxy.IsRunning)
            return InjectionResult.Fail("UDP proxy not running");

        if (PacketDecryptor.DiscoveredKeys.Count == 0)
            return InjectionResult.Fail("No encryption keys — cannot re-encrypt");

        try
        {
            // Build wire format: [4B LE length][4B LE packetId][payload]
            byte[] wire = BuildWireFrame(payload, overridePacketId);

            // Re-encrypt
            var reEncResult = PacketDecryptor.TryEncrypt(wire, dir);
            if (!reEncResult.Success || reEncResult.EncryptedData == null)
                return InjectionResult.Fail($"Re-encryption failed: {reEncResult.ErrorMessage}");

            if (dir == PacketDirection.ClientToServer)
                await _state.UdpProxy.InjectToServerAsync(reEncResult.EncryptedData);
            else
                await _state.UdpProxy.InjectToClientAsync(reEncResult.EncryptedData);

            RecordInjection(reEncResult.EncryptedData, dir, overridePacketId, false);
            return InjectionResult.Ok(reEncResult.EncryptedData.Length);
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(ex.Message);
        }
    }

    private static byte[] BuildWireFrame(byte[] payload, uint packetId)
    {
        var frame = new byte[8 + payload.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)payload.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4), packetId);
        payload.CopyTo(frame, 8);
        return frame;
    }

    private bool CheckRateLimit()
    {
        lock (_rateLock)
        {
            var now = DateTime.UtcNow;
            if ((now - _windowStart).TotalSeconds >= 1.0)
            {
                _windowStart  = now;
                _windowCount  = 0;
            }
            if (_windowCount >= MaxPerSecond) return false;
            _windowCount++;
            return true;
        }
    }

    private void RecordInjection(byte[] bytes, PacketDirection dir, uint packetId, bool isRaw)
    {
        TotalInjected++;
        History.Add(new InjectedPacket
        {
            Timestamp = DateTime.Now,
            Direction = dir,
            PacketId  = packetId,
            Length    = bytes.Length,
            IsRaw     = isRaw,
            Preview   = BitConverter.ToString(bytes.Take(16).ToArray()).Replace("-", " ")
        });
        if (History.Count > 200) History.RemoveAt(0);
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

public class InjectionResult
{
    public bool   Success  { get; private set; }
    public string Message  { get; private set; } = "";
    public int    BytesSent { get; private set; }

    public static InjectionResult Ok(int bytes)   => new() { Success = true,  Message = $"{bytes}B sent",   BytesSent = bytes };
    public static InjectionResult Fail(string msg) => new() { Success = false, Message = msg };

    public override string ToString() => Success ? Message : $"FAILED: {Message}";
}

public class InjectedPacket
{
    public DateTime        Timestamp { get; set; }
    public PacketDirection Direction { get; set; }
    public uint            PacketId  { get; set; }
    public int             Length    { get; set; }
    public bool            IsRaw     { get; set; }
    public string          Preview   { get; set; } = "";
}

public class InjectionRequest
{
    public byte[] Bytes            { get; set; } = Array.Empty<byte>();
    public uint   OverridePacketId { get; set; }
    public bool   IsRaw            { get; set; }
}
