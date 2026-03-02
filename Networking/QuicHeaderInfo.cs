// FILE: Networking/QuicHeaderInfo.cs - FIXED: Added short header support fields
namespace HyForce.Networking;

public class QuicHeaderInfo
{
    public bool IsLongHeader { get; set; }
    public uint Version { get; set; }
    public byte[] ClientConnectionId { get; set; } = Array.Empty<byte>();
    public byte[]? ServerConnectionId { get; set; }
    public byte[]? DestinationConnectionId { get; set; }
    public byte[]? SourceConnectionId { get; set; }
    public int PacketNumberLength { get; set; }
    public ulong PacketNumber { get; set; }

    // FIXED: Added short header specific fields
    public bool SpinBit { get; set; }
    public bool KeyPhase { get; set; }
    public int ReservedBits { get; set; }

    public string HeaderType => IsLongHeader ? "Long" : "Short";

    // FIXED: Helper to get DCID length (important for short headers)
    public int GetDestinationConnectionIdLength()
    {
        if (IsLongHeader)
            return ClientConnectionId.Length;
        return DestinationConnectionId?.Length ?? 0;
    }
}