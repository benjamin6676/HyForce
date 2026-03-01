namespace HyForce.Networking;

public class QuicHeaderInfo
{
    public bool IsLongHeader { get; set; }
    public uint Version { get; set; }
    public byte[] ClientConnectionId { get; set; } = Array.Empty<byte>();
    public byte[]? ServerConnectionId { get; set; }
    public byte[]? DestinationConnectionId { get; set; }  // ADDED
    public byte[]? SourceConnectionId { get; set; }       // ADDED
    public int PacketNumberLength { get; set; }
    public ulong PacketNumber { get; set; }               // ADDED
    public string HeaderType => IsLongHeader ? "Long" : "Short";  // ADDED
}