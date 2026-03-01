namespace HyForce.Networking;

public class QuicHeaderInfo
{
    public bool IsLongHeader { get; set; }
    public uint Version { get; set; }
    public byte[] ClientConnectionId { get; set; } = Array.Empty<byte>();
    public byte[]? ServerConnectionId { get; set; }
    public int PacketNumberLength { get; set; }
}