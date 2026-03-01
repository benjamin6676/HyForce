using HyForce.Protocol;

namespace HyForce.Networking;

public class CapturedPacket
{
    public uint SequenceId { get; set; }
    public DateTime Timestamp { get; set; }
    public PacketDirection Direction { get; set; }
    public ushort Opcode { get; set; }
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public bool IsTcp { get; set; }
    public string Source { get; set; } = "";
    public bool Injected { get; set; }
    public QuicHeaderInfo? QuicInfo { get; set; }

    // Parsed data
    public bool IsRegistrySync => IsTcp && Opcode is >= 0x18 and <= 0x3F;
    public string DirectionStr => Direction == PacketDirection.ServerToClient ? "S→C" : "C→S";
    public string ProtocolStr => IsTcp ? "TCP" : "UDP";
}