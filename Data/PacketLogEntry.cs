namespace HyForce.Data;

public class PacketLogEntry
{
    public DateTime Timestamp { get; set; }
    public Networking.PacketDirection Direction { get; set; }
    public int ByteLength { get; set; }
    public ushort OpcodeDecimal { get; set; }
    public string OpcodeName { get; set; } = "";
    public bool IsTcp { get; set; }
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();  // ADD THIS LINE

    // UI compatibility properties
    public string DirStr => Direction == Networking.PacketDirection.ServerToClient ? "S?C" : "C?S";
    public string ProtoStr => IsTcp ? "TCP" : "UDP";
    public string RawHexPreview { get; set; } = "";
    public string? DecompHexPreview { get; set; }
    public string CompressionMethod { get; set; } = "none";
    public int CompressedSize { get; set; }
    public int DecompressedSize { get; set; }
    public string EncryptionHint { get; set; } = "none";
    public bool IsCompressed => CompressionMethod != "none";
    public bool Injected { get; set; }

    // Quic info
    public Networking.QuicHeaderInfo? QuicInfo { get; set; }
}