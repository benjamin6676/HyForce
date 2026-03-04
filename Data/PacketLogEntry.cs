// FILE: Data/PacketLogEntry.cs  (EXTENDED)
// ADDITIONS:
//   DecryptedBytes   -- persists plaintext after QUIC decrypt
//   ParsedPacketId   -- LE uint32 at offset 4 in DecryptedBytes
//   Fields           -- structured fields parsed by WireFormatParser
//   WasDecrypted     -- convenience bool

using HyForce.Protocol;

namespace HyForce.Data;

public class PacketLogEntry
{
    public DateTime   Timestamp         { get; set; }
    public Networking.PacketDirection Direction { get; set; }
    public int        ByteLength        { get; set; }
    public ushort     OpcodeDecimal     { get; set; }
    public string     OpcodeName        { get; set; } = "";
    public bool       IsTcp             { get; set; }
    public byte[]     RawBytes          { get; set; } = Array.Empty<byte>();

    // Decryption results (set by PacketDecryptor after successful decrypt)
    public byte[]?    DecryptedBytes    { get; set; }
    public uint?      ParsedPacketId    { get; set; }   // LE uint32 @ offset 4 of DecryptedBytes
    public bool       WasDecrypted      => DecryptedBytes != null;

    // Parsed fields (set by WireFormatParser)
    public List<ParsedField>? Fields   { get; set; }

    // UI properties
    public string DirStr    => Direction == Networking.PacketDirection.ServerToClient ? "S->C" : "C->S";
    public string ProtoStr  => IsTcp ? "TCP" : "UDP";
    public string StatusStr => WasDecrypted ? (Fields != null ? "[PARSE]" : "[DEC]") : "[RAW]";

    public string     RawHexPreview     { get; set; } = "";
    public string?    DecompHexPreview  { get; set; }
    public string     CompressionMethod { get; set; } = "none";
    public int        CompressedSize    { get; set; }
    public int        DecompressedSize  { get; set; }
    public string     EncryptionHint    { get; set; } = "none";
    public bool       IsCompressed      => CompressionMethod != "none";
    public bool       Injected          { get; set; }

    public Networking.QuicHeaderInfo? QuicInfo { get; set; }
}

// ----------------------------------------------------------------------------
// Represents one auto-detected field inside a decrypted packet
public class ParsedField
{
    public string   Name        { get; set; } = "";
    public int      Offset      { get; set; }
    public int      Length      { get; set; }
    public FieldType Type       { get; set; }
    public object?  Value       { get; set; }   // int, float, string, byte[], etc.
    public string   HexPreview  { get; set; } = "";
    public double   Confidence  { get; set; }   // 0.0-1.0

    public string DisplayValue => Value switch
    {
        float   f  => $"{f:F4}",
        int     i  => $"{i} (0x{i:X8})",
        uint    u  => $"{u} (0x{u:X8})",
        long    l  => $"{l} (0x{l:X16})",
        string  s  => $"\"{s}\"",
        byte[]  b  => BitConverter.ToString(b.Take(16).ToArray()).Replace("-", " "),
        _          => Value?.ToString() ?? "null"
    };
}

public enum FieldType
{
    Int32, UInt32, Int64, UInt64,
    Float, Double,
    Vec2, Vec3, Vec4,
    String8,  // UTF-8 length-prefixed
    String16, // UTF-16LE
    Bytes,
    Pointer,  // 8-byte heap pointer
    Bool,
    Unknown
}
