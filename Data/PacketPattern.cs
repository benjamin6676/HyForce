// FILE: Data/PacketPattern.cs
namespace HyForce.Data;

public class PacketPattern
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public ushort? Opcode { get; set; }
    public int? MinSize { get; set; }
    public int? MaxSize { get; set; }
    public PacketDirection? Direction { get; set; }
    public bool IsTcp { get; set; }
    public byte[]? Signature { get; set; }
    public Func<byte[], bool>? CustomMatcher { get; set; }

    public bool Matches(PacketLogEntry entry, byte[] rawData)
    {
        if (Opcode.HasValue && entry.OpcodeDecimal != Opcode.Value)
            return false;

        if (MinSize.HasValue && entry.ByteLength < MinSize.Value)
            return false;

        if (MaxSize.HasValue && entry.ByteLength > MaxSize.Value)
            return false;

        if (Direction.HasValue && entry.Direction != Direction.Value)
            return false;

        if (entry.IsTcp != IsTcp)
            return false;

        if (Signature != null && Signature.Length > 0)
        {
            if (rawData.Length < Signature.Length)
                return false;

            for (int i = 0; i < Signature.Length; i++)
            {
                if (rawData[i] != Signature[i])
                    return false;
            }
        }

        if (CustomMatcher != null)
            return CustomMatcher(rawData);

        return true;
    }
}

public enum PacketDirection
{
    ServerToClient,
    ClientToServer
}