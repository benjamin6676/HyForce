namespace HyForce.Protocol;

public static class OpcodeRegistry
{
    public const ushort RegistryOpcode = 0x18;

    private static readonly Dictionary<ushort, OpcodeDef> Definitions = new();

    static OpcodeRegistry()
    {
        // Registry Sync - TCP
        Register(0x18, "RegistrySync", "TCP", true, "Item/block registry synchronization");

        // Extended Registry - TCP
        for (ushort i = 0x28; i <= 0x3F; i++)
            Register(i, $"RegistrySync_0x{i:X2}", "TCP", true, $"Extended registry slot 0x{i:X2}");

        // Common gameplay - UDP
        Register(0x01, "Handshake", "UDP", false, "Initial handshake");
        Register(0x02, "KeepAlive", "UDP", false, "Connection keepalive");
        Register(0x10, "EntityUpdate", "UDP", false, "Entity state update");
        Register(0x11, "PlayerMove", "UDP", false, "Player movement");
        Register(0x12, "ChunkData", "UDP", false, "World chunk data");

        // Login/Auth - TCP
        Register(0x0E, "LoginResponse", "TCP", true, "Login response with player data");
        Register(0x0F, "AuthRequest", "TCP", true, "Authentication request");
    }

    private static void Register(ushort opcode, string name, string protocol, bool isTcp, string desc)
    {
        Definitions[opcode] = new OpcodeDef
        {
            Opcode = opcode,
            Name = name,
            Protocol = protocol,
            IsTcp = isTcp,
            Description = desc
        };
    }

    public static string Label(ushort opcode, Networking.PacketDirection dir)
    {
        if (Definitions.TryGetValue(opcode, out var def))
            return def.Name;
        return dir == Networking.PacketDirection.ServerToClient ? $"S→C_0x{opcode:X2}" : $"C→S_0x{opcode:X2}";
    }

    public static bool IsKnown(ushort opcode) => Definitions.ContainsKey(opcode);
    public static bool IsTcpOpcode(ushort opcode) => Definitions.TryGetValue(opcode, out var def) && def.IsTcp;
    public static string GetDescription(ushort opcode) => Definitions.TryGetValue(opcode, out var def) ? def.Description : "Unknown";
    public static IEnumerable<OpcodeDef> GetAll() => Definitions.Values;

    public class OpcodeDef
    {
        public ushort Opcode { get; set; }
        public string Name { get; set; } = "";
        public string Protocol { get; set; } = "";
        public bool IsTcp { get; set; }
        public string Description { get; set; } = "";
    }
}