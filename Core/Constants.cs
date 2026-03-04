namespace HyForce.Core;

public static class Constants
{
    public const string AppName = "HyForce";
    public const string AppSubtitle = "Hytale Security Analyzer";
    public const string BuildName = "HyForce V22-Enhanced";
    public const string BuildVersion = "22.0.0";
    public const string BuildDate = "2024-03-01";

    // Default ports
    public const int DefaultHytalePort = 5520;
    public const int DefaultListenPort = 5521;
    public const int DefaultTargetPort = 5520;
    public const string DefaultTargetHost = "127.0.0.1";

    // Protocol
    public const ushort RegistrySyncOpcode = 0x18;
    public const ushort RegistryOpcodeStart = 0x28;
    public const ushort RegistryOpcodeEnd = 0x3F;

    // UI
    public const float DefaultWindowWidth = 1600;
    public const float DefaultWindowHeight = 900;

    // Network
    public const int MaxPacketSize = 65536;
    public const int BufferSize = 65536;
}