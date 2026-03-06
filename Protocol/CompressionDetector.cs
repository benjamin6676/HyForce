namespace HyForce.Protocol;

public static class CompressionDetector
{
    public static CompressionInfo Detect(byte[] data)
    {
        var info = new CompressionInfo { OriginalSize = data.Length };

        // Check Zstd
        if (IsZstd(data))
        {
            info.IsCompressed = true;
            info.Algorithm = "Zstd";
            info.MagicBytes = new byte[] { 0x28, 0xB5, 0x2F, 0xFD };
            return info;
        }

        // Check Gzip
        if (IsGzip(data))
        {
            info.IsCompressed = true;
            info.Algorithm = "Gzip";
            info.MagicBytes = new byte[] { 0x1F, 0x8B };
            return info;
        }

        // Check Deflate/Zlib
        if (IsZlib(data))
        {
            info.IsCompressed = true;
            info.Algorithm = "Zlib";
            info.MagicBytes = new byte[] { data[0], data[1] };
            return info;
        }

        info.IsCompressed = false;
        info.Algorithm = "None";
        return info;
    }

    private static bool IsZstd(byte[] data) =>
        data.Length >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD;

    private static bool IsGzip(byte[] data) =>
        data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B;

    private static bool IsZlib(byte[] data) =>
        data.Length >= 2 && data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA);
}

public class CompressionInfo
{
    public bool IsCompressed { get; set; }
    public string Algorithm { get; set; } = "None";
    public int OriginalSize { get; set; }
    public byte[]? MagicBytes { get; set; }
}
