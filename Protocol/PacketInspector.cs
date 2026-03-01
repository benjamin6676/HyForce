using System.Text;

namespace HyForce.Protocol;

public static class PacketInspector
{
    public static InspectionResult Inspect(byte[] data)
    {
        var result = new InspectionResult
        {
            Size = data.Length,
            Entropy = CalculateEntropy(data),
            IsCompressed = DetectCompression(data),
            CompressionType = GetCompressionType(data),
            PrintableStrings = ExtractPrintableStrings(data),
            PossibleOpcode = data.Length >= 2 ? (ushort)((data[0] << 8) | data[1]) : (ushort)0
        };

        result.IsEncrypted = result.Entropy > 7.8;
        result.IsSuspicious = result.Entropy > 7.0 && result.Entropy <= 7.8;

        return result;
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var frequencies = new int[256];
        foreach (byte b in data)
            frequencies[b]++;

        double entropy = 0;
        int len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] == 0) continue;
            double p = (double)frequencies[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool DetectCompression(byte[] data)
    {
        // Zstd
        if (data.Length >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD)
            return true;

        // Gzip
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B)
            return true;

        // Deflate/zlib
        if (data.Length >= 2 && ((data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA))))
            return true;

        return false;
    }

    private static string GetCompressionType(byte[] data)
    {
        if (data.Length >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD)
            return "zstd";
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B)
            return "gzip";
        if (data.Length >= 2 && data[0] == 0x78)
            return "zlib";
        return "none";
    }

    private static List<string> ExtractPrintableStrings(byte[] data, int minLength = 4)
    {
        var strings = new List<string>();
        var sb = new StringBuilder();

        foreach (byte b in data)
        {
            if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    strings.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= minLength)
            strings.Add(sb.ToString());

        return strings;
    }
}

public class InspectionResult
{
    public int Size { get; set; }
    public double Entropy { get; set; }
    public bool IsEncrypted { get; set; }
    public bool IsCompressed { get; set; }
    public bool IsSuspicious { get; set; }
    public string CompressionType { get; set; } = "none";
    public List<string> PrintableStrings { get; set; } = new();
    public ushort PossibleOpcode { get; set; }
}