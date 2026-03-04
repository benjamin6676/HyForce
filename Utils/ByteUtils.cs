namespace HyForce.Utils;

public static class ByteUtils
{
    public static ushort ReadUInt16BE(byte[] data, int offset)
    {
        if (data.Length < offset + 2) return 0;
        return (ushort)((data[offset] << 8) | data[offset + 1]);
    }

    public static uint ReadUInt32BE(byte[] data, int offset)
    {
        if (data.Length < offset + 4) return 0;
        return (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
    }

    public static string ToHex(byte[] data, int maxLen = -1)
    {
        if (data == null || data.Length == 0) return "";
        int len = maxLen > 0 ? Math.Min(data.Length, maxLen) : data.Length;
        return BitConverter.ToString(data, 0, len);
    }

    public static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var frequencies = new int[256];
        foreach (byte b in data) frequencies[b]++;

        double entropy = 0;
        int length = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] == 0) continue;
            double p = (double)frequencies[i] / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static List<string> ExtractStrings(byte[] data, int minLength = 4)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] >= 32 && data[i] <= 126)
            {
                sb.Append((char)data[i]);
            }
            else
            {
                if (sb.Length >= minLength)
                    result.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= minLength)
            result.Add(sb.ToString());

        return result;
    }
}