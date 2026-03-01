// FILE: Utils/ByteUtils.cs
namespace HyForce.Utils;

public static class ByteUtils
{
    public static string ToHex(byte[] data, int maxBytes = -1)
    {
        if (data == null || data.Length == 0) return "";

        int length = maxBytes > 0 ? Math.Min(maxBytes, data.Length) : data.Length;
        return BitConverter.ToString(data, 0, length);
    }

    public static List<string> ExtractStrings(byte[] data, int minLength = 3)
    {
        var result = new List<string>();
        if (data == null || data.Length == 0) return result;

        var sb = new System.Text.StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
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

    public static double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0;

        int[] frequencies = new int[256];
        foreach (byte b in data)
            frequencies[b]++;

        double entropy = 0;
        int length = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] > 0)
            {
                double probability = (double)frequencies[i] / length;
                entropy -= probability * Math.Log(probability, 2);
            }
        }

        return entropy;
    }
}