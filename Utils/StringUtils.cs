using System;
using System.Collections.Generic;  // ADDED
using System.IO;                   // ADDED
using System.Text;

namespace HyForce.Utils;

public static class StringUtils
{
    public static string Truncate(string value, int maxLength, string suffix = "...")
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length <= maxLength ? value : value[..(maxLength - suffix.Length)] + suffix;
    }

    public static string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int counter = 0;
        decimal number = bytes;

        while (Math.Round(number / 1024) >= 1)
        {
            number /= 1024;
            counter++;
        }

        return $"{number:n2} {suffixes[counter]}";
    }

    public static string FormatNumber(long number)
    {
        return number.ToString("#,##0");
    }

    public static string ToValidFilename(string input)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            input = input.Replace(c, '_');
        }
        return input;
    }

    public static string Repeat(char c, int count)
    {
        return new string(c, count);
    }

    public static string Center(string text, int width)
    {
        if (text.Length >= width) return text;
        int padding = (width - text.Length) / 2;
        return new string(' ', padding) + text + new string(' ', width - text.Length - padding);
    }

    public static List<string> WrapText(string text, int maxLineLength)
    {
        var lines = new List<string>();
        var words = text.Split(' ');
        var currentLine = new StringBuilder();

        foreach (var word in words)
        {
            if (currentLine.Length + word.Length + 1 > maxLineLength)
            {
                lines.Add(currentLine.ToString());
                currentLine.Clear();
            }

            if (currentLine.Length > 0)
                currentLine.Append(' ');
            currentLine.Append(word);
        }

        if (currentLine.Length > 0)
            lines.Add(currentLine.ToString());

        return lines;
    }
}