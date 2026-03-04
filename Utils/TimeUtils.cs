using System;

namespace HyForce.Utils;

public static class TimeUtils
{
    public static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalDays >= 1)
            return $"{duration.TotalDays:F1}d";
        if (duration.TotalHours >= 1)
            return $"{duration.TotalHours:F1}h";
        if (duration.TotalMinutes >= 1)
            return $"{duration.TotalMinutes:F1}m";
        return $"{duration.TotalSeconds:F1}s";
    }

    public static string FormatTimestamp(DateTime timestamp, bool includeDate = false)
    {
        if (includeDate)
            return timestamp.ToString("yyyy-MM-dd HH:mm:ss");
        return timestamp.ToString("HH:mm:ss.fff");
    }

    public static string FormatRelativeTime(DateTime timestamp)
    {
        var diff = DateTime.Now - timestamp;

        if (diff.TotalSeconds < 1)
            return "just now";
        if (diff.TotalSeconds < 60)
            return $"{(int)diff.TotalSeconds}s ago";
        if (diff.TotalMinutes < 60)
            return $"{(int)diff.TotalMinutes}m ago";
        if (diff.TotalHours < 24)
            return $"{(int)diff.TotalHours}h ago";
        return $"{(int)diff.TotalDays}d ago";
    }

    public static string FormatThroughput(long bytes, TimeSpan duration)
    {
        if (duration.TotalSeconds == 0) return "0 B/s";

        double bytesPerSecond = bytes / duration.TotalSeconds;
        return StringUtils.FormatBytes((long)bytesPerSecond) + "/s";
    }
}