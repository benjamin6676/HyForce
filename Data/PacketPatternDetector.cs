// FILE: Data/PacketPatternDetector.cs
using HyForce.Networking;
using HyForce.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Data;

public static class PacketPatternDetector
{
    public static List<PacketPattern> DetectPatterns(List<PacketLogEntry> packets)
    {
        var patterns = new List<PacketPattern>();

        // Group by opcode
        var grouped = packets.GroupBy(p => p.OpcodeDecimal);

        foreach (var group in grouped)
        {
            var list = group.ToList();
            if (list.Count < 5) continue; // Need at least 5 packets for pattern

            var pattern = new PacketPattern
            {
                Opcode = group.Key,
                PacketName = list[0].OpcodeName,
                Count = list.Count,
                AvgSize = (int)list.Average(p => p.ByteLength),
                Direction = list[0].Direction
            };

            // Detect periodic patterns
            if (list.Count >= 10)
            {
                var intervals = new List<double>();
                for (int i = 1; i < list.Count; i++)
                {
                    intervals.Add((list[i].Timestamp - list[i - 1].Timestamp).TotalMilliseconds);
                }

                var avgInterval = intervals.Average();
                var variance = intervals.Select(i => Math.Abs(i - avgInterval)).Average();

                if (variance < avgInterval * 0.1) // Less than 10% variance
                {
                    pattern.IsPeriodic = true;
                    pattern.PeriodMs = avgInterval;
                }
            }

            // Detect burst patterns
            var timeSpan = list.Last().Timestamp - list.First().Timestamp;
            if (timeSpan.TotalSeconds > 0)
            {
                var rate = list.Count / timeSpan.TotalSeconds;
                if (rate > 50) // More than 50 packets per second
                {
                    pattern.IsBurst = true;
                    pattern.RatePerSecond = rate;
                }
            }

            patterns.Add(pattern);
        }

        return patterns.OrderByDescending(p => p.Count).ToList();
    }
}