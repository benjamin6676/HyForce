using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HyForce.Core;

public class ServerPreset
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("ipAddress")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public int Port { get; set; } = 5520;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("isBuiltIn")]
    public bool IsBuiltIn { get; set; } = false;
}

public class Config
{
    private static readonly string PresetsFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "HyForce", "server_presets.json");

    public static readonly List<ServerPreset> BuiltInPresets = new()
    {
        new ServerPreset
        {
            Name = "HyTide",
            IpAddress = "149.56.241.73",
            Port = 5520,
            Description = "Official HyTide server",
            IsBuiltIn = true
        },
        new ServerPreset
        {
            Name = "HyTown",
            IpAddress = "51.195.60.80",
            Port = 5520,
            Description = "Official HyTown server",
            IsBuiltIn = true
        },
        new ServerPreset
        {
            Name = "HyBlock",
            IpAddress = "66.70.180.128",
            Port = 5520,
            Description = "Official HyBlock server",
            IsBuiltIn = true
        },
        new ServerPreset
        {
            Name = "Blank",
            IpAddress = "",
            Port = 5520,
            Description = "Empty preset for custom entry",
            IsBuiltIn = true
        }
    };

    // Existing properties
    public bool AutoAnalyzeRegistry { get; set; } = true;
    public bool AutoExportOnStop { get; set; } = false;
    public bool AutoScrollLogs { get; set; } = true;
    public bool CaptureTcp { get; set; } = true;
    public bool CaptureUdp { get; set; } = true;
    public int ConnectionTimeoutMs { get; set; } = 30000;
    public bool EnableAnomalyDetection { get; set; } = true;
    public string ExportDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HyForce", "Exports");
    public int MaxPacketLogSize { get; set; } = 10000;
    public bool ShowTimestamps { get; set; } = true;

    // New properties
    public List<ServerPreset> CustomPresets { get; set; } = new();
    public int AnomalyThresholdSize { get; set; } = 65535;
    public bool DarkTheme { get; set; } = true;
    public bool EnableCompressionDetection { get; set; } = true;
    public bool EnableEncryptionAnalysis { get; set; } = true;
    public bool AttemptDecryption { get; set; } = false;
    public string TlsKeyLogFile { get; set; } = string.Empty;
    public bool UseExperimentalQuicParser { get; set; } = false;

    public Config()
    {
        LoadPresets();
    }

    public List<ServerPreset> GetAllPresets()
    {
        var all = new List<ServerPreset>(BuiltInPresets);
        all.AddRange(CustomPresets);
        return all;
    }

    public void AddCustomPreset(ServerPreset preset)
    {
        preset.IsBuiltIn = false;
        CustomPresets.Add(preset);
        SavePresets();
    }

    public void DeleteCustomPreset(string name)
    {
        CustomPresets.RemoveAll(p => p.Name == name && !p.IsBuiltIn);
        SavePresets();
    }

    private void LoadPresets()
    {
        try
        {
            if (File.Exists(PresetsFilePath))
            {
                var json = File.ReadAllText(PresetsFilePath);
                var loaded = JsonSerializer.Deserialize<List<ServerPreset>>(json);
                if (loaded != null)
                    CustomPresets = loaded;
            }
        }
        catch { /* Ignore load errors */ }
    }

    private void SavePresets()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PresetsFilePath)!);
            var json = JsonSerializer.Serialize(CustomPresets, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(PresetsFilePath, json);
        }
        catch { /* Ignore save errors */ }
    }
}
