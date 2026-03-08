// Tabs/TradeTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class TradeTab : ITab
{
    public string Name => "Trade";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly TradeCapture      _trade;

    private string _captureLabel    = "";
    private int    _selectedTxIdx   = -1;
    private int    _selectedFrameIdx= -1;
    private int    _replaySlot      = 0;
    private int    _replayCount     = 1;
    private bool   _logScroll       = true;
    private readonly List<string> _log = new();

    public TradeTab(AppState state, PipeCaptureServer pipe)
    {
        _state  = state;
        _pipe   = pipe;
        _trade  = state.TradeCapture;
        _trade.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 300f;

        // Status
        string capState = _trade.IsCapturing ? "● CAPTURING" : "■ IDLE";
        ImGui.TextColored(_trade.IsCapturing ? new Vector4(0.2f,1f,0.3f,1f) : new Vector4(0.5f,0.5f,0.5f,1f), capState);
        ImGui.SameLine(0,12);
        ImGui.TextDisabled($"{_trade.Transactions.Count} transactions stored");
        ImGui.Separator();

        ImGui.BeginChild("tr_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f,0.9f,1f,1f), "TRADE CAPTURE");
            ImGui.TextDisabled("Records 0xCB SendWindowAction C2S frames.\nInteract with a merchant, then stop.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Label##trlbl", ref _captureLabel, 64);

            if (!_trade.IsCapturing)
            {
                if (ImGui.Button("Start Capture##trsc", new Vector2(-1,28)))
                {
                    _trade.StartCapture(_captureLabel);
                    _pipe.TradeCaptureOn();
                }
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f,0.1f,0.1f,1f));
                if (ImGui.Button("Stop Capture##trsp", new Vector2(-1,28)))
                {
                    _trade.StopCapture();
                    _pipe.TradeCaptureOff();
                }
                ImGui.PopStyleColor();
                if (ImGui.Button("Cancel##trcan", new Vector2(-1,0)))
                {
                    _trade.CancelCapture();
                    _pipe.TradeCaptureOff();
                }
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "TRANSACTIONS");
            ImGui.BeginChild("tr_txlist", new Vector2(-1,180), ImGuiChildFlags.Borders);
            for (int i = 0; i < _trade.Transactions.Count; i++)
            {
                var tx = _trade.Transactions[i];
                bool sel = _selectedTxIdx == i;
                if (ImGui.Selectable($"{tx.Label}  [{tx.FrameCount} frames]##trtx{i}", sel))
                    _selectedTxIdx = sel ? -1 : i;
            }
            if (_trade.Transactions.Count == 0) ImGui.TextDisabled("  (none yet)");
            ImGui.EndChild();

            if (ImGui.SmallButton("Clear All##trcal")) { _trade.Clear(); _selectedTxIdx=-1; }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            if (_selectedTxIdx >= 0 && _selectedTxIdx < _trade.Transactions.Count)
            {
                var tx = _trade.Transactions[_selectedTxIdx];
                ImGui.TextColored(new Vector4(1f,0.85f,0.3f,1f), "REPLAY");
                ImGui.TextDisabled($"Selected: {tx.Label}");

                if (ImGui.Button("Replay All Frames##trra", new Vector2(-1,0)))
                {
                    foreach (var (_, data) in tx.Frames)
                        _pipe.ForgeStream(data);
                    AddLog($"[REPLAY] {tx.FrameCount} frames from '{tx.Label}'");
                }

                ImGui.Spacing();
                ImGui.TextDisabled("Replay with modified output slot:");
                ImGui.SetNextItemWidth(80); ImGui.InputInt("Output Slot##tros", ref _replaySlot, 1); ImGui.SameLine();
                ImGui.SetNextItemWidth(50); ImGui.InputInt("x##trcnt", ref _replayCount, 0);
                _replaySlot  = Math.Max(0, _replaySlot);
                _replayCount = Math.Max(1, _replayCount);

                if (_selectedFrameIdx >= 0 && ImGui.Button("Replay Frame (modified)##trfmod", new Vector2(-1,0)))
                {
                    byte[]? patched = _trade.BuildModifiedFrame(tx, _selectedFrameIdx, _replaySlot);
                    if (patched != null)
                    {
                        for (int ri = 0; ri < _replayCount; ri++) _pipe.ForgeStream(patched);
                        AddLog($"[REPLAY] Modified frame #{_selectedFrameIdx} slot={_replaySlot} x{_replayCount}");
                    }
                }
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("tr_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("tr_right_tabs"))
            {
                if (ImGui.BeginTabItem("Frames##trf"))
                {
                    RenderFrames(avail.Y-50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Log##trl"))
                {
                    RenderLog(avail.Y-50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderFrames(float h)
    {
        if (_selectedTxIdx < 0 || _selectedTxIdx >= _trade.Transactions.Count)
        { ImGui.TextDisabled("Select a transaction on the left."); return; }

        var tx = _trade.Transactions[_selectedTxIdx];
        ImGui.TextDisabled($"{tx.Summary}");
        ImGui.Separator();

        ImGui.BeginChild("tr_ftbl", new Vector2(-1, h-100), ImGuiChildFlags.None);
        if (ImGui.BeginTable("trftbl", 4, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("#",     ImGuiTableColumnFlags.WidthFixed, 35);
            ImGui.TableSetupColumn("Time",  ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Len",   ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("Hex",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            for (int i=0; i<tx.Frames.Count; i++)
            {
                var (ts, data) = tx.Frames[i];
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                if (ImGui.Selectable($"{i}##trfsel{i}", _selectedFrameIdx==i, ImGuiSelectableFlags.SpanAllColumns))
                    _selectedFrameIdx = _selectedFrameIdx==i ? -1 : i;
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled(ts.ToString("HH:mm:ss.fff"));
                ImGui.TableSetColumnIndex(2); ImGui.TextDisabled($"{data.Length}B");
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled(BitConverter.ToString(data,0,Math.Min(data.Length,20)).Replace("-"," ") + (data.Length>20?"…":""));
            }
            ImGui.EndTable();
        }
        // Detail
        if (_selectedFrameIdx>=0 && _selectedFrameIdx<tx.Frames.Count)
        {
            var (_,data) = tx.Frames[_selectedFrameIdx];
            ImGui.Separator();
            ImGui.TextWrapped(BitConverter.ToString(data).Replace("-"," "));
            ImGui.SameLine();
            if (ImGui.SmallButton("Replay##trfrep"))
                _pipe.ForgeStream(data);
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##trlsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##trlcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("tr_log_child", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
