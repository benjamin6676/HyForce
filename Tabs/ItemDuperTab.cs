// Tabs/ItemDuperTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading;

namespace HyForce.Tabs;

public class ItemDuperTab : ITab
{
    public string Name => "Item Duper";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly ItemDuplicator    _duper;

    // Slot dupe
    private int  _dupeSrc=0, _dupeDst=9, _dupeCount=64, _dupeRepeat=8;

    // Drop dupe
    private int  _dropSlot=0; private string _dropTypeHex="00000001"; private int _dropCount=64, _dropRepeat=4;

    // Window steal
    private int  _wid=0, _wCSlot=0, _wPSlot=0, _wRepeat=1, _wDelay=50;

    // Window drain
    private int  _drainWid=0, _drainSlots=27, _drainPStart=0, _drainDelay=30;

    // Item spam
    private string _spamTypeHex="00000001"; private string _spamTypeName="";
    private int  _spamSlot=0, _spamCount=64, _spamDelay=250;
    private string _spamSearch = "";

    private bool _logScroll = true;
    private readonly List<string> _log = new();
    private CancellationTokenSource? _cts;

    public ItemDuperTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _duper = state.ItemDuplicator;
        _duper.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 350f;

        ImGui.TextColored(new Vector4(1f,0.65f,0.2f,1f),
            $"Total forged: {_duper.TotalSent}  Spam: {(_duper.IsSpamming ? "● ON" : "■ OFF")}");
        ImGui.Separator();

        ImGui.BeginChild("id_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            if (ImGui.BeginTabBar("id_left_tabs"))
            {
                if (ImGui.BeginTabItem("Slot Dupe##ids"))    { RenderSlotDupe();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Drop Dupe##idd"))    { RenderDropDupe();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Window Steal##idw")) { RenderWindowSteal(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Item Spam##idsp"))   { RenderItemSpam();    ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("id_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("id_right_tabs"))
            {
                if (ImGui.BeginTabItem("History##idh"))  { RenderHistory(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Registry##idr")) { RenderRegistry(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##idl"))      { RenderLog(avail.Y-50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderSlotDupe()
    {
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "SLOT DUPE");
        ImGui.TextDisabled("Rapid-fires 0xAF MoveItemStack(src→dst).\nServer may apply before checking — gives extra copies.");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Src Slot##idss",ref _dupeSrc,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Dst Slot##idds",ref _dupeDst,1);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##idsc",ref _dupeCount,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Repeat##idsr",ref _dupeRepeat,1);
        _dupeSrc=Math.Max(0,_dupeSrc); _dupeDst=Math.Max(0,_dupeDst);
        _dupeCount=Math.Max(1,_dupeCount); _dupeRepeat=Math.Clamp(_dupeRepeat,1,64);
        ImGui.Spacing();
        ImGui.TextDisabled($"Will send {_dupeRepeat} × MoveItemStack({_dupeSrc}→{_dupeDst}, ×{_dupeCount})");
        if (ImGui.Button("Execute Slot Dupe##idexsd", new Vector2(-1,28)))
            _duper.SlotDupe((uint)_dupeSrc,(uint)_dupeDst,(uint)_dupeCount,(uint)_dupeRepeat);

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "QUICK DUPES");
        ImGui.TextDisabled("Single click — common scenarios");
        if (ImGui.Button("Stack × 8 (slot 0→9)##idqs1"))  _duper.SlotDupe(0,9,64,8);    ImGui.SameLine();
        if (ImGui.Button("Stack × 16##idqs2"))             _duper.SlotDupe(0,9,64,16);   ImGui.SameLine();
        if (ImGui.Button("Stack × 32##idqs3"))             _duper.SlotDupe(0,9,64,32);
    }

    private void RenderDropDupe()
    {
        ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "DROP DUPE");
        ImGui.TextDisabled("DropItemStack then immediate SetCreativeItem on same slot.\nIf server processes drop before creative-give, item doubles.");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Slot##iddd_sl",ref _dropSlot,1);
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Item TypeID##iddd_tid", ref _dropTypeHex,16);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##iddd_c",ref _dropCount,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Repeat##iddd_r",ref _dropRepeat,1);
        _dropSlot=Math.Max(0,_dropSlot); _dropCount=Math.Max(1,_dropCount); _dropRepeat=Math.Clamp(_dropRepeat,1,32);
        ImGui.Spacing();
        if (ImGui.Button("Execute Drop Dupe##idexdd", new Vector2(-1,28)))
        {
            if (uint.TryParse(_dropTypeHex,System.Globalization.NumberStyles.HexNumber,null,out uint tid))
            {
                _cts = new CancellationTokenSource();
                _ = _duper.DropDupe((uint)_dropSlot, tid, (uint)_dropCount, (uint)_dropRepeat, _pipe);
            }
        }
    }

    private void RenderWindowSteal()
    {
        ImGui.TextColored(new Vector4(0.7f,0.4f,1f,1f), "WINDOW STEAL");
        ImGui.TextDisabled("Forges 0xCB SendWindowAction to take items from any\nopen container without matching the real trade flow.");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Window ID##idws_wid",ref _wid,1);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Container Slot##idws_cs",ref _wCSlot,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Player Slot##idws_ps",ref _wPSlot,1);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Repeat##idws_r",ref _wRepeat,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Delay ms##idws_d",ref _wDelay,10);
        _wRepeat=Math.Max(1,_wRepeat); _wDelay=Math.Max(0,_wDelay);
        ImGui.Spacing();
        if (ImGui.Button("Steal Slot##idexws", new Vector2(-1,0)))
            _duper.WindowSteal(new WindowStealConfig {
                WindowId=(uint)_wid, ContainerSlot=(uint)_wCSlot,
                PlayerSlot=(uint)_wPSlot, RepeatCount=_wRepeat, DelayMs=_wDelay });

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "WINDOW DRAIN");
        ImGui.TextDisabled("Steal ALL slots from a container window in one go.");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Window ID##idwd_wid",ref _drainWid,1);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("# Slots##idwd_sl",ref _drainSlots,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Delay ms##idwd_d",ref _drainDelay,5);
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Player start##idwd_ps",ref _drainPStart,1);
        _drainSlots=Math.Clamp(_drainSlots,1,54); _drainDelay=Math.Max(0,_drainDelay);
        if (ImGui.Button("Drain Window##idexdw", new Vector2(-1,28)))
            _duper.DrainWindow((uint)_drainWid,(uint)_drainSlots,(uint)_drainPStart,_drainDelay);
    }

    private void RenderItemSpam()
    {
        ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "ITEM SPAM");
        ImGui.TextDisabled("Background thread continuously injects 0xAB SetCreativeItem.\nUseful for item keep-alive or quantity grinding.");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1); ImGui.InputText("TypeID##idsp_tid",ref _spamTypeHex,16);
        if (!string.IsNullOrEmpty(_spamTypeName)) ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  {_spamTypeName}");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Slot##idsp_sl",ref _spamSlot,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##idsp_c",ref _spamCount,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Delay ms##idsp_d",ref _spamDelay,50);
        _spamSlot=Math.Max(0,_spamSlot); _spamCount=Math.Max(1,_spamCount); _spamDelay=Math.Max(0,_spamDelay);
        ImGui.Spacing();
        if (!_duper.IsSpamming)
        {
            if (ImGui.Button("Start Item Spam##idexsp", new Vector2(-1,28)))
            {
                if (uint.TryParse(_spamTypeHex,System.Globalization.NumberStyles.HexNumber,null,out uint tid))
                    _duper.StartItemSpam(tid,(uint)_spamSlot,(uint)_spamCount,(uint)_spamDelay);
            }
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button,new Vector4(0.5f,0.1f,0.1f,1f));
            if (ImGui.Button("Stop Item Spam##idsxsp", new Vector2(-1,28))) _duper.StopItemSpam();
            ImGui.PopStyleColor();
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "BATCH GIVE ALL");
        ImGui.TextDisabled("Give every item type from the registry sequentially.");
        if (ImGui.Button("Give All Items##idbatch", new Vector2(-1,28)))
        {
            var items = _state.InventoryTracker.Registry.Values.Select(d=>(d.TypeId,d.Name));
            _cts = new CancellationTokenSource();
            _ = _duper.BatchGiveAll(items, _pipe, 0, 80, _cts.Token);
        }
        if (ImGui.SmallButton("Stop Batch##idbstop")) _cts?.Cancel();
    }

    private void RenderHistory(float h)
    {
        ImGui.TextDisabled($"{_duper.History.Count} jobs");
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##idHcl")) _duper.Clear();
        ImGui.SameLine();
        if (ImGui.SmallButton("Export JSON##idHex"))
            AddLog(_duper.ExportJson());
        ImGui.Separator();
        ImGui.BeginChild("id_hist", new Vector2(-1, h-70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("idHtbl", 4, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Label",     ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Sent",      ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("Result",    ImGuiTableColumnFlags.WidthFixed, 120);
            ImGui.TableSetupColumn("Time",      ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var j in _duper.History.AsEnumerable().Reverse().Take(200))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextUnformatted(j.Label);
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled($"{j.Sent}");
                ImGui.TableSetColumnIndex(2); ImGui.TextDisabled(j.Result);
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled(j.StartedAt.ToString("HH:mm:ss"));
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderRegistry(float h)
    {
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Search##idreg_sq",ref _spamSearch,64);
        ImGui.Separator();
        var defs = _state.InventoryTracker.Registry.Values
            .Where(d => string.IsNullOrEmpty(_spamSearch)
                || d.Name.ToLower().Contains(_spamSearch.ToLower())
                || d.TypeId.ToString("X").ToLower().Contains(_spamSearch.ToLower()))
            .OrderBy(d=>d.TypeId).ToList();
        ImGui.BeginChild("id_reg", new Vector2(-1, h-70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("idRegtbl", 3, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("TypeID", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Use",    ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var d in defs.Take(2000))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{d.TypeId:X6}");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(d.Name);
                ImGui.TableSetColumnIndex(2);
                if (ImGui.SmallButton($"Spam##idrsp{d.TypeId}"))
                { _spamTypeHex=d.TypeId.ToString("X"); _spamTypeName=d.Name; }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##idlsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##idlcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("id_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var l in snap) ImGui.TextUnformatted(l);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
