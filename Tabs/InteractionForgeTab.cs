// Tabs/InteractionForgeTab.cs  v16
// Forges C2S interaction packets from captured entity IDs:
//   MountNPC (0x125), DismountNPC (0x126), CancelInteractionChain (0x123),
//   ClientOpenWindow (0xCC), SendWindowAction (0xCB), SetActiveSlot (0xB1),
//   DropItemStack (0xAE), MouseInteraction (0x6F)
//
// All packets are built using the Hytale wire format:
//   [4B LE frame_len][2B LE opcode][2B padding][...payload]
// and injected via FORGE_STREAM → msquic_inject → new unidirectional QUIC stream.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs;

public class InteractionForgeTab : ITab
{
    public string Name => "Interaction Forge";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly EntityTracker     _entities;
    private readonly InventoryTracker  _inventory;

    // ── Entity selection ────────────────────────────────────────────────────
    private string _entityFilter = "";
    private ulong  _targetEid    = 0;
    private string _targetEidHex = "";

    // ── NPC interact ────────────────────────────────────────────────────────
    private bool   _isMounted     = false;

    // ── Window / container ──────────────────────────────────────────────────
    private string _windowIdHex   = "00000001";
    private int    _windowAction  = 0;
    private int    _slotFrom      = 0;
    private int    _slotTo        = 0;
    private int    _stackCount    = 1;

    // ── Mouse interaction ────────────────────────────────────────────────────
    private int    _activeSlot    = 0;
    private int    _mouseButton   = 0;

    // ── Raw forge ────────────────────────────────────────────────────────────
    private string _rawOpcodeHex  = "00CB";
    private string _rawPayloadHex = "";
    private string _forgeStatus   = "";

    // ── Log ──────────────────────────────────────────────────────────────────
    private readonly List<string> _log = new();
    private bool _logScroll = true;

    public InteractionForgeTab(AppState state, PipeCaptureServer pipe)
    {
        _state     = state;
        _pipe      = pipe;
        _entities  = state.EntityTracker;
        _inventory = state.InventoryTracker;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        bool connected = _pipe.DllConnected;
        ImGui.TextColored(connected ? new Vector4(0.3f,1f,0.4f,1f) : new Vector4(1f,0.4f,0.3f,1f),
            connected ? "● DLL Connected" : "○ DLL Not Connected");
        ImGui.SameLine(0, 20);
        ImGui.TextDisabled("All interactions use FORGE_STREAM → new unidirectional QUIC stream.");
        ImGui.Separator();

        float leftW = avail.X * 0.55f;

        // ── Left column ──────────────────────────────────────────────────────
        ImGui.BeginChild("ifl", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("if_tabs"))
            {
                if (ImGui.BeginTabItem("NPC / Entity##npc"))  { RenderNPCPanel();      ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Window / Container##wnd")) { RenderWindowPanel(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Inventory Actions##invact")) { RenderInventoryPanel(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Raw Forge##raw"))     { RenderRawPanel();      ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right column: entity picker + log ─────────────────────────────────
        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("ifr", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("if_right_tabs"))
            {
                if (ImGui.BeginTabItem("Entity Picker##ep")) { RenderEntityPicker(avail.Y - 50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Forge Log##fl"))     { RenderLog(avail.Y - 50);          ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    // ── NPC panel ─────────────────────────────────────────────────────────────
    private void RenderNPCPanel()
    {
        ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), "NPC INTERACTION");
        ImGui.TextDisabled("Target entity ID (from Entity Picker or manual):");
        ImGui.SetNextItemWidth(-1);
        if (ImGui.InputText("Entity ID (hex)##teid", ref _targetEidHex, 32))
            ulong.TryParse(_targetEidHex.Replace("0x","").Replace("0X",""),
                System.Globalization.NumberStyles.HexNumber, null, out _targetEid);
        if (_targetEid != 0) ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  Target: 0x{_targetEid:X16}");
        else ImGui.TextDisabled("  No target selected");

        ImGui.Spacing();
        ImGui.TextDisabled("0x125 MountNPC — attempt to mount this entity as a mount.");
        if (ImGui.Button("Mount NPC##mn", new Vector2(-1, 0)))
        {
            Send(0x125, BuildEntityIdPayload(_targetEid));
            _isMounted = true;
            AddLog($"[MOUNT] MountNPC → 0x{_targetEid:X}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0x126 DismountNPC — dismount current mount.");
        if (ImGui.Button("Dismount##dm", new Vector2(-1, 0)))
        {
            Send(0x126, BuildEntityIdPayload(_targetEid));
            _isMounted = false;
            AddLog($"[DISMOUNT] DismountNPC → 0x{_targetEid:X}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0x123 CancelInteractionChain — interrupt ongoing interaction.");
        if (ImGui.Button("Cancel Interaction##ci", new Vector2(-1, 0)))
        {
            Send(0x123, Array.Empty<byte>());
            AddLog("[CANCEL] CancelInteractionChain sent");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0x6F MouseInteraction — fire a click at target entity.");
        if (ImGui.Button("Mouse Interact (left click)##mlc", new Vector2(-1, 0)))
        {
            Send(0x6F, BuildMouseInteraction(_targetEid, 0));
            AddLog($"[MOUSE] MouseInteraction → entity 0x{_targetEid:X}");
        }
        if (ImGui.Button("Mouse Interact (right click)##mrc", new Vector2(-1, 0)))
        {
            Send(0x6F, BuildMouseInteraction(_targetEid, 1));
            AddLog($"[MOUSE-R] MouseInteraction (right) → entity 0x{_targetEid:X}");
        }
    }

    // ── Window / container panel ───────────────────────────────────────────
    private void RenderWindowPanel()
    {
        ImGui.TextColored(new Vector4(1f, 0.65f, 0.2f, 1f), "WINDOW / CONTAINER");
        ImGui.TextDisabled("0xCC ClientOpenWindow — request open a container/window.");
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Window ID (hex)##wid", ref _windowIdHex, 16);
        if (ImGui.Button("Open Window##ow", new Vector2(-1, 0)))
        {
            if (uint.TryParse(_windowIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint wid))
            {
                Send(0xCC, BuildUInt32Payload(wid));
                AddLog($"[WINDOW] ClientOpenWindow ID=0x{wid:X}");
            }
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0xCB SendWindowAction — interact with an open window.");
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Action type##wa", ref _windowAction, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Slot##ws", ref _slotFrom, 1);
        if (ImGui.Button("Send Window Action##swa", new Vector2(-1, 0)))
        {
            Send(0xCB, BuildWindowAction(_windowAction, _slotFrom));
            AddLog($"[WACTION] SendWindowAction type={_windowAction} slot={_slotFrom}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("Force-open entity container (EntityID + window ID):");
        if (ImGui.Button("Open Entity Container##oec", new Vector2(-1, 0)))
        {
            if (uint.TryParse(_windowIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint wid))
            {
                byte[] p = BuildEntityWindowPayload(_targetEid, wid);
                Send(0xCC, p);
                AddLog($"[WINDOW] Open entity container eid=0x{_targetEid:X} wid=0x{wid:X}");
            }
        }
    }

    // ── Inventory actions panel ────────────────────────────────────────────
    private void RenderInventoryPanel()
    {
        ImGui.TextColored(new Vector4(1f, 0.85f, 0.3f, 1f), "INVENTORY ACTIONS");

        ImGui.TextDisabled("0xB1 SetActiveSlot — switch active hotbar slot.");
        ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Slot (0-8)##sas", ref _activeSlot, 0, 8);
        if (ImGui.Button("Set Active Slot##sas_btn", new Vector2(-1, 0)))
        {
            Send(0xB1, new[] { (byte)_activeSlot });
            AddLog($"[SLOT] SetActiveSlot → {_activeSlot}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0xAF MoveItemStack — move item between slots.");
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("From slot##mf", ref _slotFrom, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("To slot##mt", ref _slotTo, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Count##mc", ref _stackCount, 1);
        if (ImGui.Button("Move Item##mi_btn", new Vector2(-1, 0)))
        {
            Send(0xAF, BuildMoveItem(_slotFrom, _slotTo, _stackCount));
            AddLog($"[MOVE] MoveItemStack {_slotFrom}→{_slotTo} x{_stackCount}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("0xAE DropItemStack — drop item from slot.");
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Drop slot##ds", ref _slotFrom, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Drop count##dc2", ref _stackCount, 1);
        if (ImGui.Button("Drop Item##di_btn", new Vector2(-1, 0)))
        {
            Send(0xAE, BuildDropItem(_slotFrom, _stackCount));
            AddLog($"[DROP] DropItemStack slot={_slotFrom} count={_stackCount}");
        }

        ImGui.Spacing();
        ImGui.TextDisabled("Current inventory slots (from tracker):");
        var filledSlots = _inventory.Slots.Values.Where(s => !s.IsEmpty).OrderBy(s => s.SlotIndex).Take(20).ToList();
        if (filledSlots.Count == 0) ImGui.TextDisabled("  (no inventory data — needs 0xAA packet)");
        foreach (var s in filledSlots)
            ImGui.TextDisabled($"  [{s.SlotIndex,2}] {s.ItemName}  x{s.StackCount}");
    }

    // ── Raw forge panel ───────────────────────────────────────────────────
    private void RenderRawPanel()
    {
        ImGui.TextColored(new Vector4(0.7f, 0.5f, 1f, 1f), "RAW PACKET FORGE");
        ImGui.TextDisabled("Build a raw Hytale-framed packet and inject it.\nOpcode is LE 16-bit (e.g. 00CB).");
        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Opcode (hex)##ro", ref _rawOpcodeHex, 8);
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Payload (hex)##rp", ref _rawPayloadHex, 16384);
        ImGui.TextDisabled("Payload goes AFTER [4B frame_len][2B opcode][2B pad].");

        if (ImGui.Button("Forge & Inject##fai", new Vector2(-1, 32)))
        {
            try
            {
                ushort op = Convert.ToUInt16(_rawOpcodeHex, 16);
                byte[] payload = string.IsNullOrWhiteSpace(_rawPayloadHex)
                    ? Array.Empty<byte>()
                    : HexToBytes(_rawPayloadHex);
                Send(op, payload);
                _forgeStatus = $"Sent opcode=0x{op:X4}  {payload.Length}B payload";
                AddLog($"[RAW] 0x{op:X4}  {payload.Length}B  {_rawPayloadHex[..Math.Min(32, _rawPayloadHex.Length)]}");
            }
            catch (Exception ex) { _forgeStatus = $"Error: {ex.Message}"; }
        }
        if (!string.IsNullOrEmpty(_forgeStatus))
            ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), _forgeStatus);

        ImGui.Spacing(); ImGui.Separator();
        ImGui.TextDisabled("Quick templates:");
        if (ImGui.Button("Ping (0x05)##qp"))          { Send(0x05, Array.Empty<byte>()); AddLog("[RAW] Ping sent"); }
        ImGui.SameLine();
        if (ImGui.Button("ClientReady (0x69)##qcr"))   { Send(0x69, Array.Empty<byte>()); AddLog("[RAW] ClientReady sent"); }
        ImGui.SameLine();
        if (ImGui.Button("SEQRESET##qsr"))             { _pipe.SendCommand("SEQRESET"); AddLog("[RAW] SEQRESET sent"); }
    }

    // ── Entity picker ─────────────────────────────────────────────────────
    private void RenderEntityPicker(float h)
    {
        ImGui.TextDisabled("Click an entity to set as target for NPC/window actions.");
        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Filter##epf", ref _entityFilter, 64);
        ImGui.Separator();

        ImGui.BeginChild("if_eplist", new Vector2(-1, h - 80), ImGuiChildFlags.None);
        if (ImGui.BeginTable("if_etbl", 4,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Entity ID", ImGuiTableColumnFlags.WidthFixed, 130);
            ImGui.TableSetupColumn("Type",      ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Position",  ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("HP",        ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            var entities = _entities.Entities.Values
                .OrderByDescending(e => e.UpdateCount).ToList();

            if (!string.IsNullOrEmpty(_entityFilter))
            {
                var f = _entityFilter.ToLower();
                entities = entities.Where(e =>
                    e.EntityId.ToString("X").ToLower().Contains(f) ||
                    e.Label.ToLower().Contains(f)).ToList();
            }

            foreach (var e in entities)
            {
                ImGui.TableNextRow();
                bool isTgt = _targetEid == e.EntityId;
                Vector4 rowCol = isTgt ? new Vector4(1f,0.85f,0.2f,1f) : new Vector4(0.85f,0.85f,0.85f,1f);

                ImGui.TableSetColumnIndex(0);
                ImGui.PushStyleColor(ImGuiCol.Text, rowCol);
                if (ImGui.Selectable($"0x{e.EntityId:X}##ifsele{e.EntityId}",
                    isTgt, ImGuiSelectableFlags.SpanAllColumns, new Vector2(0,0)))
                {
                    _targetEid = isTgt ? 0 : e.EntityId;
                    _targetEidHex = _targetEid.ToString("X16");
                }
                ImGui.PopStyleColor();

                ImGui.TableSetColumnIndex(1);
                ImGui.TextDisabled(e.HasType ? $"0x{e.TypeId:X4}" : "-");

                ImGui.TableSetColumnIndex(2);
                ImGui.TextUnformatted(e.HasPosition ? e.PositionStr : "-");

                ImGui.TableSetColumnIndex(3);
                ImGui.TextUnformatted(e.HasHealth ? e.HealthStr : "-");
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();

        if (_targetEid != 0)
            ImGui.TextColored(new Vector4(1f,0.85f,0.2f,1f), $"Target: 0x{_targetEid:X16}");
    }

    // ── Log ──────────────────────────────────────────────────────────────────
    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##iflsc", ref _logScroll);
        ImGui.SameLine();
        if (ImGui.Button("Clear##iflcl")) lock (_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("if_log", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_log) snap = _log.ToList();
        foreach (var line in snap)
        {
            Vector4 col = line.Contains("[MOUNT]")    ? new Vector4(0.4f,0.9f,0.4f,1f)
                        : line.Contains("[WINDOW]")   ? new Vector4(1f,0.75f,0.2f,1f)
                        : line.Contains("[MOVE]")     ? new Vector4(0.5f,0.85f,1f,1f)
                        : line.Contains("[RAW]")      ? new Vector4(0.75f,0.5f,1f,1f)
                        : line.Contains("[ERR]")      ? new Vector4(1f,0.3f,0.3f,1f)
                        :                               new Vector4(0.8f,0.8f,0.8f,1f);
            ImGui.TextColored(col, line);
        }
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    // ── Packet builders ───────────────────────────────────────────────────
    private void Send(ushort opcode, byte[] payload)
    {
        // Frame: [4B LE frame_len = payload.Length + 4][2B LE opcode][2B pad][payload]
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)(payload.Length + 4)); // frame_len includes opcode+pad
        bw.Write(opcode);
        bw.Write((ushort)0);                  // padding
        bw.Write(payload);
        _pipe.ForgeStream(ms.ToArray());
    }

    private static byte[] BuildEntityIdPayload(ulong eid)
    {
        var b = new byte[8];
        BitConverter.GetBytes(eid).CopyTo(b, 0);
        return b;
    }

    private static byte[] BuildUInt32Payload(uint val)
    {
        var b = new byte[4];
        BitConverter.GetBytes(val).CopyTo(b, 0);
        return b;
    }

    private static byte[] BuildEntityWindowPayload(ulong eid, uint windowId)
    {
        var b = new byte[12];
        BitConverter.GetBytes(eid).CopyTo(b, 0);
        BitConverter.GetBytes(windowId).CopyTo(b, 8);
        return b;
    }

    private static byte[] BuildWindowAction(int actionType, int slot)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)actionType);
        bw.Write((uint)slot);
        return ms.ToArray();
    }

    private static byte[] BuildMoveItem(int from, int to, int count)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)from);
        bw.Write((uint)to);
        bw.Write((uint)count);
        return ms.ToArray();
    }

    private static byte[] BuildDropItem(int slot, int count)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)slot);
        bw.Write((uint)count);
        return ms.ToArray();
    }

    private static byte[] BuildMouseInteraction(ulong eid, int button)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)Environment.TickCount); // timestamp
        bw.Write(eid);
        bw.Write((uint)button);
        return ms.ToArray();
    }

    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("-", "");
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_log) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
    }
}
