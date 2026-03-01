// FILE: Protocol/OpcodeRegistry.cs (ENHANCED VERSION)
using HyForce.Networking;
using HyForce.Data;
using System.Collections.Generic;

namespace HyForce.Protocol;

public static class OpcodeRegistry
{
    // ADDED: Missing constant
    public const ushort RegistryOpcode = 0x18;

    // C2S Packets (Client-to-Server) - Player Input
    public static readonly Dictionary<ushort, PacketInfo> C2S_Opcodes = new()
    {
        // Core Client Setup (100-119)
        [0x64] = new PacketInfo("SetClientId", "Client identifies itself", PacketCategory.ClientSetup),
        [0x65] = new PacketInfo("SetGameMode", "Change game mode", PacketCategory.ClientSetup),
        [0x66] = new PacketInfo("SetMovementStates", "Movement state flags", PacketCategory.Movement),
        [0x67] = new PacketInfo("SetBlockPlacementOverride", "Block placement override", PacketCategory.Blocks),
        [0x68] = new PacketInfo("JoinWorld", "Request to join world", PacketCategory.World),
        [0x69] = new PacketInfo("ClientReady", "Client ready for gameplay", PacketCategory.ClientSetup),
        [0x6A] = new PacketInfo("LoadHotbar", "Load hotbar row", PacketCategory.Inventory),
        [0x6B] = new PacketInfo("SaveHotbar", "Save hotbar row", PacketCategory.Inventory),
        [0x6C] = new PacketInfo("ClientMovement", "PLAYER MOVEMENT - Position/Rotation/Velocity", PacketCategory.Movement, true),
        [0x6D] = new PacketInfo("ClientTeleport", "Teleport acknowledgment", PacketCategory.Movement),
        [0x6E] = new PacketInfo("UpdateMovementSettings", "Update movement settings", PacketCategory.Movement),
        [0x6F] = new PacketInfo("MouseInteraction", "MOUSE INPUT - Clicks/Interaction", PacketCategory.Input, true),
        [0x70] = new PacketInfo("DamageInfo", "Report damage taken", PacketCategory.Combat),
        [0x71] = new PacketInfo("ReticleEvent", "Reticle/crosshair event", PacketCategory.Input),
        [0x72] = new PacketInfo("DisplayDebug", "Display debug shape", PacketCategory.Debug),
        [0x73] = new PacketInfo("ClearDebugShapes", "Clear debug shapes", PacketCategory.Debug),
        [0x74] = new PacketInfo("SyncPlayerPreferences", "Sync player preferences", PacketCategory.Player),
        [0x75] = new PacketInfo("ClientPlaceBlock", "Place block request", PacketCategory.Blocks),
        [0x76] = new PacketInfo("UpdateMemoriesFeatureStatus", "Update memories feature", PacketCategory.Player),
        [0x77] = new PacketInfo("RemoveMapMarker", "Remove map marker", PacketCategory.WorldMap),

        // Extended C2S (18, 29-30, 131-136, 158, 216, 252, 261, 280, 283, 290)
        [0x12] = new PacketInfo("ClientReferral", "Server transfer referral", PacketCategory.Network),
        [0x1D] = new PacketInfo("SetUpdateRate", "Set client update rate", PacketCategory.Network),
        [0x1E] = new PacketInfo("SetTimeDilation", "Set time dilation", PacketCategory.World),
        [0x83] = new PacketInfo("SetChunk", "Client chunk update", PacketCategory.World),
        [0x84] = new PacketInfo("SetChunkHeightmap", "Chunk heightmap", PacketCategory.World),
        [0x85] = new PacketInfo("SetChunkTintmap", "Chunk tintmap", PacketCategory.World),
        [0x86] = new PacketInfo("SetChunkEnvironments", "Chunk environments", PacketCategory.World),
        [0x88] = new PacketInfo("SetFluids", "Set fluids", PacketCategory.World),
        [0x9E] = new PacketInfo("SetPaused", "Set paused state", PacketCategory.World),
        [0xD8] = new PacketInfo("SetPage", "Set UI page", PacketCategory.Interface),
        [0xFC] = new PacketInfo("SetServerAccess", "Set server access/password", PacketCategory.Network),
        [0x105] = new PacketInfo("SetMachinimaActorModel", "Set machinima actor", PacketCategory.Machinima),
        [0x118] = new PacketInfo("SetServerCamera", "Set server camera", PacketCategory.Camera),
        [0x11B] = new PacketInfo("SetFlyCameraMode", "Set fly camera mode", PacketCategory.Camera),
        [0x122] = new PacketInfo("SyncInteractionChains", "Sync interaction chains", PacketCategory.Interaction),

        // Inventory/Window C2S (172, 174-178, 203-204)
        [0xAC] = new PacketInfo("DropCreativeItem", "Drop creative item", PacketCategory.Inventory),
        [0xAE] = new PacketInfo("DropItemStack", "Drop item stack", PacketCategory.Inventory),
        [0xAF] = new PacketInfo("MoveItemStack", "Move item between slots", PacketCategory.Inventory, true),
        [0xB0] = new PacketInfo("SmartMoveItemStack", "Smart item move", PacketCategory.Inventory),
        [0xB1] = new PacketInfo("SetActiveSlot", "Set active hotbar slot", PacketCategory.Inventory, true),
        [0xB2] = new PacketInfo("SwitchHotbarBlockSet", "Switch hotbar block set", PacketCategory.Inventory),
        [0xCB] = new PacketInfo("SendWindowAction", "Window interaction", PacketCategory.Interface),
        [0xCC] = new PacketInfo("ClientOpenWindow", "Request open window", PacketCategory.Interface),

        // Interaction C2S (291, 293-294)
        [0x123] = new PacketInfo("CancelInteractionChain", "Cancel interaction", PacketCategory.Interaction),
        [0x125] = new PacketInfo("MountNPC", "Mount NPC request", PacketCategory.Interaction),
        [0x126] = new PacketInfo("DismountNPC", "Dismount NPC", PacketCategory.Interaction),

        // Builder Tools C2S (400-425)
        [0x190] = new PacketInfo("BuilderToolArgUpdate", "Builder tool arg update", PacketCategory.BuilderTools),
        [0x191] = new PacketInfo("BuilderToolEntityAction", "Builder tool entity action", PacketCategory.BuilderTools),
        [0x192] = new PacketInfo("BuilderToolSetEntityTransform", "Set entity transform", PacketCategory.BuilderTools),
        [0x193] = new PacketInfo("BuilderToolExtrudeAction", "Extrude action", PacketCategory.BuilderTools),
        [0x194] = new PacketInfo("BuilderToolStackArea", "Stack/duplicate area", PacketCategory.BuilderTools),
        [0x195] = new PacketInfo("BuilderToolSelectionTransform", "Transform selection", PacketCategory.BuilderTools),
        [0x196] = new PacketInfo("BuilderToolRotateClipboard", "Rotate clipboard", PacketCategory.BuilderTools),
        [0x197] = new PacketInfo("BuilderToolPasteClipboard", "Paste clipboard", PacketCategory.BuilderTools),
        [0x198] = new PacketInfo("BuilderToolSetTransformationModeState", "Set transform mode", PacketCategory.BuilderTools),
        [0x199] = new PacketInfo("BuilderToolSelectionUpdate", "Update selection", PacketCategory.BuilderTools),
        [0x19A] = new PacketInfo("BuilderToolSelectionToolAskForClipboard", "Request clipboard", PacketCategory.BuilderTools),
        [0x19B] = new PacketInfo("BuilderToolSelectionToolReplyWithClipboard", "Clipboard reply", PacketCategory.BuilderTools),
        [0x19C] = new PacketInfo("BuilderToolGeneralAction", "General builder action", PacketCategory.BuilderTools),
        [0x19D] = new PacketInfo("BuilderToolOnUseInteraction", "On-use interaction", PacketCategory.BuilderTools),
        [0x19E] = new PacketInfo("BuilderToolLineAction", "Line creation", PacketCategory.BuilderTools),
        [0x1A0] = new PacketInfo("BuilderToolSetEntityScale", "Set entity scale", PacketCategory.BuilderTools),
        [0x1A1] = new PacketInfo("BuilderToolSetEntityPickupEnabled", "Set pickup enabled", PacketCategory.BuilderTools),
        [0x1A2] = new PacketInfo("BuilderToolSetEntityLight", "Set entity light", PacketCategory.BuilderTools),
        [0x1A3] = new PacketInfo("BuilderToolSetNPCDebug", "Set NPC debug", PacketCategory.BuilderTools),
        [0x1A5] = new PacketInfo("BuilderToolSetEntityCollision", "Set entity collision", PacketCategory.BuilderTools),
    };

    // S2C Packets (Server-to-Client) - Game State
    public static readonly Dictionary<ushort, PacketInfo> S2C_Opcodes = new()
    {
        // Connection/Auth (0-15)
        [0x00] = new PacketInfo("Connect", "Connection request", PacketCategory.Connection),
        [0x01] = new PacketInfo("Disconnect", "Disconnect", PacketCategory.Connection),
        [0x02] = new PacketInfo("AuthToken", "Authentication token", PacketCategory.Authentication),
        [0x03] = new PacketInfo("ConnectAccept", "Connection accepted", PacketCategory.Authentication),
        [0x04] = new PacketInfo("ConnectReject", "Connection rejected", PacketCategory.Authentication),
        [0x05] = new PacketInfo("Ping", "Ping", PacketCategory.Connection),
        [0x06] = new PacketInfo("Pong", "Pong", PacketCategory.Connection),
        [0x07] = new PacketInfo("Kick", "Kick player", PacketCategory.Connection),

        // Setup (16-39)
        [0x10] = new PacketInfo("WorldSettings", "World settings", PacketCategory.Setup),
        [0x11] = new PacketInfo("AssetInitialize", "Asset initialization", PacketCategory.Setup),
        [0x12] = new PacketInfo("PlayerSetup", "Player setup data", PacketCategory.Setup),

        // Assets/Registry (40-66) - CRITICAL FOR REGISTRY SYNC
        [0x28] = new PacketInfo("UpdateBlockTypes", "BLOCK DEFINITIONS (Compressed)", PacketCategory.Assets, true),
        [0x29] = new PacketInfo("UpdateBlockHitboxes", "Block hitboxes", PacketCategory.Assets),
        [0x2A] = new PacketInfo("UpdateBlockSoundSets", "Block sound sets", PacketCategory.Assets),
        [0x2B] = new PacketInfo("UpdateItemSoundSets", "Item sound sets", PacketCategory.Assets),
        [0x2C] = new PacketInfo("UpdateBlockParticleSets", "Block particle sets", PacketCategory.Assets),
        [0x2D] = new PacketInfo("UpdateBlockBreakingDecals", "Block breaking decals", PacketCategory.Assets),
        [0x2E] = new PacketInfo("UpdateBlockSets", "BLOCK SETS (Compressed)", PacketCategory.Assets, true),
        [0x2F] = new PacketInfo("UpdateWeathers", "Weather configs", PacketCategory.Assets),
        [0x30] = new PacketInfo("UpdateTrails", "Particle trails", PacketCategory.Assets),
        [0x31] = new PacketInfo("UpdateParticleSystems", "PARTICLE SYSTEMS (Compressed)", PacketCategory.Assets, true),
        [0x32] = new PacketInfo("UpdateParticleSpawners", "Particle spawners", PacketCategory.Assets),
        [0x33] = new PacketInfo("UpdateEntityEffects", "Entity effect definitions", PacketCategory.Assets),
        [0x34] = new PacketInfo("UpdateItemPlayerAnimations", "Item player animations", PacketCategory.Assets),
        [0x35] = new PacketInfo("UpdateModelvfxs", "Model VFX", PacketCategory.Assets),
        [0x36] = new PacketInfo("UpdateItems", "ITEM DEFINITIONS (Compressed)", PacketCategory.Assets, true),
        [0x37] = new PacketInfo("UpdateItemQualities", "Item quality definitions", PacketCategory.Assets),
        [0x38] = new PacketInfo("UpdateItemCategories", "Item categories", PacketCategory.Assets),
        [0x39] = new PacketInfo("UpdateItemReticles", "Aiming reticles", PacketCategory.Assets),
        [0x3A] = new PacketInfo("UpdateFieldcraftCategories", "Fieldcraft categories", PacketCategory.Assets),
        [0x3B] = new PacketInfo("UpdateResourceTypes", "Resource types", PacketCategory.Assets),
        [0x3C] = new PacketInfo("UpdateRecipes", "CRAFTING RECIPES (Compressed)", PacketCategory.Assets, true),
        [0x3D] = new PacketInfo("UpdateEnvironments", "Environment definitions", PacketCategory.Assets),
        [0x3E] = new PacketInfo("UpdateAmbienceFX", "Ambient effects", PacketCategory.Assets),
        [0x3F] = new PacketInfo("UpdateFluidFX", "Fluid visual effects", PacketCategory.Assets),
        [0x40] = new PacketInfo("UpdateTranslations", "LOCALIZATION (Compressed)", PacketCategory.Assets, true),
        [0x41] = new PacketInfo("UpdateSoundEvents", "Sound event definitions", PacketCategory.Assets),
        [0x42] = new PacketInfo("UpdateInteractions", "Interaction definitions", PacketCategory.Assets),

        // World Data (131-158) - CHUNK DATA
        [0x83] = new PacketInfo("SetChunk", "CHUNK DATA - Blocks/Fluids", PacketCategory.World, true),
        [0x84] = new PacketInfo("SetChunkHeightmap", "Chunk heightmap", PacketCategory.World),
        [0x85] = new PacketInfo("SetChunkTintmap", "Chunk color tinting", PacketCategory.World),
        [0x86] = new PacketInfo("SetChunkEnvironments", "Chunk environments", PacketCategory.World),
        [0x87] = new PacketInfo("UnloadChunk", "Unload chunk", PacketCategory.World),
        [0x88] = new PacketInfo("SetFluids", "Fluid data update", PacketCategory.World),
        [0x8C] = new PacketInfo("ServerSetBlock", "Single block change", PacketCategory.World),
        [0x8D] = new PacketInfo("ServerSetBlocks", "Batch block updates", PacketCategory.World),
        [0x8E] = new PacketInfo("ServerSetFluid", "Single fluid change", PacketCategory.World),
        [0x8F] = new PacketInfo("ServerSetFluids", "Batch fluid updates", PacketCategory.World),
        [0x90] = new PacketInfo("UpdateBlockDamage", "Block damage progress", PacketCategory.World),
        [0x91] = new PacketInfo("UpdateTimeSettings", "World time settings", PacketCategory.World),
        [0x92] = new PacketInfo("UpdateTime", "Current world time", PacketCategory.World),
        [0x93] = new PacketInfo("UpdateEditorTimeOverride", "Editor time override", PacketCategory.World),
        [0x94] = new PacketInfo("ClearEditorTimeOverride", "Clear time override", PacketCategory.World),
        [0x95] = new PacketInfo("UpdateWeather", "Weather update", PacketCategory.World),
        [0x96] = new PacketInfo("UpdateEditorWeatherOverride", "Editor weather override", PacketCategory.World),
        [0x97] = new PacketInfo("UpdateEnvironmentMusic", "Background music", PacketCategory.World),
        [0x98] = new PacketInfo("SpawnParticleSystem", "Spawn particles", PacketCategory.World),
        [0x99] = new PacketInfo("SpawnBlockParticleSystem", "Block particles", PacketCategory.World),
        [0x9A] = new PacketInfo("PlaySoundEvent2D", "2D ambient sound", PacketCategory.World),
        [0x9B] = new PacketInfo("PlaySoundEvent3D", "3D positional sound", PacketCategory.World),
        [0x9C] = new PacketInfo("PlaySoundEventEntity", "Entity-attached sound", PacketCategory.World),
        [0x9D] = new PacketInfo("UpdateSleepState", "Player sleep state", PacketCategory.World),
        [0x9E] = new PacketInfo("SetPaused", "Client pause state", PacketCategory.World),
        [0x9F] = new PacketInfo("ServerSetPaused", "Server pause state", PacketCategory.World),

        // Entity Updates (160-166) - CRITICAL
        [0xA0] = new PacketInfo("SetEntitySeed", "Entity random seed", PacketCategory.Entities),
        [0xA1] = new PacketInfo("EntityUpdates", "BATCH ENTITY UPDATES", PacketCategory.Entities, true),
        [0xA2] = new PacketInfo("PlayAnimation", "Entity animation", PacketCategory.Entities),
        [0xA3] = new PacketInfo("ChangeVelocity", "Entity velocity change", PacketCategory.Entities),
        [0xA4] = new PacketInfo("ApplyKnockback", "Knockback force", PacketCategory.Entities),
        [0xA5] = new PacketInfo("SpawnModelParticles", "Model particle effects", PacketCategory.Entities),
        [0xA6] = new PacketInfo("MountMovement", "Mount movement updates", PacketCategory.Entities),

        // Inventory (170-179)
        [0xAA] = new PacketInfo("UpdatePlayerInventory", "FULL INVENTORY (Compressed)", PacketCategory.Inventory, true),
        [0xAB] = new PacketInfo("SetCreativeItem", "Creative inventory item", PacketCategory.Inventory),
        [0xAD] = new PacketInfo("SmartGiveCreativeItem", "Smart item give", PacketCategory.Inventory),

        // Window/UI (200-204)
        [0xC8] = new PacketInfo("OpenWindow", "Open GUI window", PacketCategory.Interface),
        [0xC9] = new PacketInfo("UpdateWindow", "Window content update (Compressed)", PacketCategory.Interface, true),
        [0xCA] = new PacketInfo("CloseWindow", "Close window", PacketCategory.Interface),

        // Interface (210-215, 240-251)
        [0xD2] = new PacketInfo("ChatMessage", "Chat message", PacketCategory.Interface),
        [0xD3] = new PacketInfo("Notification", "Notification popup", PacketCategory.Interface),
        [0xD4] = new PacketInfo("PlaySound", "Play sound effect", PacketCategory.Interface),
        [0xF0] = new PacketInfo("SetActiveHotbarSlot", "Set active hotbar slot", PacketCategory.Interface),
        [0xF1] = new PacketInfo("UpdateHealth", "Update player health", PacketCategory.Interface),
        [0xF2] = new PacketInfo("UpdateMana", "Update player mana", PacketCategory.Interface),
        [0xF3] = new PacketInfo("UpdateStamina", "Update player stamina", PacketCategory.Interface),
        [0xF4] = new PacketInfo("UpdateExperience", "Update experience", PacketCategory.Interface),
        [0xF5] = new PacketInfo("UpdateLevel", "Update player level", PacketCategory.Interface),

        // Interaction (290-294)
        [0x122] = new PacketInfo("SyncInteractionChains", "Sync interaction chains", PacketCategory.Interaction),
        [0x124] = new PacketInfo("PlayInteractionFor", "Play interaction", PacketCategory.Interaction),

        // Camera (280-283)
        [0x118] = new PacketInfo("SetServerCamera", "Set server camera", PacketCategory.Camera),
        [0x11B] = new PacketInfo("SetFlyCameraMode", "Set fly camera mode", PacketCategory.Camera),
        [0x119] = new PacketInfo("CameraShakeEffect", "Camera shake effect", PacketCategory.Camera),

        // Builder Tools S2C (415-419)
        [0x19F] = new PacketInfo("BuilderToolShowAnchor", "Show anchor", PacketCategory.BuilderTools),
        [0x1A0] = new PacketInfo("BuilderToolHideAnchors", "Hide anchors", PacketCategory.BuilderTools),
        [0x1A3] = new PacketInfo("BuilderToolLaserPointer", "Laser pointer", PacketCategory.BuilderTools),
    };

    public static string Label(ushort opcode, PacketDirection direction)
    {
        var dict = direction == PacketDirection.ClientToServer ? C2S_Opcodes : S2C_Opcodes;
        if (dict.TryGetValue(opcode, out var info))
            return info.Name;

        // Check if it's in the extended range
        if (opcode >= 0x60B4 && opcode <= 0x7FB4)
        {
            // These appear to be custom/modified opcodes
            return $"MOD_{opcode:X4}";
        }

        return $"{(direction == PacketDirection.ClientToServer ? "C2S" : "S2C")}_0x{opcode:X4}";
    }

    public static PacketInfo? GetInfo(ushort opcode, PacketDirection direction)
    {
        var dict = direction == PacketDirection.ClientToServer ? C2S_Opcodes : S2C_Opcodes;
        return dict.TryGetValue(opcode, out var info) ? info : null;
    }

    public static bool IsKnownOpcode(ushort opcode, PacketDirection direction)
    {
        var dict = direction == PacketDirection.ClientToServer ? C2S_Opcodes : S2C_Opcodes;
        return dict.ContainsKey(opcode);
    }
}

public record PacketInfo(string Name, string Description, PacketCategory Category, bool IsCritical = false);