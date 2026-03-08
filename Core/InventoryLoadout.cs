using System;
using System.Collections.Generic;
using System.Text;

namespace HyForce.Core;

public class InventoryLoadout
{
    public string Name { get; set; } = "";
    public System.Collections.Generic.List<(int Slot, uint TypeId, int Count)> Slots { get; set; } = new();
}