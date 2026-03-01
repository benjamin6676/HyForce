namespace HyForce.Tabs;

public interface ITab
{
    string Name { get; }
    void Render();
}