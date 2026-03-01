using HyForce.App;
using Veldrid;
using Veldrid.Sdl2;
using Veldrid.StartupUtilities;

namespace HyForce;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════════════════╗");
        Console.WriteLine("║           HYFORCE V22-ENHANCED               ║");
        Console.WriteLine("║      Hytale Security Analyzer Tool           ║");
        Console.WriteLine("╚══════════════════════════════════════════════╝");
        Console.WriteLine();

        WindowCreateInfo windowCI = new WindowCreateInfo
        {
            X = 100,
            Y = 100,
            WindowWidth = 1600,
            WindowHeight = 900,
            WindowTitle = "HyForce V22-Enhanced - Hytale Security Analyzer"
        };

        Sdl2Window window = VeldridStartup.CreateWindow(ref windowCI);

        // Fixed: Use parameterless constructor and set properties
        GraphicsDeviceOptions options = new GraphicsDeviceOptions();
        options.SyncToVerticalBlank = true;
        options.ResourceBindingModel = ResourceBindingModel.Improved;

        GraphicsDevice graphicsDevice = VeldridStartup.CreateGraphicsDevice(window, options, GraphicsBackend.Direct3D11);

        var app = new HyForceApp(window, graphicsDevice);
        app.Run();

        graphicsDevice.Dispose();
        window.Close();
    }
}