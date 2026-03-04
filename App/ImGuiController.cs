using System.Numerics;
using System.Runtime.InteropServices;
using Veldrid;
using ImGuiNET;

namespace HyForce.App;

public class ImGuiController : IDisposable
{
    private GraphicsDevice _gd;
    private bool _frameBegun;
    private int _windowWidth;
    private int _windowHeight;

    private DeviceBuffer _vertexBuffer = null!;
    private DeviceBuffer _indexBuffer = null!;
    private DeviceBuffer _projMatrixBuffer = null!;
    private Shader _vertexShader = null!;
    private Shader _fragmentShader = null!;
    private Pipeline _pipeline = null!;
    private Texture _fontTexture = null!;
    private TextureView _fontTextureView = null!;
    private ResourceSet _mainResourceSet = null!;
    private ResourceLayout _mainResourceLayout = null!;

    // Static clipboard buffer for callbacks
    private static string _clipboardBuffer = "";
    private static IntPtr _clipboardPtr = IntPtr.Zero;
    private static readonly object _clipboardLock = new();

    // Use standard delegate types that match ImGui's expected signatures
    private delegate void SetClipboardTextDelegate(IntPtr userData, IntPtr text);
    private delegate IntPtr GetClipboardTextDelegate(IntPtr userData);

    private SetClipboardTextDelegate _setClipboardDelegate;
    private GetClipboardTextDelegate _getClipboardDelegate;

    public ImGuiController(GraphicsDevice gd, OutputDescription outputDescription, int width, int height)
    {
        _gd = gd;
        _windowWidth = width;
        _windowHeight = height;

        ImGui.CreateContext();

        var io = ImGui.GetIO();
        io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags.DockingEnable;

        io.BackendFlags |= ImGuiBackendFlags.HasMouseCursors;
        io.BackendFlags |= ImGuiBackendFlags.HasSetMousePos;

        // Setup clipboard via PlatformIO
        var platformIO = ImGui.GetPlatformIO();

        // Create delegate instances and store them in fields to prevent GC
        _setClipboardDelegate = new SetClipboardTextDelegate(SetClipboardTextCallback);
        _getClipboardDelegate = new GetClipboardTextDelegate(GetClipboardTextCallback);

        // Assign to function pointers in PlatformIO
        platformIO.Platform_SetClipboardTextFn = Marshal.GetFunctionPointerForDelegate(_setClipboardDelegate);
        platformIO.Platform_GetClipboardTextFn = Marshal.GetFunctionPointerForDelegate(_getClipboardDelegate);

        CreateDeviceResources(gd, outputDescription);

        // ── Font scale: makes all text significantly larger and more readable ──
        // The default ImGui font is 13px bitmap; 1.5x scale gives ~20px effective size
        var io2 = ImGui.GetIO();
        // Scale: 1.0 = default ImGui font (~13px). Keeps all tabs visible on screen.
        // If user has a 4K screen they can bump this via Settings later.
        io2.FontGlobalScale = 1.0f;

        SetPerFrameImGuiData(1f / 60f);
        ImGui.NewFrame();
        _frameBegun = true;
    }

    // Clipboard callback methods
    private static void SetClipboardTextCallback(IntPtr userData, IntPtr text)
    {
        if (text != IntPtr.Zero)
        {
            var str = Marshal.PtrToStringUTF8(text);
            if (str != null)
            {
                _clipboardBuffer = str;
                try { TextCopy.ClipboardService.SetText(str); } catch { }
            }
        }
    }

    private static IntPtr GetClipboardTextCallback(IntPtr userData)
    {
        try
        {
            var text = TextCopy.ClipboardService.GetText();
            if (!string.IsNullOrEmpty(text))
                _clipboardBuffer = text;
        }
        catch { }

        if (string.IsNullOrEmpty(_clipboardBuffer))
            return IntPtr.Zero;

        lock (_clipboardLock)
        {
            // Free previous allocation to prevent memory leak
            if (_clipboardPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_clipboardPtr);
                _clipboardPtr = IntPtr.Zero;
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(_clipboardBuffer + "\\0");
            _clipboardPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, _clipboardPtr, bytes.Length);
            return _clipboardPtr;
        }
    }

    public void WindowResized(int width, int height)
    {
        _windowWidth = width;
        _windowHeight = height;
    }

    public void CreateDeviceResources(GraphicsDevice gd, OutputDescription outputDescription)
    {
        _gd = gd;
        ResourceFactory factory = gd.ResourceFactory;

        _vertexShader = factory.CreateShader(new ShaderDescription(
            ShaderStages.Vertex,
            GetVertexShaderBytes(gd.BackendType),
            "main"));

        _fragmentShader = factory.CreateShader(new ShaderDescription(
            ShaderStages.Fragment,
            GetFragmentShaderBytes(gd.BackendType),
            "main"));

        _projMatrixBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer | BufferUsage.Dynamic));

        var vertexLayout = new VertexLayoutDescription(
            new VertexElementDescription("in_position", VertexElementSemantic.Position, VertexElementFormat.Float2),
            new VertexElementDescription("in_texCoord", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2),
            new VertexElementDescription("in_color", VertexElementSemantic.Color, VertexElementFormat.Byte4_Norm));

        _mainResourceLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("ProjectionMatrixBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex),
            new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment),
            new ResourceLayoutElementDescription("FontSampler", ResourceKind.Sampler, ShaderStages.Fragment)));

        var pipelineDescription = new GraphicsPipelineDescription(
            BlendStateDescription.SingleAlphaBlend,
            new DepthStencilStateDescription(false, false, ComparisonKind.Always),
            new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, true, false),
            PrimitiveTopology.TriangleList,
            new ShaderSetDescription(
                new[] { vertexLayout },
                new[] { _vertexShader, _fragmentShader }),
            new ResourceLayout[] { _mainResourceLayout },
            outputDescription,
            ResourceBindingModel.Default);

        _pipeline = factory.CreateGraphicsPipeline(pipelineDescription);
        RecreateFontDeviceTexture(gd);
    }

    private byte[] GetVertexShaderBytes(GraphicsBackend backend)
    {
        if (backend == GraphicsBackend.Direct3D11)
        {
            string hlsl = @"
cbuffer ProjectionMatrixBuffer : register(b0)
{
    float4x4 projection_matrix;
};

struct VS_INPUT
{
    float2 pos : POSITION;
    float2 uv : TEXCOORD;
    float4 col : COLOR;
};

struct PS_INPUT
{
    float4 pos : SV_POSITION;
    float4 col : COLOR;
    float2 uv : TEXCOORD;
};

PS_INPUT main(VS_INPUT input)
{
    PS_INPUT output;
    output.pos = mul(projection_matrix, float4(input.pos.xy, 0.0, 1.0));
    output.col = input.col;
    output.uv = input.uv;
    return output;
}
";
            return System.Text.Encoding.UTF8.GetBytes(hlsl);
        }
        else
        {
            string glsl = @"
#version 450
layout(set = 0, binding = 0) uniform ProjectionMatrixBuffer
{
    mat4 projection_matrix;
};

layout(location = 0) in vec2 in_position;
layout(location = 1) in vec2 in_texCoord;
layout(location = 2) in vec4 in_color;

layout(location = 0) out vec4 fsin_color;
layout(location = 1) out vec2 fsin_texCoord;

void main()
{
    gl_Position = projection_matrix * vec4(in_position, 0.0, 1.0);
    fsin_color = in_color;
    fsin_texCoord = in_texCoord;
}
";
            return System.Text.Encoding.UTF8.GetBytes(glsl);
        }
    }

    private byte[] GetFragmentShaderBytes(GraphicsBackend backend)
    {
        if (backend == GraphicsBackend.Direct3D11)
        {
            string hlsl = @"
struct PS_INPUT
{
    float4 pos : SV_POSITION;
    float4 col : COLOR;
    float2 uv : TEXCOORD;
};

Texture2D FontTexture : register(t0);
SamplerState FontSampler : register(s0);

float4 main(PS_INPUT input) : SV_Target
{
    return input.col * FontTexture.Sample(FontSampler, input.uv);
}
";
            return System.Text.Encoding.UTF8.GetBytes(hlsl);
        }
        else
        {
            string glsl = @"
#version 450
layout(set = 0, binding = 1) uniform texture2D FontTexture;
layout(set = 0, binding = 2) uniform sampler FontSampler;

layout(location = 0) in vec4 fsin_color;
layout(location = 1) in vec2 fsin_texCoord;

layout(location = 0) out vec4 outputColor;

void main()
{
    outputColor = fsin_color * texture(sampler2D(FontTexture, FontSampler), fsin_texCoord);
}
";
            return System.Text.Encoding.UTF8.GetBytes(glsl);
        }
    }

    private void RecreateFontDeviceTexture(GraphicsDevice gd)
    {
        ImGuiIOPtr io = ImGui.GetIO();
        io.Fonts.GetTexDataAsRGBA32(out IntPtr pixels, out int width, out int height, out int bytesPerPixel);

        _fontTexture = gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
            (uint)width, (uint)height, 1, 1, PixelFormat.R8_G8_B8_A8_UNorm, TextureUsage.Sampled));

        gd.UpdateTexture(_fontTexture, pixels, (uint)(width * height * bytesPerPixel), 0, 0, 0,
            (uint)width, (uint)height, 1, 0, 0);

        _fontTextureView = gd.ResourceFactory.CreateTextureView(_fontTexture);

        io.Fonts.SetTexID((IntPtr)_fontTextureView.GetHashCode());
        io.Fonts.ClearTexData();
    }

    private void SetPerFrameImGuiData(float deltaSeconds)
    {
        ImGuiIOPtr io = ImGui.GetIO();
        io.DisplaySize = new Vector2(_windowWidth, _windowHeight);
        io.DisplayFramebufferScale = Vector2.One;
        io.DeltaTime = deltaSeconds;
    }

    public void Update(float deltaSeconds, InputSnapshot snapshot)
    {
        if (_frameBegun)
        {
            ImGui.Render();
        }

        SetPerFrameImGuiData(deltaSeconds);
        UpdateImGuiInput(snapshot);

        _frameBegun = true;
        ImGui.NewFrame();
    }

    private void UpdateImGuiInput(InputSnapshot snapshot)
    {
        ImGuiIOPtr io = ImGui.GetIO();

        io.MousePos = snapshot.MousePosition;
        io.MouseDown[0] = snapshot.IsMouseDown(MouseButton.Left);
        io.MouseDown[1] = snapshot.IsMouseDown(MouseButton.Right);
        io.MouseDown[2] = snapshot.IsMouseDown(MouseButton.Middle);
        io.MouseWheel = snapshot.WheelDelta;

        foreach (var keyEvent in snapshot.KeyEvents)
        {
            ImGuiKey imguiKey = VeldridKeyToImGuiKey(keyEvent.Key);
            if (imguiKey != ImGuiKey.None)
            {
                io.AddKeyEvent(imguiKey, keyEvent.Down);
            }
        }

        foreach (var c in snapshot.KeyCharPresses)
        {
            io.AddInputCharacter(c);
        }

        io.KeyCtrl = IsKeyDown(snapshot, Key.ControlLeft) || IsKeyDown(snapshot, Key.ControlRight);
        io.KeyAlt = IsKeyDown(snapshot, Key.AltLeft) || IsKeyDown(snapshot, Key.AltRight);
        io.KeyShift = IsKeyDown(snapshot, Key.ShiftLeft) || IsKeyDown(snapshot, Key.ShiftRight);
        io.KeySuper = IsKeyDown(snapshot, Key.WinLeft) || IsKeyDown(snapshot, Key.WinRight);
    }

    private bool IsKeyDown(InputSnapshot snapshot, Key key)
    {
        foreach (var keyEvent in snapshot.KeyEvents)
        {
            if (keyEvent.Key == key)
                return keyEvent.Down;
        }
        return false;
    }

    private ImGuiKey VeldridKeyToImGuiKey(Key key)
    {
        return key switch
        {
            Key.Tab => ImGuiKey.Tab,
            Key.Left => ImGuiKey.LeftArrow,
            Key.Right => ImGuiKey.RightArrow,
            Key.Up => ImGuiKey.UpArrow,
            Key.Down => ImGuiKey.DownArrow,
            Key.PageUp => ImGuiKey.PageUp,
            Key.PageDown => ImGuiKey.PageDown,
            Key.Home => ImGuiKey.Home,
            Key.End => ImGuiKey.End,
            Key.Insert => ImGuiKey.Insert,
            Key.Delete => ImGuiKey.Delete,
            Key.BackSpace => ImGuiKey.Backspace,
            Key.Space => ImGuiKey.Space,
            Key.Enter => ImGuiKey.Enter,
            Key.Escape => ImGuiKey.Escape,
            Key.KeypadEnter => ImGuiKey.KeypadEnter,
            Key.A => ImGuiKey.A,
            Key.C => ImGuiKey.C,
            Key.V => ImGuiKey.V,
            Key.X => ImGuiKey.X,
            Key.Y => ImGuiKey.Y,
            Key.Z => ImGuiKey.Z,
            _ => ImGuiKey.None
        };
    }

    public void Render(GraphicsDevice gd, CommandList cl)
    {
        if (_frameBegun)
        {
            _frameBegun = false;
            ImGui.Render();
            RenderImDrawData(ImGui.GetDrawData(), gd, cl);
        }
    }

    private unsafe void RenderImDrawData(ImDrawDataPtr drawData, GraphicsDevice gd, CommandList cl)
    {
        if (drawData.CmdListsCount == 0)
            return;

        uint vertexOffsetInVertices = 0;
        uint indexOffsetInElements = 0;

        int totalVtxCount = 0;
        int totalIdxCount = 0;

        for (int i = 0; i < drawData.CmdListsCount; i++)
        {
            ImDrawListPtr cmdList = drawData.CmdLists[i];
            totalVtxCount += cmdList.VtxBuffer.Size;
            totalIdxCount += cmdList.IdxBuffer.Size;
        }

        if (_vertexBuffer == null || _vertexBuffer.SizeInBytes < (ulong)(totalVtxCount * sizeof(ImDrawVert)))
        {
            _vertexBuffer?.Dispose();
            _vertexBuffer = gd.ResourceFactory.CreateBuffer(new BufferDescription(
                (uint)(totalVtxCount * sizeof(ImDrawVert)),
                BufferUsage.VertexBuffer | BufferUsage.Dynamic));
        }

        if (_indexBuffer == null || _indexBuffer.SizeInBytes < (ulong)(totalIdxCount * sizeof(ushort)))
        {
            _indexBuffer?.Dispose();
            _indexBuffer = gd.ResourceFactory.CreateBuffer(new BufferDescription(
                (uint)(totalIdxCount * sizeof(ushort)),
                BufferUsage.IndexBuffer | BufferUsage.Dynamic));
        }

        for (int i = 0; i < drawData.CmdListsCount; i++)
        {
            ImDrawListPtr cmdList = drawData.CmdLists[i];

            cl.UpdateBuffer(_vertexBuffer, vertexOffsetInVertices * (uint)sizeof(ImDrawVert),
                (IntPtr)cmdList.VtxBuffer.Data, (uint)(cmdList.VtxBuffer.Size * sizeof(ImDrawVert)));

            cl.UpdateBuffer(_indexBuffer, indexOffsetInElements * sizeof(ushort),
                (IntPtr)cmdList.IdxBuffer.Data, (uint)(cmdList.IdxBuffer.Size * sizeof(ushort)));

            vertexOffsetInVertices += (uint)cmdList.VtxBuffer.Size;
            indexOffsetInElements += (uint)cmdList.IdxBuffer.Size;
        }

        var mvp = Matrix4x4.CreateOrthographicOffCenter(
            drawData.DisplayPos.X,
            drawData.DisplayPos.X + drawData.DisplaySize.X,
            drawData.DisplayPos.Y + drawData.DisplaySize.Y,
            drawData.DisplayPos.Y,
            -1.0f,
            1.0f);

        cl.UpdateBuffer(_projMatrixBuffer, 0, ref mvp);

        _mainResourceSet = gd.ResourceFactory.CreateResourceSet(new ResourceSetDescription(
            _mainResourceLayout,
            _projMatrixBuffer,
            _fontTextureView,
            gd.PointSampler));

        cl.SetPipeline(_pipeline);
        cl.SetGraphicsResourceSet(0, _mainResourceSet);
        cl.SetVertexBuffer(0, _vertexBuffer);
        cl.SetIndexBuffer(_indexBuffer, IndexFormat.UInt16);

        vertexOffsetInVertices = 0;
        indexOffsetInElements = 0;

        Vector2 clipOffset = drawData.DisplayPos;

        for (int n = 0; n < drawData.CmdListsCount; n++)
        {
            ImDrawListPtr cmdList = drawData.CmdLists[n];

            for (int cmdI = 0; cmdI < cmdList.CmdBuffer.Size; cmdI++)
            {
                ImDrawCmdPtr pcmd = cmdList.CmdBuffer[cmdI];

                if (pcmd.UserCallback != IntPtr.Zero)
                    continue;

                Vector4 clipRect = pcmd.ClipRect;
                cl.SetScissorRect(0,
                    (uint)(clipRect.X - clipOffset.X),
                    (uint)(clipRect.Y - clipOffset.Y),
                    (uint)(clipRect.Z - clipRect.X),
                    (uint)(clipRect.W - clipRect.Y));

                cl.DrawIndexed(pcmd.ElemCount, 1,
                    (uint)(pcmd.IdxOffset + indexOffsetInElements),
                    (int)(pcmd.VtxOffset + vertexOffsetInVertices),
                    0);
            }

            vertexOffsetInVertices += (uint)cmdList.VtxBuffer.Size;
            indexOffsetInElements += (uint)cmdList.IdxBuffer.Size;
        }
    }

    public void Dispose()
    {
        // CRITICAL: Free clipboard memory to prevent leak
        lock (_clipboardLock)
        {
            if (_clipboardPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_clipboardPtr);
                _clipboardPtr = IntPtr.Zero;
            }
            _clipboardBuffer = "";
        }

        // Dispose resources in reverse order of creation
        _mainResourceSet?.Dispose();
        _mainResourceLayout?.Dispose();
        _pipeline?.Dispose();
        _fragmentShader?.Dispose();
        _vertexShader?.Dispose();
        _fontTextureView?.Dispose();
        _fontTexture?.Dispose();
        _projMatrixBuffer?.Dispose();
        _indexBuffer?.Dispose();
        _vertexBuffer?.Dispose();

        GC.SuppressFinalize(this);
    }
}