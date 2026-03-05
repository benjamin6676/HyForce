# HyForceHook DLL — Build Instructions
# ========================================

## What it does
Injects into Hytale.exe and hooks WSASendTo / WSARecvFrom (Windows socket functions).
Every UDP packet Hytale sends or receives is cloned and sent to HyForce via a named pipe.
HyForce decrypts using the SSLKEYLOGFILE keys — no proxy, no lag, no session mismatch.

## Option A — MSVC (recommended, ships with Visual Studio)
From "x64 Native Tools Command Prompt for VS 2022":
```
cl /LD /O2 /EHsc HyForceHook.cpp ws2_32.lib psapi.lib /Fe:HyForceHook.dll
```
Copy HyForceHook.dll to the HyForce.exe folder.

## Option B — MinGW-w64 (free, easier install)
Install: https://www.msys2.org → pacman -S mingw-w64-x86_64-gcc
```
x86_64-w64-mingw32-g++ -shared -m64 -O2 -o HyForceHook.dll HyForceHook.cpp -lws2_32 -lpsapi -static
```

## Option C — Pre-built DLL
A pre-compiled x64 HyForceHook.dll will be available at:
https://github.com/HyForce/releases (if released publicly)

## Injection
1. Start HyForce
2. Click Injection tab
3. Start Hytale (before connecting to server)
4. Select Hytale.exe in process list
5. Select HyForceHook.dll in DLL dropdown
6. Click INJECT
7. HyForce pipe receives ● ACTIVE status
8. Connect to Hytale server — decryption begins automatically

## Why this works better than proxy
- Proxy: requires Hytale to route through 127.0.0.1:5521 → lag, session issues
- DLL: reads packets directly inside Hytale.exe memory → zero overhead
- DLL captures Initial packet → DCID length resolved immediately
- Same TLS session as SSLKEYLOGFILE → guaranteed key match
- Game server sees normal connection → no proxy detection

## Architecture note
Hytale runs on Java 25 JVM. The JVM calls Windows ws2_32.dll natively for all
UDP (via java.nio.channels.DatagramChannel → sun.nio.ch.DatagramChannelImpl → 
WindowsDatagramChannelImpl → JNI → ws2_32). IAT patching in the JVM module 
(jvm.dll) is sufficient to intercept all QUIC traffic.

## Troubleshooting
- "Access denied": Run HyForce as Administrator
- "Injection may have failed": Hytale has basic anticheat — try before connecting to server
- "No pipe data": Check HyForce pipe server is started (green in Injection tab)
- Pipe name: \\.\pipe\HyForceCapture
