@echo off
REM ──────────────────────────────────────────────────────────
REM  HyForceHook.dll build script
REM
REM  Option A — Visual Studio (recommended, produces best x64 code)
REM    Open "x64 Native Tools Command Prompt for VS 20xx"
REM    then run this script.
REM
REM  Option B — MinGW-w64
REM    Install https://www.mingw-w64.org/  (select x86_64)
REM    Add MinGW bin folder to PATH, then run this script.
REM ──────────────────────────────────────────────────────────

setlocal

where cl.exe >nul 2>&1
if %errorlevel%==0 (
    echo Building with MSVC...
    cl.exe /O2 /Oy- /LD ^
        /D_WIN32_WINNT=0x0A00 ^
        /DNDEBUG ^
        HyForceHook.c ^
        /Fe:HyForceHook.dll ^
        /link ws2_32.lib
    if %errorlevel%==0 (
        echo.
        echo [OK] HyForceHook.dll built successfully.
    ) else (
        echo [FAIL] MSVC build failed.
    )
    goto :done
)

where gcc >nul 2>&1
if %errorlevel%==0 (
    echo Building with MinGW gcc...
    gcc -O2 -shared -m64 ^
        -D_WIN32_WINNT=0x0A00 -DNDEBUG ^
        -o HyForceHook.dll ^
        HyForceHook.c ^
        -lws2_32
    if %errorlevel%==0 (
        echo.
        echo [OK] HyForceHook.dll built successfully.
    ) else (
        echo [FAIL] MinGW build failed.
    )
    goto :done
)

echo [ERROR] Neither cl.exe (MSVC) nor gcc (MinGW) found in PATH.
echo   For MSVC: open 'x64 Native Tools Command Prompt for VS 20xx' first.
echo   For MinGW: install https://www.mingw-w64.org/ and add bin to PATH.

:done
endlocal
pause
