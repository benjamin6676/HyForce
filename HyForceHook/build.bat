@echo off
:: Build HyForceHook.dll v9
:: iphlpapi required for GetExtendedUdpTable (SOCKENUM command)
:: advapi32 required for OpenProcessToken, GetTokenInformation, etc.
setlocal

set SRC=HyForceHook.c
set OUT=HyForceHook.dll
set DEST=%APPDATA%\HyForce\DLLs

where cl.exe >nul 2>&1
if %errorlevel%==0 (
    echo [MSVC x64] Building...
   cl /O2 /LD /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS HyForceHook.c /Fe:HyForceHook.dll ws2_32.lib psapi.lib iphlpapi.lib advapi32.lib ntdll.lib shlwapi.lib
    goto done
)
where x86_64-w64-mingw32-gcc >nul 2>&1
if %errorlevel%==0 (
    echo [MinGW-w64 x64] Building...
    x86_64-w64-mingw32-gcc -O2 -shared -m64 -D_WIN32_WINNT=0x0A00 -o %OUT% %SRC% -lws2_32 -lpsapi -liphlpapi -ladvapi32
    goto done
)
where gcc >nul 2>&1
if %errorlevel%==0 (
    echo [gcc x64] Building...
    gcc -O2 -shared -m64 -D_WIN32_WINNT=0x0A00 -o %OUT% %SRC% -lws2_32 -lpsapi -liphlpapi -ladvapi32
    goto done
)
echo [ERROR] No compiler found. Install MinGW-w64 or open VS x64 Native Tools prompt.
goto end

:done
if exist %OUT% (
    echo [OK] Built: %OUT%
    if not exist "%DEST%" mkdir "%DEST%"
    copy /Y %OUT% "%DEST%\%OUT%" >nul
    echo [OK] Deployed to %DEST%
) else (
    echo [FAIL] Build failed.
)

:end
endlocal
pause