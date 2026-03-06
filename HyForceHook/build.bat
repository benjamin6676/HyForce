@echo off
:: Build HyForceHook.dll  (ONE .c file, one output DLL)
setlocal

set SRC=HyForceHook.c
set OUT=HyForceHook.dll
set DEST=%APPDATA%\HyForce\DLLs

where cl.exe >nul 2>&1
if %errorlevel%==0 (
    echo [MSVC x64] Building %SRC% ...
    cl /O2 /LD /D_WIN32_WINNT=0x0A00 %SRC% /Fe:%OUT% ws2_32.lib
    goto done
)
where x86_64-w64-mingw32-gcc >nul 2>&1
if %errorlevel%==0 (
    echo [MinGW-w64 x64] Building %SRC% ...
    x86_64-w64-mingw32-gcc -O2 -shared -m64 -D_WIN32_WINNT=0x0A00 -o %OUT% %SRC% -lws2_32
    goto done
)
where gcc >nul 2>&1
if %errorlevel%==0 (
    echo [gcc x64] Building %SRC% ...
    gcc -O2 -shared -m64 -D_WIN32_WINNT=0x0A00 -o %OUT% %SRC% -lws2_32
    goto done
)
echo [ERROR] No C compiler found.
echo   Option A: open "x64 Native Tools Command Prompt for VS" and run this bat
echo   Option B: install MinGW-w64 from https://winlibs.com and add its bin\ to PATH
goto end

:done
if exist %OUT% (
    echo.
    echo [OK] %OUT% built successfully.
    if not exist "%DEST%" mkdir "%DEST%"
    copy /Y %OUT% "%DEST%\%OUT%" >nul
    echo [OK] Copied to %DEST%\%OUT%
    echo.
    echo Ready. Start HyForce, go to Injection tab, click Inject DLL.
) else (
    echo [FAIL] Build failed - check errors above.
)

:end
endlocal
pause
