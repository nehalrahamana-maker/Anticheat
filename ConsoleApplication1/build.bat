@echo off
setlocal EnableDelayedExpansion

title NEHAL ANTI-CHEAT — Build Script
echo.
echo ============================================================
echo   NEHAL ANTI-CHEAT v3.5  ^|  MSBuild Release x64
echo ============================================================
echo.

REM ----------------------------------------------------------------
REM  Locate MSBuild — try VS2022, VS2019, VS2017 in order
REM ----------------------------------------------------------------
set "MSBUILD="

REM Preferred: VS2022 (v143)
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%P (
        set "MSBUILD=%%~P"
        goto :found
    )
)

REM Fallback: VS2019 (v142)
for %%P in (
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%P (
        set "MSBUILD=%%~P"
        goto :found
    )
)

REM Last resort: try PATH
where msbuild >nul 2>&1
if %ERRORLEVEL% == 0 (
    set "MSBUILD=msbuild"
    goto :found
)

echo [ERROR] MSBuild not found.
echo         Install Visual Studio 2022 (or 2019) with the
echo         "Desktop development with C++" workload, or
echo         install "Build Tools for Visual Studio".
echo.
pause
exit /b 1

:found
echo [+] MSBuild found:  %MSBUILD%
echo.

REM ----------------------------------------------------------------
REM  Project path (relative to this bat's location)
REM ----------------------------------------------------------------
set "PROJECT=%~dp0ConsoleApplication1\ConsoleApplication1.vcxproj"

if not exist "%PROJECT%" (
    echo [ERROR] Project file not found:
    echo         %PROJECT%
    pause
    exit /b 1
)

REM ----------------------------------------------------------------
REM  Build configuration — change CONFIG or PLATFORM here if needed
REM     CONFIG  = Debug   ^| Release
REM     PLATFORM= Win32   ^| x64
REM ----------------------------------------------------------------
set "CONFIG=Release"
set "PLATFORM=x64"
set "JOBS=/maxcpucount"

echo [*] Building:  %CONFIG% ^| %PLATFORM%
echo [*] Project:   %PROJECT%
echo.

REM ----------------------------------------------------------------
REM  Run MSBuild
REM ----------------------------------------------------------------
"%MSBUILD%" "%PROJECT%" ^
    /p:Configuration=%CONFIG% ^
    /p:Platform=%PLATFORM% ^
    /p:PlatformToolset=v143 ^
    /p:WindowsTargetPlatformVersion=10.0 ^
    /verbosity:minimal ^
    /nologo ^
    %JOBS%

set "BUILD_RESULT=%ERRORLEVEL%"

echo.
if %BUILD_RESULT% == 0 (
    echo ============================================================
    echo   BUILD SUCCEEDED
    echo ============================================================

    REM Show output binary location
    set "OUTDIR=%~dp0ConsoleApplication1\x64\Release"
    set "EXE=!OUTDIR!\ConsoleApplication1.exe"

    if exist "!EXE!" (
        echo.
        echo   Binary:  !EXE!
        for %%F in ("!EXE!") do echo   Size:    %%~zF bytes
        echo.

        REM Ask user if they want to run the scanner now
        choice /C YN /M "Run scanner now (needs Administrator)?"
        if !ERRORLEVEL! == 1 (
            echo.
            echo [*] Launching as Administrator...
            powershell -Command "Start-Process -FilePath '!EXE!' -Verb RunAs"
        )
    ) else (
        echo   [!] Binary not found at expected path — check project output dir.
    )
) else (
    echo ============================================================
    echo   BUILD FAILED  ^(exit code %BUILD_RESULT%^)
    echo ============================================================
    echo.
    echo   Common causes:
    echo     - Missing Windows SDK (install via VS Installer)
    echo     - Missing v143 toolset (install "MSVC v143" in VS Installer)
    echo     - New .cpp files not added to the .vcxproj
    echo       (right-click project in VS ^> Add ^> Existing Item)
    echo     - Syntax errors in newly added scanner files
    echo.
)

echo.
pause
exit /b %BUILD_RESULT%
