@echo off
cd /d "%~dp0"
echo =============================================================
echo   BootCounter v1.1 - Compile to Native C/C++ Machine Code
echo   (Nuitka Native Compiler + Inno Setup 6 Modern Installer)
echo =============================================================
echo.

if not exist "boot_counter.py" (
    echo [ERROR] boot_counter.py not found in current folder.
    pause
    exit /b 1
)
if not exist "BootCounter_Setup.iss" (
    echo [ERROR] BootCounter_Setup.iss not found in current folder.
    pause
    exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3 not found. Please install Python 3 first.
    pause
    exit /b 1
)

echo [1/3] Checking/Installing Nuitka...
python -m pip show nuitka >nul 2>nul
if errorlevel 1 (
    python -m pip install --upgrade nuitka ordered-set zstandard
    if errorlevel 1 (
        echo [ERROR] Failed to install Nuitka.
        pause
        exit /b 1
    )
)

echo [2/3] Compiling boot_counter.py to native C/C++ machine code (takes 2-5 mins on first run)...
if exist "build\BootCounter_App" rmdir /s /q "build\BootCounter_App"
if exist "build\boot_counter.dist" rmdir /s /q "build\boot_counter.dist"
python -m nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter --windows-icon-from-ico=app.ico --include-data-files=app.ico=app.ico --output-dir=build --output-filename=BootCounter.exe --assume-yes-for-downloads boot_counter.py
if errorlevel 1 (
    echo [ERROR] Nuitka native compilation failed. Check error messages above.
    pause
    exit /b 1
)

rename "build\boot_counter.dist" "BootCounter_App"

echo [3/3] Packaging into modern Windows 11 Installer (Inno Setup 6)...
set "ISCC="
for /f "delims=" %%i in ('where iscc 2^>nul') do set "ISCC=%%i"
if not defined ISCC if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not defined ISCC (
    echo Installing Inno Setup 6 via winget...
    winget install -e --id JRSoftware.InnoSetup --accept-source-agreements --accept-package-agreements
    if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)

if not defined ISCC (
    echo [ERROR] Inno Setup 6 not found. Native compiled files are ready in build\BootCounter_App
    pause
    exit /b 1
)

"%ISCC%" "BootCounter_Setup.iss"
if errorlevel 1 (
    echo [ERROR] Inno Setup compilation failed.
    pause
    exit /b 1
)

echo.
echo =============================================================
echo   SUCCESS! Native C-compiled Windows Installer created:
echo   dist\BootCounter_Setup_1.1.0_amd64.exe
echo =============================================================
pause
