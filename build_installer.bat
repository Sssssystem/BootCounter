@echo off
cd /d "%~dp0"
echo ======================================================
echo   BootCounter - Build Modern Windows 11 Installer
echo ======================================================
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

echo [1/3] Checking/Installing cx_Freeze...
python -m pip show cx_Freeze >nul 2>nul
if errorlevel 1 (
    python -m pip install --upgrade cx_Freeze
    if errorlevel 1 (
        echo [ERROR] Failed to install cx_Freeze.
        pause
        exit /b 1
    )
)

echo [2/3] Building application files (build\BootCounter_App)...
if exist "build\BootCounter_App" rmdir /s /q "build\BootCounter_App"
python setup_msi.py build_exe --build-exe="build\BootCounter_App"
if errorlevel 1 (
    echo [ERROR] build_exe failed.
    pause
    exit /b 1
)

echo [3/3] Looking for Inno Setup 6 (ISCC.exe)...
set "ISCC="
for /f "delims=" %%i in ('where iscc 2^>nul') do set "ISCC=%%i"
if not defined ISCC if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not defined ISCC (
    echo Inno Setup 6 not found. Installing via winget...
    winget install -e --id JRSoftware.InnoSetup --accept-source-agreements --accept-package-agreements
    if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)

if not defined ISCC (
    echo [ERROR] Inno Setup 6 not found. Please install it from https://jrsoftware.org/isdl.php and run this script again.
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
echo ======================================================
echo   SUCCESS! Modern Installer created:
echo   dist\BootCounter_Setup_1.1.0_amd64.exe
echo ======================================================
pause
