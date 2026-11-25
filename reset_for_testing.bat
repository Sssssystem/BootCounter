@echo off
cd /d "%~dp0"
echo ======================================================
echo   BootCounter v1.1 - Wipe All Local Data (Testing Only)
echo ======================================================
echo.
echo This will delete:
echo   1. Running BootCounter.exe tray process
echo   2. TPM 2.0 dedicated test key (BootCounter_InstallKey_v1)
echo   3. %APPDATA%\BootCounter (state.json and audit.log)
echo   4. HKCU\Software\BootCounter (registry anchor)
echo   5. HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BootCounter
echo.
echo Press Ctrl+C to cancel, or press any key to continue...
pause >nul

taskkill /f /im BootCounter.exe >nul 2>nul
if exist "C:\Program Files\BootCounter\BootCounter.exe" "C:\Program Files\BootCounter\BootCounter.exe" --destroy-tpm-key
if exist "D:\Program Files\BootCounter\BootCounter.exe" "D:\Program Files\BootCounter\BootCounter.exe" --destroy-tpm-key
if exist "%LOCALAPPDATA%\Programs\BootCounter\BootCounter.exe" "%LOCALAPPDATA%\Programs\BootCounter\BootCounter.exe" --destroy-tpm-key
certutil -user -csp "Microsoft Platform Crypto Provider" -delkey BootCounter_InstallKey_v1 >nul 2>nul
echo [OK] Requested TPM 2.0 test key cleanup

if exist "%APPDATA%\BootCounter" (
    rmdir /s /q "%APPDATA%\BootCounter"
    echo [OK] Deleted %APPDATA%\BootCounter
) else (
    echo [INFO] %APPDATA%\BootCounter not found.
)

reg delete "HKCU\Software\BootCounter" /f >nul 2>nul
echo [OK] Cleared registry anchor HKCU\Software\BootCounter

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BootCounter /f >nul 2>nul
echo [OK] Cleared autostart registry entry

echo.
echo Done! You can now launch or reinstall BootCounter for a fresh first-run test.
pause
