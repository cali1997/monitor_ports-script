@echo off
REM Windows Security Suite Launcher
REM Batch versie voor Windows 11

echo.
echo 🚀 Starting Windows Security Monitoring Suite...
echo.

REM Check of Python beschikbaar is
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python niet gevonden! Installeer Python 3.x eerst.
    echo    Download van: https://python.org
    pause
    exit /b 1
)

REM Check of psutil geinstalleerd is
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo ❌ psutil niet gevonden!
    echo 📦 Installeren van psutil...
    pip install psutil
    if errorlevel 1 (
        echo ❌ Kon psutil niet installeren
        pause
        exit /b 1
    )
)

echo ✅ Dependencies OK
echo.

REM Krijg script directory
set "SCRIPT_DIR=%~dp0"

echo 🖥️  Starting Port Monitor (rechts)...
start "Windows Port Monitor" python "%SCRIPT_DIR%port_sidebar_windows.py"
timeout /t 1 >nul

echo 🛡️ Starting Firewall Control (links)...
start "Windows Firewall Control" python "%SCRIPT_DIR%firewall_sidebar_windows.py"
timeout /t 1 >nul

echo 🚨 Starting Security Defense (center)...
start "Windows Security Defense" python "%SCRIPT_DIR%security_defense_windows.py"

echo.
echo ✅ WINDOWS SECURITY SUITE ACTIVE:
echo    - Port Monitor (rechts venster)
echo    - Firewall Control (links venster)
echo    - Security Defense (center venster)
echo.
echo 💡 Tips:
echo    - Start als Administrator voor volledige firewall functies
echo    - Gebruik rechtermuisklik menu's voor extra opties
echo    - Check Security Defense voor automatische threat detection
echo.
echo ⚠️  Druk op een toets om vensters te sluiten en suite te stoppen...
pause >nul

echo.
echo 🛑 Stopping Windows Security Suite...

REM Kill alle Python processen van deze suite
taskkill /f /im python.exe /fi "WINDOWTITLE eq Windows Port Monitor*" >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq Windows Firewall Control*" >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq Windows Security Defense*" >nul 2>&1

echo ✅ Suite gestopt
echo Bedankt voor het gebruiken van Windows Security Suite!
timeout /t 2 >nul