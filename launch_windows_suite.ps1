# Windows Security Suite Launcher - PowerShell versie
# Uitgebreidere versie met meer checks en opties

param(
    [switch]$SkipDependencyCheck,
    [switch]$NoWait,
    [string]$Component = "all"  # "all", "ports", "firewall", "defense"
)

Write-Host ""
Write-Host "🚀 Windows Security Monitoring Suite" -ForegroundColor Green
Write-Host "   Versie voor Windows 11" -ForegroundColor Gray
Write-Host ""

# Check Administrator rechten
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "✅ Administrator rechten gedetecteerd - Volledige functionaliteit beschikbaar" -ForegroundColor Green
} else {
    Write-Host "⚠️  Draait NIET als Administrator" -ForegroundColor Yellow
    Write-Host "   Sommige firewall functies kunnen beperkt zijn" -ForegroundColor Yellow
    Write-Host "   Start PowerShell als Administrator voor volledige functionaliteit" -ForegroundColor Yellow
}
Write-Host ""

# Dependency checks (tenzij overgeslagen)
if (-not $SkipDependencyCheck) {
    Write-Host "🔍 Checking dependencies..." -ForegroundColor Cyan
    
    # Check Python
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+\.\d+)") {
            $version = $matches[1]
            if ([version]$version -ge [version]"3.6") {
                Write-Host "✅ Python $version OK" -ForegroundColor Green
            } else {
                Write-Host "❌ Python $version te oud. Minimaal 3.6 vereist" -ForegroundColor Red
                exit 1
            }
        }
    } catch {
        Write-Host "❌ Python niet gevonden!" -ForegroundColor Red
        Write-Host "   Download en installeer Python van https://python.org" -ForegroundColor Yellow
        exit 1
    }
    
    # Check psutil
    $psutilCheck = python -c "import psutil; print('OK')" 2>&1
    if ($psutilCheck -eq "OK") {
        Write-Host "✅ psutil module OK" -ForegroundColor Green
    } else {
        Write-Host "📦 psutil niet gevonden, installeren..." -ForegroundColor Yellow
        pip install psutil
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Kon psutil niet installeren" -ForegroundColor Red
            exit 1
        }
        Write-Host "✅ psutil geinstalleerd" -ForegroundColor Green
    }
    
    # Check tkinter (meestal standaard met Python)
    $tkinterCheck = python -c "import tkinter; print('OK')" 2>&1
    if ($tkinterCheck -eq "OK") {
        Write-Host "✅ tkinter GUI module OK" -ForegroundColor Green
    } else {
        Write-Host "❌ tkinter niet beschikbaar" -ForegroundColor Red
        Write-Host "   Herinstalleer Python met tkinter support" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ""

# Script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Component launcher functies
function Start-PortMonitor {
    Write-Host "🖥️  Starting Windows Port Monitor..." -ForegroundColor Cyan
    $portScript = Join-Path $scriptDir "port_sidebar_windows.py"
    if (Test-Path $portScript) {
        Start-Process python -ArgumentList "`"$portScript`"" -WindowStyle Normal
        Start-Sleep 1
        Write-Host "✅ Port Monitor gestart (rechter venster)" -ForegroundColor Green
    } else {
        Write-Host "❌ Port monitor script niet gevonden: $portScript" -ForegroundColor Red
    }
}

function Start-FirewallControl {
    Write-Host "🛡️ Starting Windows Firewall Control..." -ForegroundColor Cyan
    $firewallScript = Join-Path $scriptDir "firewall_sidebar_windows.py"
    if (Test-Path $firewallScript) {
        Start-Process python -ArgumentList "`"$firewallScript`"" -WindowStyle Normal
        Start-Sleep 1
        Write-Host "✅ Firewall Control gestart (linker venster)" -ForegroundColor Green
    } else {
        Write-Host "❌ Firewall script niet gevonden: $firewallScript" -ForegroundColor Red
    }
}

function Start-SecurityDefense {
    Write-Host "🚨 Starting Security Defense System..." -ForegroundColor Cyan
    $defenseScript = Join-Path $scriptDir "security_defense_windows.py"
    if (Test-Path $defenseScript) {
        Start-Process python -ArgumentList "`"$defenseScript`"" -WindowStyle Normal
        Start-Sleep 1
        Write-Host "✅ Security Defense gestart (center venster)" -ForegroundColor Green
    } else {
        Write-Host "❌ Security defense script niet gevonden: $defenseScript" -ForegroundColor Red
    }
}

# Start componenten op basis van parameter
switch ($Component.ToLower()) {
    "ports" {
        Start-PortMonitor
    }
    "firewall" {
        Start-FirewallControl
    }
    "defense" {
        Start-SecurityDefense
    }
    "all" {
        Start-PortMonitor
        Start-FirewallControl
        Start-SecurityDefense
    }
    default {
        Write-Host "❌ Onbekend component: $Component" -ForegroundColor Red
        Write-Host "   Gebruik: all, ports, firewall, of defense" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ""
Write-Host "✅ WINDOWS SECURITY SUITE ACTIVE" -ForegroundColor Green -BackgroundColor DarkGreen
Write-Host ""
Write-Host "📋 Actieve componenten:" -ForegroundColor White
if ($Component -eq "all" -or $Component -eq "ports") {
    Write-Host "   🖥️  Port Monitor - Real-time poort monitoring" -ForegroundColor Cyan
}
if ($Component -eq "all" -or $Component -eq "firewall") {
    Write-Host "   🛡️ Firewall Control - IP blokkering en systeem info" -ForegroundColor Orange
}
if ($Component -eq "all" -or $Component -eq "defense") {
    Write-Host "   🚨 Security Defense - Automatische threat detection" -ForegroundColor Red
}

Write-Host ""
Write-Host "💡 Tips:" -ForegroundColor Yellow
Write-Host "   • Rechtermuisklik op items voor extra opties" -ForegroundColor Gray
Write-Host "   • Check Security Defense tabs voor verschillende functies" -ForegroundColor Gray
Write-Host "   • Firewall functies werken het best als Administrator" -ForegroundColor Gray
Write-Host "   • Alle vensters zijn 'always on top' voor makkelijke monitoring" -ForegroundColor Gray

if (-not $NoWait) {
    Write-Host ""
    Write-Host "Druk op een toets om de suite te stoppen..." -ForegroundColor White
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    Write-Host ""
    Write-Host "🛑 Stopping Windows Security Suite..." -ForegroundColor Red
    
    # Probeer netjes af te sluiten door Python processen te stoppen
    # Dit is een wat ruwe methode, maar effectief
    Get-Process python -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowTitle -like "*Windows*Monitor*" -or
        $_.MainWindowTitle -like "*Windows*Firewall*" -or
        $_.MainWindowTitle -like "*Windows*Security*" -or
        $_.MainWindowTitle -like "*Windows*Defense*"
    } | ForEach-Object {
        Write-Host "Stopping $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Yellow
        $_ | Stop-Process -Force
    }
    
    Write-Host "✅ Suite gestopt" -ForegroundColor Green
    Write-Host "Bedankt voor het gebruiken van Windows Security Suite!" -ForegroundColor Cyan
}