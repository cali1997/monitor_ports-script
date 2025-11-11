# ==== Port Monitor voor Windows 11 ====
# PowerShell versie van monitor_ports.sh
# Gebruikt netstat in plaats van ss

param(
    [int]$Interval = 3,        # Aantal seconden tussen checks
    [bool]$OnlyTCP = $true,    # true = alleen TCP, false = TCP+UDP
    [bool]$FilterLocal = $true, # true = localhost niet tonen
    [string]$LogFile = ""      # Optioneel log bestand
)

$script:prev = ""

Write-Host "[*] Windows Port Monitor gestart (elke $Interval s). Ctrl+C om te stoppen." -ForegroundColor Green

function Get-CurrentPorts {
    # Gebruik netstat om listening poorten te krijgen
    if ($OnlyTCP) {
        # Alleen TCP listening poorten
        $netstatOutput = netstat -an | Where-Object { $_ -match "TCP.*LISTENING" }
    } else {
        # TCP + UDP
        $netstatOutput = netstat -an | Where-Object { $_ -match "(TCP.*LISTENING|UDP)" }
    }
    
    $ports = @()
    foreach ($line in $netstatOutput) {
        if ($line -match '\s+(TCP|UDP)\s+([0-9.:]+)\s+(LISTENING|\*)') {
            $protocol = $matches[1]
            $address = $matches[2]
            
            # Filter localhost indien nodig
            if ($FilterLocal -and ($address -match "127\.0\.0\.1" -or $address -match "::1")) {
                continue
            }
            
            $ports += "$protocol $address"
        }
    }
    
    return ($ports | Sort-Object)
}

# Hoofdloop
while ($true) {
    $current = Get-CurrentPorts
    $currentStr = $current -join "`n"
    
    if ($script:prev -ne "") {
        # Vergelijk huidige met vorige
        $prevArray = $script:prev -split "`n" | Where-Object { $_ -ne "" }
        $currentArray = $current | Where-Object { $_ -ne "" }
        
        # Nieuwe poorten (in current maar niet in prev)
        $added = $currentArray | Where-Object { $_ -notin $prevArray }
        
        # Gesloten poorten (in prev maar niet in current)
        $removed = $prevArray | Where-Object { $_ -notin $currentArray }
        
        if ($added.Count -gt 0) {
            Write-Host ""
            Write-Host "🔔 NIEUWE LISTENING SOCKET(s) GEDETECTEERD:" -ForegroundColor Green
            foreach ($port in $added) {
                Write-Host "  $port" -ForegroundColor Yellow
            }
            [Console]::Beep(800, 200)  # Windows beep
            
            if ($LogFile) {
                Add-Content -Path $LogFile -Value "$(Get-Date) ADDED: $($added -join ', ')"
            }
        }
        
        if ($removed.Count -gt 0) {
            Write-Host ""
            Write-Host "🔴 LISTENING SOCKET(s) GESLOTEN:" -ForegroundColor Red
            foreach ($port in $removed) {
                Write-Host "  $port" -ForegroundColor Cyan
            }
            [Console]::Beep(400, 200)  # Lagere toon voor gesloten
            
            if ($LogFile) {
                Add-Content -Path $LogFile -Value "$(Get-Date) REMOVED: $($removed -join ', ')"
            }
        }
    }
    
    $script:prev = $currentStr
    Start-Sleep -Seconds $Interval
}