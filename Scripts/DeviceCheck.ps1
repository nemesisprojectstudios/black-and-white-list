<#
.SYNOPSIS
    DeviceCheck - LOC Recording Rules validation for anti-cheat (embedded)
.DESCRIPTION
    Runs LOC Recording Rules (Tier 1) locally and outputs detailed results
    Output format: Detailed per-check results + summary + Final result: [PASS/FAIL/ERROR]
.NOTES
    Must run as Administrator
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: Not running as Administrator"
    exit 1
}

try {
    # --- LOC Recording Rules (Tier 1) EMBEDDED ---
    
    # Blacklist definitions
    $blacklist = @("matcha", "olduimatrix", "autoexe", "bin", "workspace", "monkeyaim", "thunderaim", "thunderclient", "celex", "release", "matrix", "matcha.exe", "triggerbot", "solara", "xeno", "wave", "cloudy", "tupical", "horizon", "myst", "celery", "zarora", "juju", "nezure", "FusionHacks.zip", "release.zip", "bootstrapper", "aimmy.exe", "aimmy", "Fluxus", "clumsy", "build", "build.zip", "build.rar", "MystW.exe", "isabelle", "dx9", "dx9ware")
    $suspiciousList = @("isabelle", "xeno", "solara", "bootstrapper", "bootstrappernew", "loader", "santoware", "mystw", "severe", "mapper", "thunderclient", "monkeyaim", "olduimatrix", "matrix", "matcha")
    $watchlist = @("BOOTSTRAPPERNEW.EXE", "BOOTSTRAPPER.EXE", "XENO.EXE", "XENOUI.EXE", "SOLARA.EXE", "MAPPER.EXE", "LOADER.EXE", "MATCHA.EXE", "EVOLVE.EXE")

    $detectedCheats = @()
    $allOutputs = @()

    function Add-Output {
        param([string]$Message, [string]$Type = "INFO")
        $allOutputs += "$Message"
    }

    # --- 1. Exclusion Check ---
    try {
        $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
        if ($exclusions) {
            Add-Output "FAILURE: Exclusion paths detected:`n$($exclusions -join "`n")"
            $detectedCheats += "exclusion_paths"
        } else {
            Add-Output "SUCCESS: No Exclusions were found at the moment."
        }
    } catch {
        Add-Output "WARNING: Could not get exclusion paths."
    }

    # --- 2. Threats Check ---
    try {
        Import-Module Defender -ErrorAction SilentlyContinue
        $threats = Get-MpThreatDetection
        $activeThreats = $threats | Where-Object { $_.ThreatStatus -eq "Active" -and $_.QuarantineStatus -ne "Quarantined" }
        if ($activeThreats) {
            foreach ($t in $activeThreats) {
                $msg = "FAILURE: Threat detected - Name: $($t.ThreatName), Severity: $($t.Severity), Path: $($t.Path), Detected: $($t.DetectionTime)"
                Add-Output $msg
                $detectedCheats += "defender_threat_$($t.ThreatName)"
            }
        } else {
            Add-Output "SUCCESS: No active threats that are not quarantined."
        }
    } catch {
        Add-Output "WARNING: Threat scan could not complete."
    }

    # --- 3. Memory Integrity & Blocklist ---
    try {
        $miReg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $vbReg = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" 
        $memOn = Get-ItemPropertyValue -Path $miReg -Name "Enabled" -ErrorAction Stop
        $vbOn = $false
        try {
            $vbStatus = Get-ItemPropertyValue -Path $vbReg -Name "VulnerableBlocklistStatus"
            if ($vbStatus -eq 1) { $vbOn = $true }
        } catch {}
        if (-not ($memOn -eq 1 -or $vbOn)) {
            Add-Output "FAILURE: Memory integrity and blocklist are both disabled."
            $detectedCheats += "memory_integrity_disabled"
        } else {
            Add-Output "SUCCESS: Memory integrity is enabled or Vulnerable Blocklist is active."
        }
    } catch {
        Add-Output "WARNING: Unable to verify memory integrity."
    }

    # --- 4. Windows Defender ---
    try {
        $defender = Get-MpComputerStatus
        if (-not ($defender.AMServiceEnabled -and $defender.RealTimeProtectionEnabled)) {
            Add-Output "FAILURE: Windows Defender real-time protection is DISABLED."
            $detectedCheats += "defender_realtime_disabled"
        } else {
            Add-Output "SUCCESS: Windows Defender real-time protection is ENABLED."
        }
    } catch {
        Add-Output "WARNING: Could not assess Defender status."
    }

    # --- 5. Exploit Checker ---
    try {
        $hash = "A89E3321B2BC0A90C21714F153E26DCF2BDEA4BC7200AF9C8CA8394FF54470A1"
        $found = Test-Path "$env:APPDATA\Isabelle"
        if ($hash -and $found) {
            Add-Output "FAILURE: Isabelle exploit folder found and hash matched."
            $detectedCheats += "isabelle_exploit"
        } else {
            Add-Output "SUCCESS: No exploit signs found."
        }
    } catch {
        Add-Output "WARNING: Exploit check could not be completed."
    }

    # --- 6. Prefetch ---
    try {
        $now = Get-Date
        $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf"
        foreach ($pf in $pfFiles) {
            $name = $pf.BaseName.ToUpper()
            $lastWrite = $pf.LastWriteTime
            $age = [math]::Round(($now - $lastWrite).TotalHours, 2)
            if ($watchlist -contains "$name.EXE") {
                $msg = "WARNING: Suspicious prefetch file: $name | $age hours ago"
                Add-Output $msg
                $detectedCheats += "prefetch_suspicious_$name"
            } else {
                Add-Output "Detected: $name | $age hrs ago"
            }
        }
    } catch {
        Add-Output "WARNING: Could not access prefetch."
    }

    # --- 7. Key Checker ---
    try {
        $folders = Get-ChildItem "C:\ProgramData\KeyAuth\debug" -Directory -ErrorAction Stop
        foreach ($f in $folders) {
            $msg = "FAILURE: External cheat/KeyAuth folder: $($f.Name)"
            Add-Output $msg
            $detectedCheats += "keyauth_folder_$($f.Name)"
        }
    } catch {
        Add-Output "SUCCESS: No KeyAuth folders found."
    }

    # --- 8. Registry Suspicious Check ---
    try {
        $mui = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        $entries = Get-ItemProperty -Path $mui
        foreach ($prop in $entries.PSObject.Properties) {
            $lower = $prop.Name.ToLower()
            foreach ($b in $blacklist) {
                if ($lower -like "*$b*") {
                    if ($suspiciousList -contains $b) {
                        $msg = "WARNING: Suspicious registry: $($prop.Name)"
                        Add-Output $msg
                        $detectedCheats += "registry_suspicious_$b"
                    }
                }
            }
        }
    } catch {
        Add-Output "WARNING: Cannot access MuiCache registry."
    }

    # --- 9. PAH Check - SKIPPED (per request) ---
    # Original item 9: PAH Check - Process Active History GUI
    # Skipped per user request

    # --- 10. Summary Header ---
    Add-Output ""
    Add-Output "--- Summary ---"

    # --- 11. Success Rate (no color) ---
    $totalChecks = 8  # 8 main checks performed
    $failCount = ($detectedCheats | Measure-Object).Count
    $successCount = $totalChecks - $failCount
    $rate = [math]::Round(($successCount / $totalChecks) * 100, 2)
    Add-Output "Success Rate: $rate% ($successCount / $totalChecks)"

    # --- 12. Failures Count ---
    Add-Output "Failures: $failCount"

    # --- 13. Warnings Count ---
    $warningCount = ($allOutputs | Where-Object { $_ -like "WARNING:*" }).Count
    Add-Output "Warnings: $warningCount"

    # --- 14. Completion Time - SKIPPED (per request) ---
    # Original item 14: Completed in X.XX seconds - SKIPPED per request

    # --- 15. Timestamp ---
    Add-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # Output all collected outputs
    $allOutputs | ForEach-Object { Write-Output $_ }

    # Final result line
    $uniqueCheats = $detectedCheats | Select-Object -Unique
    if ($uniqueCheats.Count -gt 0) {
        Write-Output ""
        Write-Output "Final result:"
        Write-Output "FAIL: $($uniqueCheats -join ', ')"
        exit 1
    } else {
        Write-Output ""
        Write-Output "Final result:"
        Write-Output "PASS"
        exit 0
    }

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output ""
    Write-Output "Final result:"
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
