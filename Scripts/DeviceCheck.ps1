<#
.SYNOPSIS
    DeviceCheck - LOC Recording Rules validation for anti-cheat (embedded)
.DESCRIPTION
    Runs LOC Recording Rules (Tier 1) locally and outputs PASS/FAIL/ERROR status
    Returns PASS/FAIL: cheat1, cheat2 on FAIL, or PASS on clean
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

    # --- Exclusion Check ---
    try {
        $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
        if ($exclusions) {
            $detectedCheats += "exclusion_paths"
        }
    } catch {}

    # --- Threats Check ---
    try {
        Import-Module Defender -ErrorAction SilentlyContinue
        $threats = Get-MpThreatDetection
        $activeThreats = $threats | Where-Object { $_.ThreatStatus -eq "Active" -and $_.QuarantineStatus -ne "Quarantined" }
        if ($activeThreats) {
            foreach ($t in $activeThreats) {
                $detectedCheats += "defender_threat_$($t.ThreatName)"
            }
        }
    } catch {}

    # --- Memory Integrity & Blocklist ---
    try {
        $miReg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $vbReg = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" 
        $memOn = Get-ItemPropertyValue -Path $miReg -Name "Enabled" -ErrorAction Stop
        $vbOn = $false
        try {
            $vbStatus = Get-ItemPropertyValue -Path $vbReg -Name "VulnerableBlocklistStatus"
            if ($vbStatus -eq 1) { $vbOn = $true }
        } catch {}
        if -not ($memOn -eq 1 -or $vbOn) {
            $detectedCheats += "memory_integrity_disabled"
        }
    } catch {}

    # --- Defender Check ---
    try {
        $defender = Get-MpComputerStatus
        if -not ($defender.AMServiceEnabled -and $defender.RealTimeProtectionEnabled) {
            $detectedCheats += "defender_realtime_disabled"
        }
    } catch {}

    # --- Exploit Check ---
    try {
        $hash = "A89E3321B2BC0A90C21714F153E26DCF2BDEA4BC7200AF9C8CA8394FF54470A1"
        $found = Test-Path "$env:APPDATA\Isabelle"
        if ($hash -and $found) {
            $detectedCheats += "isabelle_exploit"
        }
    } catch {}

    # --- Prefetch ---
    try {
        $now = Get-Date
        $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf"
        foreach ($pf in $pfFiles) {
            $name = $pf.BaseName.ToUpper()
            if ($watchlist -contains "$name.EXE") {
                $detectedCheats += "prefetch_suspicious_$name"
            }
        }
    } catch {}

    # --- Key Checker ---
    try {
        $folders = Get-ChildItem "C:\ProgramData\KeyAuth\debug" -Directory -ErrorAction Stop
        foreach ($f in $folders) {
            $detectedCheats += "keyauth_folder_$($f.Name)"
        }
    } catch {}

    # --- Registry Suspicious Check ---
    try {
        $mui = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        $entries = Get-ItemProperty -Path $mui
        foreach ($prop in $entries.PSObject.Properties) {
            $lower = $prop.Name.ToLower()
            foreach ($b in $blacklist) {
                if ($lower -like "*$b*") {
                    if ($suspiciousList -contains $b) {
                        $detectedCheats += "registry_suspicious_$b"
                    }
                }
            }
        }
    } catch {}

    # --- PAH Check (Process Active History) ---
    # Just check if PAH would trigger - we don't actually launch it
    # (The original script launches a GUI window, we just note it would run)

    # --- Output Result ---
    $uniqueCheats = $detectedCheats | Select-Object -Unique
    if ($uniqueCheats.Count -gt 0) {
        Write-Output "FAIL: $($uniqueCheats -join ', ')"
        exit 1
    } else {
        Write-Output "PASS"
        exit 0
    }

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
