<#
.SYNOPSIS
    DeviceCheck - LOC Recording Rules validation for anti-cheat
.DESCRIPTION
    Runs LOC Recording Rules (Tier 1) and outputs PASS/FAIL/ERROR status
    Returns only status and cheat list on FAIL
.NOTES
    Must run as Administrator
#>

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: Not running as Administrator"
    exit 1
}

try {
    # Fetch and execute LOC Recording Rules (Tier 1) silently
    $content = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mortimmortalmort/LOC-Recording-Rules/refs/heads/main/LOC%20Recording%20Rule%20(Tier%201)' -UseBasicParsing -ErrorAction Stop
    
    # Execute in isolated scope to prevent PAH/shell interference
    $result = & {
        try {
            # Suppress any shell initialization that might cause errors
            $ErrorActionPreference = 'Stop'
            iex $content.Content
            return "PASS"
        }
        catch {
            return "FAIL: $($_.Exception.Message)"
        }
    }
    
    Write-Output $result
    exit ($result -like "PASS*" ? 0 : 1)
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
