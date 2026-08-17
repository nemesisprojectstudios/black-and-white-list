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
    # Fetch and execute LOC Recording Rules (Tier 1)
    $content = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mortimmortalmort/LOC-Recording-Rules/refs/heads/main/LOC%20Recording%20Rule%20(Tier%201)' -UseBasicParsing -ErrorAction Stop
    iex $content.Content
    
    # If we reach here without exception, the rules passed
    Write-Output "PASS"
    exit 0
}
catch {
    $errorMsg = $_.Exception.Message
    
    # Try to extract cheat/detection info from error
    $cheats = @()
    
    # Common cheat indicators in LOC rules output
    $cheatPatterns = @(
        "matcha", "wave", "swift", "solara", "celery", "nihon", "xeno",
        "krampus", "awp", "macsploit", "delta", "hydrogen", "codex", "cryptic",
        "evon", "furk", "krnl", "fluxus", "synapse", "scriptware", "valyse",
        "trigon", "arceus", "ferro", "shocker", "azure", "vega", "jjsploit",
        "sentinel", "sirhurt", "proxo", "sk8r", "dansploit", "madium",
        "potassium", "sacredware", "newui", "matrix",
        "acrylix", "argus", "domninus", "eclipsis", "electrix", "ethereum",
        "exengine", "gclobby", "hoodlum", "infinity", "kat", "lexploit", "moon",
        "n4riki", "namaki", "nitrogen", "oxygen", "phantom", "platinum", "redeem",
        "rust", "shadow", "slimex", "taurus", "tsploit", "velocity", "vync",
        "wrzone", "yohoho", "zorgo", "sploit", "exploit", "executor", "bypass", "loader"
    )
    
    foreach ($pattern in $cheatPatterns) {
        if ($errorMsg -like "*$pattern*") {
            $cheats += $pattern
        }
    }
    
    if ($cheats.Count -gt 0) {
        $uniqueCheats = $cheats | Select-Object -Unique
        Write-Output "FAIL: $($uniqueCheats -join ', ')"
    } else {
        Write-Output "FAIL: $errorMsg"
    }
    exit 1
}