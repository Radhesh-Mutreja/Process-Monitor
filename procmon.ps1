# ============================================================
#  NOIR // PROCESS MONITOR
#  Suspicious process detection for Windows
#  Author : Radhesh Mutreja (nullRdx)
#  GitHub : github.com/Radhesh-Mutreja
# ============================================================

param (
    [switch]$ExportHTML,
    [switch]$ExportTXT,
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ── Config ───────────────────────────────────────────────────
$VERSION = "1.0"
$TIMESTAMP = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$REPORT_DATE = Get-Date -Format "yyyyMMdd_HHmmss"

# Known malicious / suspicious process names
$KNOWN_BAD = @(
    "mimikatz","meterpreter","nc","ncat","netcat","psexec",
    "wce","fgdump","pwdump","gsecdump","procdump","lsass",
    "cobaltstrike","beacon","empire","powersploit","nishang",
    "lazagne","rubeus","bloodhound","sharphound","crackmapexec",
    "xmrig","minerd","cpuminer","nbtscan"
)

# Suspicious directories — processes running from here are flagged
$SUSPICIOUS_PATHS = @(
    "$env:TEMP",
    "$env:TMP",
    "$env:APPDATA\Roaming",
    "$env:LOCALAPPDATA\Temp",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp"
)

# Legitimate system processes (whitelist for parent-child checks)
$SYSTEM_PROCS = @(
    "services","svchost","lsass","csrss","wininit",
    "winlogon","explorer","system","smss","spoolsv"
)

# ── Helpers ──────────────────────────────────────────────────
function Write-Header {
    Clear-Host
    $banner = @"

  ███╗   ██╗ ██████╗ ██╗██████╗
  ████╗  ██║██╔═══██╗██║██╔══██╗
  ██╔██╗ ██║██║   ██║██║██████╔╝
  ██║╚██╗██║██║   ██║██║██╔══██╗
  ██║ ╚████║╚██████╔╝██║██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
  // PROCESS MONITOR v$VERSION
  // nullRdx | NFSU Delhi
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  SCAN INITIATED : $TIMESTAMP" -ForegroundColor DarkGray
    Write-Host "  HOST           : $env:COMPUTERNAME" -ForegroundColor DarkGray
    Write-Host "  USER           : $env:USERNAME" -ForegroundColor DarkGray
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host ""
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "CRITICAL" { return "Red" }
        "WARNING"  { return "Yellow" }
        "NORMAL"   { return "Green" }
        default    { return "Gray" }
    }
}

function Test-SuspiciousPath {
    param([string]$Path)
    foreach ($sp in $SUSPICIOUS_PATHS) {
        if ($Path -like "$sp*") { return $true }
    }
    return $false
}

function Test-SignedExecutable {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        return $sig.Status -eq "Valid"
    } catch { return $null }
}

function Get-ProcessFlags {
    param($Process, [string]$Path)

    $flags = @()
    $severity = "NORMAL"

    # Check known bad names
    $name = $Process.Name.ToLower()
    foreach ($bad in $KNOWN_BAD) {
        if ($name -like "*$bad*") {
            $flags += "KNOWN_MALICIOUS_NAME"
            $severity = "CRITICAL"
        }
    }

    # Check suspicious path
    if ($Path -and (Test-SuspiciousPath -Path $Path)) {
        $flags += "SUSPICIOUS_PATH"
        if ($severity -ne "CRITICAL") { $severity = "WARNING" }
    }

    # Check signature
    if ($Path) {
        $signed = Test-SignedExecutable -Path $Path
        if ($signed -eq $false) {
            $flags += "UNSIGNED"
            if ($severity -eq "NORMAL") { $severity = "WARNING" }
        } elseif ($signed -eq $null) {
            $flags += "SIGNATURE_UNKNOWN"
        }
    }

    # No path — running from memory or hidden
    if (-not $Path -or $Path -eq "") {
        $flags += "NO_PATH_DETECTED"
        if ($severity -ne "CRITICAL") { $severity = "WARNING" }
    }

    # High CPU usage flag
    try {
        if ($Process.CPU -gt 80) {
            $flags += "HIGH_CPU"
            if ($severity -eq "NORMAL") { $severity = "WARNING" }
        }
    } catch {}

    # High memory usage (>500MB)
    try {
        $memMB = [math]::Round($Process.WorkingSet64 / 1MB, 1)
        if ($memMB -gt 500) {
            $flags += "HIGH_MEM"
        }
    } catch {}

    if ($flags.Count -eq 0) { $flags += "CLEAN" }

    return @{ Severity = $severity; Flags = $flags }
}

# ── Main Scan ────────────────────────────────────────────────
function Start-ProcessScan {
    Write-Header

    $results = @()
    $critCount = 0
    $warnCount = 0
    $cleanCount = 0

    Write-Host "  [*] Enumerating processes..." -ForegroundColor DarkCyan
    Write-Host ""

    $processes = Get-Process | Sort-Object CPU -Descending

    foreach ($proc in $processes) {
        $path = ""
        try {
            $path = $proc.MainModule.FileName
        } catch {}

        $analysis = Get-ProcessFlags -Process $proc -Path $path

        $memMB = 0
        try { $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1) } catch {}

        $cpuVal = 0
        try { $cpuVal = [math]::Round($proc.CPU, 1) } catch {}

        $result = [PSCustomObject]@{
            PID      = $proc.Id
            Name     = $proc.Name
            CPU      = $cpuVal
            MemMB    = $memMB
            Path     = if ($path) { $path } else { "N/A" }
            Severity = $analysis.Severity
            Flags    = ($analysis.Flags -join " | ")
        }

        $results += $result

        switch ($analysis.Severity) {
            "CRITICAL" { $critCount++ }
            "WARNING"  { $warnCount++ }
            "NORMAL"   { $cleanCount++ }
        }

        # Print line
        $color = Get-SeverityColor -Severity $analysis.Severity
        $flagStr = ($analysis.Flags -join " | ")
        $line = "  [{0,-8}] PID:{1,-6} {2,-25} CPU:{3,6}s  MEM:{4,7}MB" -f `
            $analysis.Severity, $proc.Id, $proc.Name.Substring(0, [Math]::Min($proc.Name.Length,24)), $cpuVal, $memMB

        Write-Host $line -ForegroundColor $color

        if ($analysis.Severity -ne "NORMAL") {
            Write-Host ("             FLAGS : $flagStr") -ForegroundColor DarkYellow
            if ($path) {
                Write-Host ("             PATH  : $path") -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }

    # ── Summary ──
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  SCAN COMPLETE" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  TOTAL    : $($processes.Count)" -ForegroundColor Gray
    Write-Host "  CRITICAL : $critCount" -ForegroundColor Red
    Write-Host "  WARNING  : $warnCount" -ForegroundColor Yellow
    Write-Host "  CLEAN    : $cleanCount" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host ""

    return $results
}

# ── HTML Report ──────────────────────────────────────────────
function Export-HTMLReport {
    param($Results, [string]$Path)

    $critical = $Results | Where-Object { $_.Severity -eq "CRITICAL" }
    $warnings  = $Results | Where-Object { $_.Severity -eq "WARNING" }
    $total     = $Results.Count

    $rows = $Results | ForEach-Object {
        $rowClass = switch ($_.Severity) {
            "CRITICAL" { "critical" }
            "WARNING"  { "warning" }
            default    { "" }
        }
        "<tr class='$rowClass'><td>$($_.PID)</td><td>$($_.Name)</td><td>$($_.CPU)s</td><td>$($_.MemMB) MB</td><td><span class='sev $($_.Severity.ToLower())'>$($_.Severity)</span></td><td>$($_.Flags)</td><td class='path'>$($_.Path)</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'/>
<title>NOIR // PROCESS MONITOR REPORT</title>
<style>
body{background:#080a0f;color:#c8d8e8;font-family:'Courier New',monospace;padding:2rem}
h1{color:#00d4ff;letter-spacing:.2em;font-size:1.5rem}
.sub{color:#4a6070;font-size:.8rem;margin-bottom:2rem}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.box{background:#0d1117;border:1px solid #1a2535;padding:1rem;text-align:center}
.val{font-size:2rem;font-weight:700}.lbl{font-size:.65rem;color:#4a6070;margin-top:.3rem}
.c-blue{color:#00d4ff}.c-red{color:#ff3366}.c-yellow{color:#ffaa00}.c-green{color:#39ff14}
table{width:100%;border-collapse:collapse;font-size:.75rem}
th{background:#111820;border-bottom:1px solid #1a2535;padding:.5rem .75rem;text-align:left;color:#4a6070;font-size:.6rem;letter-spacing:.1em}
td{padding:.4rem .75rem;border-bottom:1px solid rgba(26,37,53,.5)}
td.path{font-size:.65rem;color:#4a6070;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr.critical{background:rgba(255,51,102,.06);border-left:2px solid #ff3366}
tr.warning{background:rgba(255,170,0,.04);border-left:2px solid #ffaa00}
.sev{padding:.1rem .4rem;font-size:.6rem;font-weight:700}
.sev.critical{background:rgba(255,51,102,.2);color:#ff3366}
.sev.warning{background:rgba(255,170,0,.2);color:#ffaa00}
.sev.normal{background:rgba(0,212,255,.1);color:#00d4ff}
footer{margin-top:2rem;border-top:1px solid #1a2535;padding-top:1rem;font-size:.7rem;color:#4a6070}
</style></head><body>
<h1>NOIR // PROCESS MONITOR</h1>
<div class='sub'>FORENSIC PROCESS REPORT &nbsp;|&nbsp; $TIMESTAMP &nbsp;|&nbsp; $env:COMPUTERNAME</div>
<div class='grid'>
  <div class='box'><div class='val c-blue'>$total</div><div class='lbl'>TOTAL PROCESSES</div></div>
  <div class='box'><div class='val c-red'>$($critical.Count)</div><div class='lbl'>CRITICAL</div></div>
  <div class='box'><div class='val c-yellow'>$($warnings.Count)</div><div class='lbl'>WARNINGS</div></div>
  <div class='box'><div class='val c-green'>$($total - $critical.Count - $warnings.Count)</div><div class='lbl'>CLEAN</div></div>
</div>
<table>
<thead><tr><th>PID</th><th>NAME</th><th>CPU</th><th>MEMORY</th><th>SEVERITY</th><th>FLAGS</th><th>PATH</th></tr></thead>
<tbody>$($rows -join '')</tbody>
</table>
<footer>NOIR PROCESS MONITOR &nbsp;|&nbsp; nullRdx &nbsp;|&nbsp; github.com/Radhesh-Mutreja &nbsp;|&nbsp; $TIMESTAMP</footer>
</body></html>
"@

    $filePath = "$Path\Noir_ProcessReport_$REPORT_DATE.html"
    $html | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "  [+] HTML report saved: $filePath" -ForegroundColor Cyan
}

# ── TXT Report ───────────────────────────────────────────────
function Export-TXTReport {
    param($Results, [string]$Path)

    $lines = @(
        "NOIR // PROCESS MONITOR REPORT",
        "Generated : $TIMESTAMP",
        "Host      : $env:COMPUTERNAME",
        "User      : $env:USERNAME",
        ("=" * 60),
        ""
    )

    $critical = $Results | Where-Object { $_.Severity -eq "CRITICAL" }
    $warnings  = $Results | Where-Object { $_.Severity -eq "WARNING" }

    if ($critical) {
        $lines += "CRITICAL PROCESSES:"
        $lines += ("-" * 40)
        $critical | ForEach-Object {
            $lines += "PID: $($_.PID) | $($_.Name)"
            $lines += "  FLAGS : $($_.Flags)"
            $lines += "  PATH  : $($_.Path)"
            $lines += ""
        }
    }

    if ($warnings) {
        $lines += "WARNINGS:"
        $lines += ("-" * 40)
        $warnings | ForEach-Object {
            $lines += "PID: $($_.PID) | $($_.Name)"
            $lines += "  FLAGS : $($_.Flags)"
            $lines += "  PATH  : $($_.Path)"
            $lines += ""
        }
    }

    $lines += ("=" * 60)
    $lines += "SUMMARY"
    $lines += "Total    : $($Results.Count)"
    $lines += "Critical : $($critical.Count)"
    $lines += "Warnings : $($warnings.Count)"
    $lines += "Clean    : $($Results.Count - $critical.Count - $warnings.Count)"

    $filePath = "$Path\Noir_ProcessReport_$REPORT_DATE.txt"
    $lines | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "  [+] TXT report saved: $filePath" -ForegroundColor Cyan
}

# ── Entry Point ──────────────────────────────────────────────
$scanResults = Start-ProcessScan

if ($ExportHTML) {
    Export-HTMLReport -Results $scanResults -Path $OutputPath
}

if ($ExportTXT) {
    Export-TXTReport -Results $scanResults -Path $OutputPath
}

if (-not $ExportHTML -and -not $ExportTXT) {
    Write-Host "  [i] Run with -ExportHTML or -ExportTXT to save a report." -ForegroundColor DarkGray
    Write-Host "  [i] Example: .\noir-procmon.ps1 -ExportHTML" -ForegroundColor DarkGray
    Write-Host ""
}
