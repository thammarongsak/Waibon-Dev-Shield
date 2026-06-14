[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$Version = "0.6.0"
function Wds-Header {
    Write-Host "============================================================"
    Write-Host " WAIBON DEV SHIELD PRE-OPEN GUARD v$Version"
    Write-Host " Evidence Fusion & Intent-Aware Pre-Open Guard"
    Write-Host "============================================================"
    Write-Host " This guard scans before opening VS Code / Cursor / Codex."
    Write-Host " It combines text, context, behavior, chain, and intent evidence before deciding whether to recommend review."
    Write-Host " Report only: no delete, no modify, no quarantine. Scan report opens before editor."
    Write-Host " Developed by: Mr.Thammarongsak Panichsawas (Thailand)"
    Write-Host " Project     : www.zetaorigin.com"
    Write-Host " Follow      : https://www.facebook.com/ZetaCoreAI"
    Write-Host "============================================================"
}
function Ask($Text,$Default) {
    $v = Read-Host $Text
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v
}
try {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptRoot
    Wds-Header
    $Target = Ask "Paste target project folder path" ""
    if ([string]::IsNullOrWhiteSpace($Target)) { throw "Target path is required." }
    $tool = Ask "Open after scan: 0=Scan only, 1=VS Code, 2=Cursor, 3=Codex [0]" "0"
    $scanChoice = Ask "Scan profile: 1=Quick, 2=Smart Deep, 3=Full Deep, 4=Secrets, 5=Supply-chain, 6=AI Agent/MCP [2]" "1"
    if ($scanChoice -eq "1") { $Mode = "Quick" } elseif ($scanChoice -eq "3") { $Mode = "Deep" } elseif ($scanChoice -eq "4") { $Mode = "Secrets" } elseif ($scanChoice -eq "5") { $Mode = "SupplyChain" } elseif ($scanChoice -eq "6") { $Mode = "AgentMcp" } else { $Mode = "SmartDeep" }
    $scanScript = Join-Path $ScriptRoot "Waibon-DevShield-Scan.ps1"
    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$scanScript,"-TargetPath",$Target,"-ScanMode",$Mode,"-NoAutoOpenReport","-BatchSize","300","-ProgressIntervalSec","4")
    Write-Host ""
    Write-Host "[GUARD] Running safety scan first..."
    $p = Start-Process -FilePath "powershell" -ArgumentList $args -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Scan failed. Project will not be opened automatically." }
    $latest = Join-Path $ProjectRoot "reports\latest-report-paths.json"
    if (Test-Path -LiteralPath $latest) {
        $doc = Get-Content -LiteralPath $latest -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($doc.html_report) { Start-Process $doc.html_report | Out-Null }
        $risk = [string]$doc.risk_status
        Write-Host "[GUARD] Risk status: $risk"
        if ($risk -like "RED*") {
            Write-Host "[GUARD] Critical review needed. Auto-open is blocked by default."
            $confirm = Ask "Type OPEN to override and open anyway, or press Enter to stop" ""
            if ($confirm -ne "OPEN") { return }
        } elseif ($risk -like "ORANGE*" -or $risk -like "YELLOW*") {
            $confirm = Ask "Review recommended. Open anyway? Y/N [N]" "N"
            if ($confirm.ToUpperInvariant() -ne "Y") { return }
        }
    }
    if ($tool -eq "1") { Start-Process "code" -ArgumentList @($Target); return }
    if ($tool -eq "2") { Start-Process "cursor" -ArgumentList @($Target); return }
    if ($tool -eq "3") { Start-Process "codex" -ArgumentList @("app",$Target); return }
    Write-Host "[GUARD] Scan only selected. No editor opened."
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)"
    exit 1
}
