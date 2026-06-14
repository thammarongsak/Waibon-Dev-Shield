<#
.SYNOPSIS
  Waibon Dev Shield v0.6.0 - Evidence Fusion & Intent-Aware Dev Safety Scanner.
.DESCRIPTION
  Report-only local project scanner that combines Text Evidence, Context Evidence,
  Behavior Evidence, Chain Evidence, and Intent Evidence before raising review priority.
  It includes trust workflow, report diff, scan profiles, strict red/warning gates,
  finding navigation links, and pre-open guard support.
  Report only: no delete, no modify, no quarantine, no target-file execution.
  Public wording uses Evidence Fusion / Intent-Aware / Risk Evidence wording.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][string]$TargetPath,
    [Parameter(Mandatory=$false)][string]$OutputDir,
    [Parameter(Mandatory=$false)][ValidateSet("Quick","SmartDeep","Deep","Secrets","SupplyChain","AgentMcp")][string]$ScanMode = "Quick",
    [Parameter(Mandatory=$false)][int]$MaxFileSizeMB = 0,
    [Parameter(Mandatory=$false)][int]$MaxHtmlFindings = 1000,
    [Parameter(Mandatory=$false)][int]$BatchSize = 250,
    [Parameter(Mandatory=$false)][int]$ProgressIntervalSec = 3,
    [Parameter(Mandatory=$false)][int]$MaxWorkers = 1,
    [Parameter(Mandatory=$false)][string]$CacheDir,
    [Parameter(Mandatory=$false)][switch]$NoCache,
    [Parameter(Mandatory=$false)][switch]$ClearCache,
    [Parameter(Mandatory=$false)][switch]$ForceFullScan,
    [Parameter(Mandatory=$false)][switch]$QuietProgress,
    [Parameter(Mandatory=$false)][switch]$NoAutoOpenReport,
    [Parameter(Mandatory=$false)][string]$TrustFile,
    [Parameter(Mandatory=$false)][ValidateSet("Never","Critical","Warning")][string]$FailOn = "Never",
    [Parameter(Mandatory=$false)][switch]$CI
)
$ErrorActionPreference = "Stop"
$Version = "0.6.0"

function Wds-Status {
    param([string]$Message,[string]$Level="INFO")
    $tag = "[INFO]"
    switch (($Level + "").ToUpperInvariant()) {
        "OK"    { $tag = "[OK]" }
        "WARN"  { $tag = "[WARN]" }
        "ERROR" { $tag = "[ERROR]" }
        "SCAN"  { $tag = "[SCAN]" }
    }
    Write-Host ("{0} {1}" -f $tag, $Message)
}
function Show-WdsHeader {
    Write-Host "============================================================"
    Write-Host " WAIBON DEV SHIELD v$Version"
    Write-Host " Evidence Fusion & Intent-Aware Dev Safety Scanner"
    Write-Host "============================================================"
    Write-Host " What this tool does:"
    Write-Host "  Scans developer project folders before opening or running work"
    Write-Host "  in VS Code / Cursor / Codex."
    Write-Host ""
    Write-Host " Evidence Fusion Layers:"
    Write-Host "  - Text Evidence      : raw commands, tokens, keywords, config patterns"
    Write-Host "  - Context Evidence   : docs, tests, examples, placeholders, active code"
    Write-Host "  - Behavior Evidence  : download, execute, credential, persistence, CI, agent surfaces"
    Write-Host "  - Chain Evidence     : related actions such as download -> execute -> persist"
    Write-Host "  - Intent Evidence    : inferred purpose from combined evidence"
    Write-Host ""
    Write-Host " Important:"
    Write-Host "  A text match alone is not a verdict."
    Write-Host "  Risk levels are based on combined evidence, context, behavior, chain, and inferred intent."
    Write-Host ""
    Write-Host " Safety Mode: Report only. No delete. No modify. No quarantine."
    Write-Host " Findings are evidence-based review signals, not malware verdicts."
    Write-Host ""
    Write-Host " Developed by: Mr.Thammarongsak Panichsawas (Thailand)"
    Write-Host " Project     : www.zetaorigin.com"
    Write-Host " Follow      : https://www.facebook.com/ZetaCoreAI"
    Write-Host "============================================================"
}
function HtmlSafe {
    param($Text)
    if ($null -eq $Text) { return "" }
    try { return [System.Net.WebUtility]::HtmlEncode([string]$Text) } catch { return [string]$Text }
}
function StringSha256 {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Text)
        return (([System.BitConverter]::ToString($sha.ComputeHash($bytes))) -replace "-","").ToLowerInvariant()
    } finally { $sha.Dispose() }
}
function FileSha256Safe {
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $stream = [System.IO.File]::Open($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
            try { return (([System.BitConverter]::ToString($sha.ComputeHash($stream))) -replace "-","").ToLowerInvariant() }
            finally { $stream.Dispose() }
        } finally { $sha.Dispose() }
    } catch { return "" }
}
function Get-RuleProp {
    param($Obj,[string]$Name,[string]$Default="")
    try {
        if ($null -eq $Obj) { return $Default }
        $p = $Obj.PSObject.Properties[$Name]
        if ($null -ne $p -and $null -ne $p.Value) {
            $v = [string]$p.Value
            if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
        }
    } catch {}
    return $Default
}
function Test-PatternSafe {
    param([string]$Text,[string]$Pattern)
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $false }
    try { return [System.Text.RegularExpressions.Regex]::IsMatch([string]$Text,[string]$Pattern) }
    catch { return $false }
}
function IsDocumentationOrSamplePath {
    param([string]$RelativePath)
    return (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])(docs|documentation|examples|sample|samples|test|tests|fixtures|mock|mocks|tutorial|tutorials)[\/]')
}
function IsLikelyRealSecret {
    param([string]$Line,[string]$RelativePath="")
    $l = [string]$Line
    $rp = [string]$RelativePath
    if ([string]::IsNullOrWhiteSpace($l)) { return $false }
    # Detector/config/example contexts often contain literal secret strings as rules, not real secrets.
    if (Test-PatternSafe -Text $rp -Pattern '(?i)(pre-commit-config\.ya?ml|gitleaks|secretlint|detect-secrets|trufflehog|semgrep|scanner|detector|rules?[\/])') {
        if (Test-PatternSafe -Text $l -Pattern '(?i)(regex|pattern|rule|exclude|allowlist|detect|BEGIN\s+PRIVATE\s+KEY|BEGIN\s+RSA\s+PRIVATE\s+KEY)') { return $false }
    }
    if (Test-PatternSafe -Text $rp -Pattern '(?i)(^|[\/])(docs|documentation|examples|sample|samples|test|tests|fixtures|mock|mocks|tutorial|tutorials)[\/]') { return $false }
    if (Test-PatternSafe -Text $rp -Pattern '(?i)(^|[\/])README\.md$|\.md$') { return $false }
    if (Test-PatternSafe -Text $l -Pattern '(?i)(example|sample|placeholder|dummy|changeme|your_|xxxx|todo|localhost|127\.0\.0\.1|<[^>]+>|\$\{[^}]+\}|fake|mock)') { return $false }
    if (Test-PatternSafe -Text $l -Pattern '(?i)^\s*(#|//|/\*|\*)') { return $false }
    if (Test-PatternSafe -Text $l -Pattern '(?i)(sk-[A-Za-z0-9_\-]{24,}|ghp_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9_]{30,}|ghu_[A-Za-z0-9_]{30,}|ghs_[A-Za-z0-9_]{30,}|npm_[A-Za-z0-9]{30,})') { return $true }
    if (Test-PatternSafe -Text $l -Pattern '(?i)^\s*-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----\s*$') { return $true }
    if (Test-PatternSafe -Text $l -Pattern '(?i)(OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|SUPABASE_SERVICE_ROLE_KEY|DATABASE_URL|PRIVATE_KEY|PASSWORD|SECRET|TOKEN|API[_-]?KEY)\s*[:=]\s*["'']?[^"''\s]{28,}') { return $true }
    return $false
}
function RuleAppliesToContext {
    param($Rule,[string]$Line,[string]$RelativePath)
    $ruleId = Get-RuleProp -Obj $Rule -Name "id" -Default ""
    switch ($ruleId) {
        "GITHUB_ACTION_RISK" {
            return (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.github[\/](workflows|actions)[\/].+\.(yml|yaml)$')
        }
        "VSCODE_TASKS" {
            return (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.vscode[\/](tasks|settings|launch)\.json$|(^|[\/])(tasks|settings|launch)\.json$')
        }
        "AI_AGENT_CONFIG" {
            if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])(AGENTS\.md|CLAUDE\.md|GEMINI\.md|mcp\.json|\.mcp\.json)$') { return $true }
            if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.(cursor|claude|windsurf)[\/]') { return $true }
            if (Test-PatternSafe -Text $Line -Pattern '(?i)(mcpServers|serverCommand|systemPrompt|tool_call|allowedTools|disallowedTools)') { return $true }
            return $false
        }
        "NPM_LIFECYCLE_SCRIPT" {
            return (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])package(-lock)?\.json$|(^|[\/])npm-shrinkwrap\.json$')
        }
        "NODE_CHILD_PROCESS" {
            if (IsDocumentationOrSamplePath -RelativePath $RelativePath) { return $false }
            return $true
        }
        "PYTHON_SHELL_EXEC" {
            if (IsDocumentationOrSamplePath -RelativePath $RelativePath) { return $false }
            return $true
        }
        default { return $true }
    }
}
function Mask-SensitiveLine {
    param($Line)
    $m = [string]$Line
    if ([string]::IsNullOrWhiteSpace($m)) { return "" }
    try {
        $assign = [System.Text.RegularExpressions.Regex]::Match($m,'(?i)^(\s*[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE)[A-Z0-9_]*\s*[:=]\s*).+$')
        if ($assign.Success) { $m = $assign.Groups[1].Value + "***MASKED***" }
    } catch {}
    try {
        $m = [System.Text.RegularExpressions.Regex]::Replace($m,'(?i)(sk-)[A-Za-z0-9_\-]{10,}', '${1}***MASKED***')
        $m = [System.Text.RegularExpressions.Regex]::Replace($m,'(?i)(github_pat_)[A-Za-z0-9_]{10,}', '${1}***MASKED***')
        $m = [System.Text.RegularExpressions.Regex]::Replace($m,'(?i)(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_]{10,}', '${1}***MASKED***')
        $m = [System.Text.RegularExpressions.Regex]::Replace($m,'(?i)(npm_)[A-Za-z0-9]{10,}', '${1}***MASKED***')
    } catch {}
    if ($m.Length -gt 240) { $m = $m.Substring(0,240) + "..." }
    return $m.Trim()
}
function RelPath {
    param([string]$FullPath,[string]$RootPath)
    $full = [string]$FullPath
    $root = ([string]$RootPath).TrimEnd('\','/')
    try {
        if ($full.ToLowerInvariant().StartsWith($root.ToLowerInvariant())) {
            return $full.Substring($root.Length).TrimStart([char[]]@('\','/'))
        }
    } catch {}
    return $full
}
function ShortPath {
    param([string]$Text,[int]$MaxLength=90)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    if ($Text.Length -le $MaxLength) { return $Text }
    return "..." + $Text.Substring($Text.Length - ($MaxLength - 3))
}
function RiskScoreBase {
    param([string]$Severity)
    # Conservative base weight: a rule label is only one input, not a verdict.
    switch (($Severity + "").ToLowerInvariant()) {
        "critical" { return 5 }
        "high"     { return 3 }
        "medium"   { return 2 }
        default     { return 1 }
    }
}
function RiskFromTotal {
    param([int]$Total)
    # v0.6.0: conservative thresholds. CRITICAL is reserved for strong proof or chained behavior after calibration.
    if ($Total -ge 22) { return "CRITICAL" }
    if ($Total -ge 15) { return "WARNING" }
    if ($Total -ge 6)  { return "REVIEW" }
    return "INFO"
}
function RiskRank {
    param([string]$Risk)
    switch (($Risk+"").ToUpperInvariant()) { "CRITICAL" {4}; "WARNING" {3}; "REVIEW" {2}; "INFO" {1}; default {2} }
}
function WorseRisk {
    param([string]$A,[string]$B)
    if ((RiskRank -Risk $B) -gt (RiskRank -Risk $A)) { return ($B+"").ToUpperInvariant() }
    return ($A+"").ToUpperInvariant()
}
function ConfidenceRank {
    param([string]$C)
    switch (($C+"").ToUpperInvariant()) { "HIGH" {3}; "MEDIUM" {2}; default {1} }
}
function HigherConfidence {
    param([string]$A,[string]$B)
    if ((ConfidenceRank -C $B) -gt (ConfidenceRank -C $A)) { return (Get-Culture).TextInfo.ToTitleCase(($B+"").ToLowerInvariant()) }
    return (Get-Culture).TextInfo.ToTitleCase(($A+"").ToLowerInvariant())
}
function ComputeEvidence {
    param($Rule,[string]$Line,[string]$RelativePath)
    $severity = Get-RuleProp -Obj $Rule -Name "severity" -Default "Low"
    $ruleId = Get-RuleProp -Obj $Rule -Name "id" -Default "UNKNOWN_RULE"
    $base = RiskScoreBase -Severity $severity
    $trigger = 0
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.github[\/]workflows[\/]') { $trigger += 2 }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.vscode[\/](tasks|settings|launch)\.json$') { $trigger += 2 }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.(cursor|claude|windsurf)[\/]') { $trigger += 2 }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])(AGENTS\.md|CLAUDE\.md|GEMINI\.md|mcp\.json|\.mcp\.json)$') { $trigger += 2 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(preinstall|install|postinstall|prepare|schtasks|RunOnce|CurrentVersion\\Run|Startup)') { $trigger += 2 }
    if (Test-PatternSafe -Text $ruleId -Pattern '(?i)(NPM|GITHUB|VSCODE|AGENT|LOLBIN)') { $trigger += 1 }
    if ($trigger -gt 5) { $trigger = 5 }
    $impact = 0
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(DisableRealtimeMonitoring|Set-MpPreference|Add-MpPreference|ExclusionPath|ExclusionProcess)') { $impact += 4 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(Remove-Item|rmdir|rd\s+/s|del\s+/s|format\s+[A-Z]:|cipher\s+/w)') { $impact += 3 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b|child_process|execSync|subprocess|os\.system)') { $impact += 3 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|curl|wget).{0,160}(powershell|pwsh|cmd|bash|sh|Start-Process|Invoke-Expression|\biex\b)') { $impact += 3 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|BEGIN\s+(RSA\s+)?PRIVATE\s+KEY)') { $impact += 4 }
    if ($impact -gt 8) { $impact = 8 }
    $density = 0
    $signals = @(
        '(?i)(Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|curl|wget)',
        '(?i)(powershell|pwsh|cmd\.exe|bash|sh|Start-Process)',
        '(?i)(EncodedCommand|FromBase64String|Invoke-Expression|\biex\b)',
        '(?i)(AppData|Temp|ProgramData|Startup|RunOnce|schtasks)',
        '(?i)(\.env|secret|token|api[_-]?key|password|PRIVATE\s+KEY)',
        '(?i)(child_process|execSync|spawn\(|subprocess|os\.system|eval\(|exec\()',
        '(?i)(mcpServers|serverCommand|systemPrompt|AGENTS|CLAUDE|cursor|codex)',
        '(?i)(preinstall|postinstall|prepare|run:|uses:|permissions:|secrets\.)'
    )
    foreach ($sig in $signals) { if (Test-PatternSafe -Text $Line -Pattern $sig) { $density++ } }
    if ($density -gt 5) { $density = 5 }
    if ($density -lt 1) { $density = 1 }
    $correction = 0
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])(docs|documentation|examples|sample|samples|test|tests|fixtures|mock|mocks)[\/]') { $correction += 3 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(example|sample|placeholder|dummy|changeme|your_|xxxx|todo|localhost|127\.0\.0\.1|regex|pattern|fake|mock)') { $correction += 3 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|SECRET|TOKEN|API_KEY)\s*[:=]\s*["'']?\s*$') { $correction += 2 }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)^\s*(#|//|/\*|\*)') { $correction += 2 }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(pre-commit-config\.ya?ml|gitleaks|secretlint|detect-secrets|trufflehog|semgrep|scanner|detector|rules?[\/])') { $correction += 4 }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Pipfile\.lock|composer\.lock)$') { $correction += 2 }
    if ($correction -gt 8) { $correction = 8 }
    $total = [int]([math]::Max(0,($base + $trigger + $impact + $density - $correction)))
    $risk = RiskFromTotal -Total $total
    $conf = "Low"
    if (($total -ge 12) -and ($density -ge 3) -and ($correction -le 1)) { $conf = "High" }
    elseif ($total -ge 8) { $conf = "Medium" }
    return [pscustomobject]@{
        engine_version = $Version; base_score = $base; trigger_score = $trigger; impact_score = $impact; density_score = $density; context_correction = $correction; evidence_total = $total; engine_risk = $risk; engine_confidence = $conf; engine_explain = "Base=$base, Trigger=$trigger, Impact=$impact, Density=$density, ContextCorrection=$correction, Total=$total. This is review-priority scoring, not proof of malware."
    }
}

function Get-ContextFlags {
    param([string]$Line,[string]$RelativePath)
    $flags = New-Object System.Collections.Generic.List[string]
    if (IsDocumentationOrSamplePath -RelativePath $RelativePath) { $flags.Add("docs/examples/tests") | Out-Null }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])README\.md$|\.md$') { $flags.Add("markdown/documentation") | Out-Null }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(pre-commit-config\.ya?ml|detect-secrets|secretlint|gitleaks|trufflehog|semgrep|scanner|detector|rules?[\/])') { $flags.Add("detector-rule-context") | Out-Null }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Pipfile\.lock|composer\.lock)$') { $flags.Add("lockfile/generated-context") | Out-Null }
    if (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])(dist|build|generated|coverage|public|static|assets|storybook-static)[\/]') { $flags.Add("generated/build-context") | Out-Null }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(example|sample|placeholder|dummy|changeme|your_|xxxx|todo|localhost|127\.0\.0\.1|regex|pattern|fake|mock)') { $flags.Add("placeholder-or-example") | Out-Null }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)^\s*(#|//|/\*|\*)') { $flags.Add("comment-line") | Out-Null }
    if (Test-PatternSafe -Text $Line -Pattern '(?i)(OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|SECRET|TOKEN|API[_-]?KEY)\s*[:=]\s*["'']?\s*$') { $flags.Add("empty-secret-assignment") | Out-Null }
    if ($flags.Count -eq 0) { $flags.Add("active-code-or-config") | Out-Null }
    return @($flags | Select-Object -Unique)
}
function Get-BehaviorTags {
    param($Rule,[string]$Line,[string]$RelativePath)
    $tags = New-Object System.Collections.Generic.List[string]
    $ruleId = Get-RuleProp -Obj $Rule -Name "id" -Default ""
    $category = Get-RuleProp -Obj $Rule -Name "category" -Default ""
    $combined = ($ruleId + " " + $category + " " + $Line + " " + $RelativePath)
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|curl|wget|download)') { $tags.Add("Download intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(Start-Process|Invoke-Expression|\biex\b|powershell|pwsh|cmd\.exe|bash|sh|child_process|execSync|spawn\(|subprocess|os\.system|eval\(|exec\()') { $tags.Add("Execution intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(EncodedCommand|FromBase64String|obfuscat|base64)') { $tags.Add("Obfuscation or evasion intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(schtasks|RunOnce|CurrentVersion\\Run|Startup|LaunchAgent|systemd|crontab|persistence)') { $tags.Add("Persistence intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(\.env|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET|AZURE_CLIENT_SECRET|SUPABASE|PRIVATE\s+KEY|secret|token|credential|password)') { $tags.Add("Credential or secret exposure intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(Invoke-RestMethod|webhook|http(s)?://|upload|exfil|send|POST|curl)') { if (Test-PatternSafe -Text $combined -Pattern '(?i)(secret|token|\.env|credential|password|PRIVATE\s+KEY|cookie|session)') { $tags.Add("Possible exfiltration chain") | Out-Null } }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(Remove-Item|rmdir|rd\s+/s|del\s+/s|format\s+[A-Z]:|cipher\s+/w|vssadmin|shadowcopy|bcdedit|recoveryenabled|ransom|encrypt)') { $tags.Add("Destructive or ransomware-like intent") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess|Defender|security setting)') { $tags.Add("Security setting modification") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(postinstall|preinstall|prepare|package\.json|binding\.gyp|setup\.py|pyproject|requirements|npm|pip)') { $tags.Add("Supply-chain install surface") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(\.github[\\/]workflows|permissions:|secrets\.|actions|workflow)') { $tags.Add("CI/CD workflow surface") | Out-Null }
    if (Test-PatternSafe -Text $combined -Pattern '(?i)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|cursor|mcp\.json|mcpServers|systemPrompt|tool_call|agent)') { $tags.Add("AI agent instruction surface") | Out-Null }
    if ($tags.Count -eq 0) { $tags.Add("General review signal") | Out-Null }
    return @($tags | Select-Object -Unique)
}
function Get-BehaviorInterpretation {
    param([string[]]$Tags,[string[]]$ContextFlags)
    $t = ($Tags -join "; ")
    $c = ($ContextFlags -join "; ")
    if (($t -match "Download intent") -and ($t -match "Execution intent") -and ($t -match "Persistence intent")) { return "Potential download-execute-persistence chain. Review strongly before running." }
    if (($t -match "Credential") -and ($t -match "exfiltration")) { return "Potential credential-access plus outbound-transfer chain. Review strongly before running." }
    if (($t -match "Destructive") -and ($t -match "Obfuscation")) { return "Potential destructive behavior combined with hiding/evasion signals. Review strongly." }
    if ($c -match "detector-rule-context") { return "This appears inside a detector/rule context; reduce severity unless a real secret or active execution chain is also present." }
    if ($c -match "docs/examples/tests|placeholder") { return "This appears in documentation, examples, tests, or placeholder context; treat as lower-confidence unless supported by other active behavior." }
    return "Review the behavior context. This is a risk signal, not a malware verdict."
}
function Get-MissingEvidence {
    param([string[]]$Tags,[string[]]$ContextFlags)
    $missing = New-Object System.Collections.Generic.List[string]
    $t = ($Tags -join "; ")
    if ($t -match "Download intent" -and $t -notmatch "Execution intent") { $missing.Add("No execution chain found for this signal.") | Out-Null }
    if ($t -match "Execution intent" -and $t -notmatch "Download intent|Credential") { $missing.Add("No download or credential-access chain found with this signal.") | Out-Null }
    if ($t -match "Security setting modification" -and $t -notmatch "Credential|exfiltration|Persistence") { $missing.Add("No credential exfiltration or persistence chain found with this signal.") | Out-Null }
    if ($t -match "Credential" -and $t -notmatch "exfiltration") { $missing.Add("No outbound exfiltration chain found with this signal.") | Out-Null }
    if ($t -match "Supply-chain" -and $t -notmatch "Download intent|Execution intent|Credential") { $missing.Add("No install-time execution chain found with this signal.") | Out-Null }
    if ($missing.Count -eq 0) { $missing.Add("No missing-evidence note generated; review full file context if risk is high.") | Out-Null }
    return @($missing | Select-Object -Unique)
}
function BuildBehaviorSummary {
    param([object[]]$Findings)
    $map = @{}
    $fileMap = @{}
    foreach ($f in @($Findings)) {
        $tags = @(([string]$f.behavior_tags) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($tag in $tags) {
            if (-not $map.ContainsKey($tag)) { $map[$tag] = 0; $fileMap[$tag] = @{} }
            $map[$tag] = [int]$map[$tag] + 1
            $fname = [string]$f.file
            $fm = $fileMap[$tag]
            $fm[$fname] = $true
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($map.Keys | Sort-Object)) {
        $items.Add([pscustomobject]@{ behavior=$key; findings=[int]$map[$key]; files=[int]$fileMap[$key].Count }) | Out-Null
    }
    return @($items | Sort-Object @{Expression="findings";Descending=$true}, @{Expression="behavior";Descending=$false})
}


function Get-RootCauseKey {
    param($Finding)
    $file = ([string]$Finding.file).ToLowerInvariant()
    $rule = ([string]$Finding.rule_id).ToLowerInvariant()
    $intent = ([string]$Finding.intent_evidence).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($intent)) { $intent = ([string]$Finding.behavior_tags).ToLowerInvariant() }
    return (StringSha256 -Text ("$file|$rule|$intent")).Substring(0,12)
}
function BuildRootCauseGroups {
    param([object[]]$Findings)
    $map = @{}
    foreach ($f in @($Findings | Where-Object { ([string]$_.risk_level) -ne "INFO" })) {
        $key = Get-RootCauseKey -Finding $f
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [pscustomobject]@{
                root_id=$key; risk_level=[string]$f.risk_level; risk_rank=(RiskRank -Risk ([string]$f.risk_level));
                file=[string]$f.file; file_name=[string]$f.file_name; first_line=[int]$f.line; line_reference=[string]$f.line_reference;
                rule_id=[string]$f.rule_id; intent=[string]$f.intent_evidence; chain_strength=[string]$f.behavior_chain_strength;
                signal_count=0; files_map=@{}; representative=$f
            }
        }
        $g = $map[$key]
        $g.signal_count = [int]$g.signal_count + 1
        $g.files_map[[string]$f.file] = $true
        $rr = RiskRank -Risk ([string]$f.risk_level)
        if (($rr -gt [int]$g.risk_rank) -or ([int]$f.risk_score -gt [int]$g.representative.risk_score)) {
            $g.risk_level = [string]$f.risk_level
            $g.risk_rank = $rr
            $g.representative = $f
            $g.first_line = [int]$f.line
            $g.line_reference = [string]$f.line_reference
            $g.chain_strength = [string]$f.behavior_chain_strength
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($kv in $map.GetEnumerator()) {
        $g = $kv.Value
        $rep = $g.representative
        $items.Add([pscustomobject]@{
            root_id=[string]$g.root_id; risk_level=[string]$g.risk_level; risk_rank=[int]$g.risk_rank;
            file=[string]$g.file; file_name=[string]$g.file_name; first_line=[int]$g.first_line; line_reference=[string]$g.line_reference;
            signal_count=[int]$g.signal_count; file_count=[int]$g.files_map.Count; rule_id=[string]$g.rule_id;
            intent=[string]$g.intent; chain_strength=[string]$g.chain_strength; anchor_id=[string]$rep.anchor_id;
            why_review=[string]$rep.why_not_critical; file_uri=[string]$rep.file_uri; vscode_uri=[string]$rep.vscode_uri
        }) | Out-Null
    }
    return @($items | Sort-Object @{Expression="risk_rank";Descending=$true}, @{Expression="signal_count";Descending=$true}, @{Expression="file";Descending=$false}, @{Expression="first_line";Descending=$false})
}

function Get-FalsePositiveClass {
    param([string[]]$ContextFlags)
    $c = ($ContextFlags -join "; ")
    if ($c -match "detector-rule-context") { return "Detector rule / security scanner config" }
    if ($c -match "docs/examples/tests|markdown/documentation") { return "Documentation, examples, tests, or markdown" }
    if ($c -match "placeholder-or-example|empty-secret-assignment") { return "Placeholder, sample, or empty assignment" }
    if ($c -match "lockfile/generated-context|generated/build-context") { return "Generated, lockfile, or build output" }
    if ($c -match "comment-line") { return "Comment-only context" }
    return "Active code or config"
}
function HasStrongBehaviorChain {
    param([string[]]$Tags)
    $t = ($Tags -join "; ")
    if (($t -match "Download intent") -and ($t -match "Execution intent") -and ($t -match "Persistence intent|Obfuscation")) { return $true }
    if (($t -match "Credential") -and ($t -match "Possible exfiltration")) { return $true }
    if (($t -match "Destructive") -and ($t -match "Obfuscation|Persistence")) { return $true }
    return $false
}

function Get-TextEvidenceLabel {
    param($Rule,[string]$Line,[string]$RelativePath)
    $ruleId = Get-RuleProp -Obj $Rule -Name "id" -Default "UNKNOWN_RULE"
    if ($ruleId -match "OPENAI|GITHUB|NPM|CLOUD|SECRET|PRIVATE|TOKEN") { return "Secret/token text signal" }
    if ($ruleId -match "DOWNLOAD|WEBREQUEST|CURL|WGET") { return "Download-command text signal" }
    if ($ruleId -match "ENCODED|INVOKE|EXEC|CHILD|SHELL") { return "Dynamic-execution text signal" }
    if ($ruleId -match "DEFENDER|TAMPER|PERMISSION|LOLBIN") { return "Security-setting or Windows command text signal" }
    if ($ruleId -match "GITHUB|VSCODE|AGENT|MCP|LIFECYCLE|NPM") { return "Workflow/configuration text signal" }
    return "General text signal"
}
function Test-ReducedContext {
    param([string[]]$ContextFlags)
    $c = ($ContextFlags -join "; ")
    return ($c -match "detector-rule-context|docs/examples/tests|markdown/documentation|placeholder-or-example|comment-line|empty-secret-assignment|lockfile/generated-context|generated/build-context")
}
function Test-ActiveHighRiskContext {
    param([string[]]$ContextFlags)
    return -not (Test-ReducedContext -ContextFlags $ContextFlags)
}
function Get-IntentEvidence {
    param([string[]]$Tags,[string[]]$ContextFlags,[string]$Line,[string]$RelativePath,[bool]$RealSecret,[bool]$StrongChain)
    $t = ($Tags -join "; ")
    $reduced = Test-ReducedContext -ContextFlags $ContextFlags
    $intent = "Review intent"
    $conf = "Low"
    $why = "Intent is inferred from text, context, behavior, and chain evidence. It is not a verdict."
    if ($reduced) {
        $intent = "Likely reference/example/detector intent"
        $conf = "Low"
        $why = "The signal appears in reduced context such as docs, tests, examples, placeholders, generated output, comments, or detector rules."
    } elseif ($RealSecret -and ($t -match "Possible exfiltration")) {
        $intent = "Possible credential exfiltration intent"
        $conf = "High"
        $why = "Credential-like evidence appears together with outbound transfer behavior."
    } elseif ($RealSecret -and (Test-PatternSafe -Text $Line -Pattern '(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY')) {
        $intent = "Real private key exposure intent"
        $conf = "High"
        $why = "A private-key boundary appears in active code/config context."
    } elseif ($RealSecret) {
        $intent = "Credential exposure intent"
        $conf = "Medium"
        $why = "A value looks like a real secret/token in active context, but no outbound exfiltration chain was confirmed."
    } elseif (($t -match "Download intent") -and ($t -match "Execution intent") -and ($t -match "Persistence intent|Obfuscation")) {
        $intent = "Download-execute-persistence intent"
        $conf = "High"
        $why = "Download, execution, and persistence/evasion signals appear together."
    } elseif (($t -match "Destructive") -and ($t -match "Persistence|Obfuscation")) {
        $intent = "Destructive or ransomware-like intent"
        $conf = "High"
        $why = "Destructive behavior appears with persistence or evasion signals."
    } elseif (($t -match "Security setting modification") -and ($t -match "Execution intent|Persistence intent|Obfuscation")) {
        $intent = "Security weakening plus execution intent"
        $conf = "Medium"
        $why = "Security-setting modification appears with execution, persistence, or evasion."
    } elseif (($t -match "Supply-chain") -and ($t -match "Download intent|Execution intent")) {
        $intent = "Supply-chain install execution intent"
        $conf = "Medium"
        $why = "Package/workflow install surface appears with download or execution behavior."
    } elseif ($t -match "CI/CD workflow surface") {
        $intent = "Build or CI workflow intent"
        $conf = "Low"
        $why = "The signal appears in workflow/build automation context; review before trusting automation."
    } elseif ($t -match "AI agent instruction surface") {
        $intent = "AI agent instruction/tooling intent"
        $conf = "Low"
        $why = "The signal appears in AI-agent/MCP/tool instruction surface; review tool permissions and prompts."
    } elseif ($t -match "Download intent") {
        $intent = "Download/setup intent"
        $conf = "Low"
        $why = "Download evidence is present, but no strong execution/persistence/exfiltration chain was confirmed."
    } elseif ($t -match "Execution intent") {
        $intent = "Execution/setup intent"
        $conf = "Low"
        $why = "Execution evidence is present, but no strong malicious chain was confirmed."
    }
    return [pscustomobject]@{intent=$intent; confidence=$conf; explanation=$why}
}
function Test-StrictRedGate {
    param([string]$RuleId,[string[]]$Tags,[string[]]$ContextFlags,[string]$Line,[bool]$RealSecret,[bool]$StrongChain,$Intent)
    $active = Test-ActiveHighRiskContext -ContextFlags $ContextFlags
    if (-not $active) { return [pscustomobject]@{pass=$false; reason="Reduced context detected; red gate blocked."} }
    $t = ($Tags -join "; ")
    if ($RealSecret -and ($t -match "Possible exfiltration")) { return [pscustomobject]@{pass=$true; reason="Real-secret evidence plus possible outbound transfer chain."} }
    if ($RealSecret -and (Test-PatternSafe -Text $Line -Pattern '(?i)^\s*-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----')) { return [pscustomobject]@{pass=$true; reason="Private-key boundary in active context."} }
    if (($t -match "Download intent") -and ($t -match "Execution intent") -and ($t -match "Persistence intent|Obfuscation")) { return [pscustomobject]@{pass=$true; reason="Download + execution + persistence/evasion chain."} }
    if (($t -match "Destructive") -and ($t -match "Persistence|Obfuscation")) { return [pscustomobject]@{pass=$true; reason="Destructive behavior plus persistence/evasion chain."} }
    return [pscustomobject]@{pass=$false; reason="Strict red gate requires real secret with exfiltration/private-key proof or strong behavior chain."}
}

function Test-WarningGate {
    param([string]$RuleId,[string[]]$Tags,[string[]]$ContextFlags,[string]$Line,[bool]$RealSecret,[bool]$StrongChain,$RedGate)
    if ($RedGate.pass) { return [pscustomobject]@{pass=$true; reason="Red gate passed; warning gate implicitly passed."} }
    $active = Test-ActiveHighRiskContext -ContextFlags $ContextFlags
    if (-not $active) { return [pscustomobject]@{pass=$false; reason="Reduced context detected; warning gate blocked."} }
    $t = ($Tags -join "; ")
    if ($RealSecret) { return [pscustomobject]@{pass=$true; reason="Real secret-like value in active context; no exfiltration chain confirmed."} }
    if ($RuleId -eq "DEFENDER_TAMPER") { return [pscustomobject]@{pass=$true; reason="Security/Defender setting modification in active context."} }
    if (($RuleId -match "PS_ENCODED_COMMAND|PS_INVOKE_EXPRESSION") -and ($t -match "Execution intent|Obfuscation")) { return [pscustomobject]@{pass=$true; reason="Dynamic execution or obfuscation in active context."} }
    if (($RuleId -eq "DOWNLOAD_AND_RUN") -and ($t -match "Download intent") -and ($t -match "Execution intent")) { return [pscustomobject]@{pass=$true; reason="Download plus execution pattern in active context."} }
    if (($RuleId -eq "DESTRUCTIVE_REMOVE") -and ($t -match "Destructive")) { return [pscustomobject]@{pass=$true; reason="Destructive file operation signal in active context."} }
    if (($t -match "Security setting modification") -and ($t -match "Execution intent|Persistence intent|Obfuscation")) { return [pscustomobject]@{pass=$true; reason="Security modification combined with execution/persistence/evasion."} }
    if (($t -match "Download intent") -and ($t -match "Execution intent") -and ($t -match "Supply-chain")) { return [pscustomobject]@{pass=$true; reason="Supply-chain surface with download/execution behavior."} }
    return [pscustomobject]@{pass=$false; reason="Warning gate requires active-context evidence such as real secret, dynamic execution, security modification, destructive action, or download+execute chain."}
}
function New-FileUri {
    param([string]$Path)
    try { return ([System.Uri]::new((Resolve-Path -LiteralPath $Path).Path)).AbsoluteUri } catch { return "" }
}
function New-VSCodeUri {
    param([string]$Path,[int]$Line)
    try {
        $p = (Resolve-Path -LiteralPath $Path).Path -replace '\\','/'
        $enc = [System.Uri]::EscapeUriString($p)
        return "vscode://file/$enc`:$Line"
    } catch { return "" }
}
function New-FindingAnchorId {
    param([string]$RelativePath,[int]$Line,[string]$RuleId)
    return "finding-" + (StringSha256 -Text ("$RelativePath|$Line|$RuleId")).Substring(0,12)
}
function MaxRisk {
    param([string]$Risk,[string]$Ceiling)
    if ((RiskRank -Risk $Risk) -gt (RiskRank -Risk $Ceiling)) { return $Ceiling }
    return $Risk
}
function Get-ScanModeTrustNote {
    param([string]$Mode)
    if ($Mode -eq "Deep") { return "Full Deep Scan is the broadest and slowest mode. Use it for exhaustive research review, not routine pre-open checks. It is still not a malware verdict." }
    if ($Mode -eq "SmartDeep") { return "Smart Deep Scan is the recommended detailed mode. It uses staged prefiltering and behavior-context review to reduce false positives while avoiding a heavy pass over every low-signal file." }
    return "Quick Scan is a fast preliminary pre-open review. It may show more warnings because it prioritizes speed and early warning. Run Smart Deep Scan before final judgment."
}
function TrustFields {
    param($Rule,[string]$Line,[string]$RelativePath)
    $risk = (Get-RuleProp -Obj $Rule -Name "riskLevel" -Default "REVIEW").ToUpperInvariant()
    $confidence = Get-RuleProp -Obj $Rule -Name "confidence" -Default "Low"
    $ruleId = Get-RuleProp -Obj $Rule -Name "id" -Default "UNKNOWN_RULE"
    $category = Get-RuleProp -Obj $Rule -Name "category" -Default "General"
    $severity = Get-RuleProp -Obj $Rule -Name "severity" -Default "Low"
    $ev = ComputeEvidence -Rule $Rule -Line $Line -RelativePath $RelativePath
    $tags = @(Get-BehaviorTags -Rule $Rule -Line $Line -RelativePath $RelativePath)
    $ctx = @(Get-ContextFlags -Line $Line -RelativePath $RelativePath)
    $ctxText = ($ctx -join "; ")
    $fpClass = Get-FalsePositiveClass -ContextFlags $ctx
    $realSecret = IsLikelyRealSecret -Line $Line -RelativePath $RelativePath
    $strongChain = HasStrongBehaviorChain -Tags $tags
    $intent = Get-IntentEvidence -Tags $tags -ContextFlags $ctx -Line $Line -RelativePath $RelativePath -RealSecret $realSecret -StrongChain $strongChain
    $textEvidence = Get-TextEvidenceLabel -Rule $Rule -Line $Line -RelativePath $RelativePath
    $redGate = Test-StrictRedGate -RuleId $ruleId -Tags $tags -ContextFlags $ctx -Line $Line -RealSecret $realSecret -StrongChain $strongChain -Intent $intent

    # v0.6.0 evidence fusion: text evidence and rule severity are raw evidence, not verdicts.
    # Start from computed evidence. Promotion to WARNING/CRITICAL must pass calibrated gates below.
    $finalRisk = [string]$ev.engine_risk
    if ((RiskRank -Risk $finalRisk) -lt 2) { $finalRisk = "REVIEW" }
    $warningGate = Test-WarningGate -RuleId $ruleId -Tags $tags -ContextFlags $ctx -Line $Line -RealSecret $realSecret -StrongChain $strongChain -RedGate $redGate

    # Secrets: only private-key proof or secret+exfiltration should become CRITICAL. Plain token-like values without chain are WARNING.
    if ($ruleId -match "OPENAI_KEY_PATTERN|GITHUB_TOKEN_PATTERN|NPM_TOKEN_PATTERN|CLOUD_SECRET_PATTERN") {
        if ($redGate.pass) { $finalRisk = "CRITICAL"; $confidence = "High" }
        elseif ($realSecret) { $finalRisk = "WARNING"; $confidence = "Medium" }
        else { $finalRisk = "REVIEW"; $confidence = "Low" }
    }
    if ($ruleId -eq "GENERIC_SECRET_WORD") {
        if ($redGate.pass) { $finalRisk = "CRITICAL"; $confidence = "High" }
        elseif ($realSecret) { $finalRisk = "WARNING"; $confidence = "Medium" }
        else { $finalRisk = "INFO"; $confidence = "Low" }
    }

    # Common developer surfaces are REVIEW unless supported by an actual behavior chain.
    if (($ruleId -match "GITHUB_ACTION_RISK|VSCODE_TASKS|AI_AGENT_CONFIG|NPM_LIFECYCLE_SCRIPT|WINDOWS_LOLBINS|NODE_CHILD_PROCESS|PYTHON_SHELL_EXEC|PERMISSION_TAKEOVER") -and (-not $redGate.pass)) {
        if ((RiskRank -Risk $finalRisk) -gt 2) { $finalRisk = "REVIEW" }
    }
    if ($ruleId -eq "DEFENDER_TAMPER") {
        if ($redGate.pass) { $finalRisk = "CRITICAL"; $confidence = "High" }
        elseif (Test-PatternSafe -Text $RelativePath -Pattern '(?i)(^|[\/])\.github[\/]workflows[\/].+\.(yml|yaml)$') { $finalRisk = "WARNING"; $confidence = "Medium" }
        else { $finalRisk = "WARNING"; if ((ConfidenceRank -C $confidence) -lt 2) { $confidence = "Medium" } }
    }
    if (($ruleId -eq "DOWNLOAD_AND_RUN") -and (-not $redGate.pass)) { $finalRisk = "WARNING" }
    if (($ruleId -match "PS_ENCODED_COMMAND|PS_INVOKE_EXPRESSION") -and (-not $strongChain)) { $finalRisk = MaxRisk -Risk $finalRisk -Ceiling "WARNING" }

    # Context ceilings reduce false positives.
    if ($ctxText -match "detector-rule-context") { $finalRisk = MaxRisk -Risk $finalRisk -Ceiling "INFO"; $confidence = "Low" }
    elseif ($ctxText -match "docs/examples/tests|markdown/documentation|placeholder-or-example|comment-line|empty-secret-assignment") { $finalRisk = MaxRisk -Risk $finalRisk -Ceiling "REVIEW"; if ((ConfidenceRank -C $confidence) -gt 1) { $confidence = "Low" } }
    elseif ($ctxText -match "lockfile/generated-context|generated/build-context") { $finalRisk = MaxRisk -Risk $finalRisk -Ceiling "REVIEW" }

    # Strict red gate: after all context checks, CRITICAL requires proof.
    if (($finalRisk -eq "CRITICAL") -and (-not $redGate.pass)) { $finalRisk = "WARNING" }
    # Strict warning gate: WARNING also needs meaningful active-context evidence.
    # Otherwise downgrade to REVIEW so Quick Scan does not create reputation-damaging high-risk counts from weak signals.
    if (($finalRisk -eq "WARNING") -and (-not $warningGate.pass)) { $finalRisk = "REVIEW"; if ((ConfidenceRank -C $confidence) -gt 1) { $confidence = "Low" } }
    $finalConfidence = HigherConfidence -A $confidence -B $ev.engine_confidence
    if ((-not $redGate.pass) -and ($finalConfidence -eq "High")) { $finalConfidence = "Medium" }
    if (($ctxText -match "docs/examples/tests|markdown/documentation|detector-rule-context|placeholder-or-example|comment-line|empty-secret-assignment") -and ($finalConfidence -ne "Low")) { $finalConfidence = "Low" }

    $whyNotCritical = ""
    if ($finalRisk -ne "CRITICAL") {
        $whyNotCritical = "Strict red gate not satisfied. "
        if (-not $realSecret) { $whyNotCritical += "No real secret/private key confirmed. " }
        if (-not $strongChain) { $whyNotCritical += "No strong chained behavior confirmed. " }
        if ($fpClass -ne "Active code or config") { $whyNotCritical += "Context reduced: $fpClass. " }
        $whyNotCritical += "Red-gate reason: $($redGate.reason). Warning-gate reason: $($warningGate.reason)"
    }
    $chainStrength = "Single signal"
    if ($strongChain) { $chainStrength = "Strong behavior chain" }
    elseif ($tags.Count -ge 3) { $chainStrength = "Multiple related signals" }
    elseif ($tags.Count -eq 2) { $chainStrength = "Two-signal context" }
    $score = [int]((RiskRank -Risk $finalRisk) * 10 + $ev.evidence_total)
    return [pscustomobject]@{
        risk_level = $finalRisk; confidence = $finalConfidence; risk_score = $score; rule_id = $ruleId; category = $category; severity = $severity;
        why_flagged = (Get-RuleProp -Obj $Rule -Name "whyFlagged" -Default "Pattern requires context review before running.");
        false_positive_note = (Get-RuleProp -Obj $Rule -Name "falsePositiveNote" -Default "This signal may be legitimate. It is not a malware verdict.");
        suggested_action = (Get-RuleProp -Obj $Rule -Name "recommendation" -Default "Review file and context before running.");
        engine_version = $ev.engine_version; base_score = $ev.base_score; trigger_score = $ev.trigger_score; impact_score = $ev.impact_score; density_score = $ev.density_score; context_correction = $ev.context_correction; evidence_total = $ev.evidence_total; engine_risk = $ev.engine_risk; engine_confidence = $ev.engine_confidence; engine_explain = $ev.engine_explain;
        false_positive_class=$fpClass; why_not_critical=$whyNotCritical; behavior_chain_strength=$chainStrength; accuracy_calibration="v0.6.0 evidence fusion + intent + strict red/warning gates";
        text_evidence=$textEvidence; intent_evidence=[string]$intent.intent; intent_confidence=[string]$intent.confidence; intent_explanation=[string]$intent.explanation; strict_red_gate=[bool]$redGate.pass; strict_red_reason=[string]$redGate.reason; strict_warning_gate=[bool]$warningGate.pass; strict_warning_reason=[string]$warningGate.reason
    }
}

function ConvertTo-StableRegex {
    param([string]$Pattern)
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $null }
    $p = [Regex]::Escape($Pattern.Trim().Replace('\','/'))
    $p = $p.Replace("\*", ".*")
    return "^$p$"
}
function New-FindingFingerprint {
    param($Finding)
    $raw = (([string]$Finding.file).ToLowerInvariant() + "|" + ([string]$Finding.rule_id).ToLowerInvariant() + "|" + ([string]$Finding.preview).Trim().ToLowerInvariant())
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace("-","").ToLowerInvariant()
    } catch { return ([Math]::Abs($raw.GetHashCode())).ToString() }
}
function Load-TrustPolicy {
    param([string]$Root,[string]$ExplicitTrustFile)
    $path = $ExplicitTrustFile
    if ([string]::IsNullOrWhiteSpace($path)) { $path = Join-Path $Root ".waibon-trust.json" }
    $policy = [pscustomobject]@{ path=$path; loaded=$false; trusted_files=@(); trusted_rules=@(); trusted_pairs=@(); trusted_fingerprints=@(); notes="" }
    if (Test-Path -LiteralPath $path) {
        try {
            $doc = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            $policy.loaded = $true
            $policy.trusted_files = @($doc.trusted_files)
            $policy.trusted_rules = @($doc.trusted_rules)
            $policy.trusted_pairs = @($doc.trusted_pairs)
            $policy.trusted_fingerprints = @($doc.trusted_fingerprints)
            $policy.notes = [string]$doc.notes
        } catch { }
    }
    return $policy
}
function Test-TrustMatch {
    param($Finding,$TrustPolicy)
    if (-not $TrustPolicy.loaded) { return $null }
    $file = ([string]$Finding.file).Replace('\','/')
    $rule = [string]$Finding.rule_id
    $fp = [string]$Finding.fingerprint
    foreach ($x in @($TrustPolicy.trusted_fingerprints)) { if (-not [string]::IsNullOrWhiteSpace($x) -and $fp -eq [string]$x) { return "trusted fingerprint" } }
    foreach ($r in @($TrustPolicy.trusted_rules)) { if (-not [string]::IsNullOrWhiteSpace($r) -and $rule -ieq [string]$r) { return "trusted rule" } }
    foreach ($p in @($TrustPolicy.trusted_files)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $pat = ([string]$p).Replace('\','/')
        if ($pat.EndsWith("/")) { if ($file.ToLowerInvariant().StartsWith($pat.ToLowerInvariant())) { return "trusted path prefix" } }
        elseif ($pat.Contains("*")) { $rx = ConvertTo-StableRegex $pat; if ($rx -and ($file -match $rx)) { return "trusted file pattern" } }
        elseif ($file -ieq $pat) { return "trusted file" }
    }
    foreach ($pair in @($TrustPolicy.trusted_pairs)) {
        $pf = ([string]$pair.file).Replace('\','/')
        $pr = [string]$pair.rule_id
        if ((-not [string]::IsNullOrWhiteSpace($pf)) -and (-not [string]::IsNullOrWhiteSpace($pr))) {
            $fileOk = $false
            if ($pf.Contains("*")) { $rx = ConvertTo-StableRegex $pf; if ($rx -and ($file -match $rx)) { $fileOk = $true } }
            elseif ($pf.EndsWith("/")) { if ($file.ToLowerInvariant().StartsWith($pf.ToLowerInvariant())) { $fileOk = $true } }
            elseif ($file -ieq $pf) { $fileOk = $true }
            if ($fileOk -and ($rule -ieq $pr)) { return "trusted file+rule" }
        }
    }
    return $null
}
function Apply-TrustBaseline {
    param([object[]]$Findings,$TrustPolicy)
    $trusted = 0
    foreach ($f in @($Findings)) {
        $fp = New-FindingFingerprint -Finding $f
        Add-Member -InputObject $f -NotePropertyName fingerprint -NotePropertyValue $fp -Force
        Add-Member -InputObject $f -NotePropertyName trusted -NotePropertyValue $false -Force
        Add-Member -InputObject $f -NotePropertyName trust_reason -NotePropertyValue "" -Force
        $reason = Test-TrustMatch -Finding $f -TrustPolicy $TrustPolicy
        if ($reason) {
            $trusted++
            $original = [string]$f.risk_level
            $f.trusted = $true
            $f.trust_reason = $reason
            $f.risk_level = "INFO"
            $f.confidence = "Low"
            $f.risk_score = 1
            $f.false_positive_class = (([string]$f.false_positive_class) + "; local trust baseline").Trim(';',' ')
            $f.why_not_critical = (([string]$f.why_not_critical) + " Local trust baseline reduced prior risk ($original) to INFO for this repository only.").Trim()
            $f.accuracy_calibration = "v0.6.0 trust workflow applied"
        }
    }
    return $trusted
}
function Load-PreviousScanIndex {
    param([string]$ReportsDir)
    $path = Join-Path $ReportsDir "last-scan-fingerprints.json"
    $map = @{}
    if (Test-Path -LiteralPath $path) {
        try {
            $doc = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($x in @($doc.findings)) { if ($x.fingerprint) { $map[[string]$x.fingerprint] = $x } }
        } catch { }
    }
    return $map
}
function Save-CurrentScanIndex {
    param([string]$ReportsDir,[object[]]$Findings,[string]$Version,[string]$Target,[string]$ScanMode)
    $path = Join-Path $ReportsDir "last-scan-fingerprints.json"
    $items = @()
    foreach ($f in @($Findings)) { $items += [pscustomobject]@{fingerprint=$f.fingerprint; file=$f.file; line=$f.line; rule_id=$f.rule_id; risk_level=$f.risk_level; trusted=$f.trusted; preview=$f.preview} }
    [pscustomobject]@{tool="Waibon Dev Shield"; version=$Version; generated=(Get-Date).ToString("o"); target=$Target; scan_mode=$ScanMode; findings=$items} | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}
function Build-ReportDiff {
    param([object[]]$Findings,$PrevMap)
    $new=0; $unchanged=0; $riskUp=0; $riskDown=0
    $current = @{}
    foreach ($f in @($Findings)) {
        $fp = [string]$f.fingerprint
        if ([string]::IsNullOrWhiteSpace($fp)) { continue }
        $current[$fp]=$true
        if ($PrevMap.ContainsKey($fp)) {
            $unchanged++
            $oldRisk = [string]$PrevMap[$fp].risk_level
            $newRisk = [string]$f.risk_level
            if ((RiskRank -Risk $newRisk) -gt (RiskRank -Risk $oldRisk)) { $riskUp++ }
            elseif ((RiskRank -Risk $newRisk) -lt (RiskRank -Risk $oldRisk)) { $riskDown++ }
        } else { $new++ }
    }
    $resolved = 0
    foreach ($k in $PrevMap.Keys) { if (-not $current.ContainsKey($k)) { $resolved++ } }
    return [pscustomobject]@{new_findings=$new; unchanged_findings=$unchanged; resolved_findings=$resolved; risk_increased=$riskUp; risk_reduced=$riskDown; previous_count=$PrevMap.Count; current_count=$Findings.Count}
}

function ScanProfile {
    param([string]$Mode,$RulesDoc)
    $baseSkip = @($RulesDoc.settings.skipDirectories)
    $deepSkip = @($baseSkip + @("out","target","bin","obj","tmp","temp","logs","coverage","reports",".waibon-cache")) | Select-Object -Unique
    $quickSkip = @($deepSkip + @("dist-runtime","runtime-dist","release","releases","generated","public","static","assets","images","media","uploads","downloads","storybook-static",".vite",".turbo",".parcel-cache",".sass-cache")) | Select-Object -Unique
    $smartSkip = @($deepSkip + @("dist-runtime","runtime-dist","release","releases","generated","public","static","assets","images","media","uploads","downloads","storybook-static",".vite",".turbo",".parcel-cache",".sass-cache","docs-output","site","storybook")) | Select-Object -Unique
    $quickExt = @(".ps1",".psm1",".psd1",".bat",".cmd",".vbs",".sh",".env",".toml",".yml",".yaml",".json")
    $smartExt = @(".ps1",".psm1",".psd1",".bat",".cmd",".vbs",".sh",".env",".toml",".yml",".yaml",".json",".js",".jsx",".ts",".tsx",".py")
    $quickNames = @("package.json","package-lock.json","npm-shrinkwrap.json","pnpm-lock.yaml","yarn.lock",".npmrc","binding.gyp","requirements.txt","pyproject.toml","setup.py","setup.cfg","Pipfile","Pipfile.lock","poetry.lock","composer.json","composer.lock","Dockerfile","docker-compose.yml","docker-compose.yaml","Makefile","mcp.json",".mcp.json","AGENTS.md","CLAUDE.md","GEMINI.md","copilot-instructions.md",".env",".env.local",".env.production",".env.development",".env.example",".env.sample","tasks.json","settings.json","launch.json","pre-commit-config.yaml","lefthook.yml","lefthook.yaml")
    if ($Mode -eq "Secrets") {
        return [pscustomobject]@{Name="Secrets"; Description="Secret & Token Scan - focused review for credentials, private keys, .env files, and token-like patterns."; SkipDirs=$smartSkip; IncludeExtensions=@(".env",".json",".yml",".yaml",".toml",".ini",".txt",".md",".js",".ts",".py",".ps1"); IncludeFileNames=@(".env",".env.local",".env.production",".env.example",".npmrc","package.json","pre-commit-config.yaml","settings.json","mcp.json",".mcp.json"); DefaultMaxFileSizeMB=3; BatchSize=400; ProgressIntervalSec=4; SmartPrefilter=$true; FullScope=$false}
    }
    if ($Mode -eq "SupplyChain") {
        return [pscustomobject]@{Name="SupplyChain"; Description="Supply-chain Scan - focused review for package hooks, CI/CD workflows, install surfaces, publish and dependency risk."; SkipDirs=$smartSkip; IncludeExtensions=@(".json",".yml",".yaml",".toml",".lock",".js",".ts",".py",".ps1",".sh",".cmd",".bat"); IncludeFileNames=@("package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","npm-shrinkwrap.json","binding.gyp","requirements.txt","pyproject.toml","setup.py","setup.cfg","Pipfile","Pipfile.lock","poetry.lock","composer.json","composer.lock","Dockerfile","docker-compose.yml","docker-compose.yaml","Makefile","pre-commit-config.yaml","lefthook.yml","lefthook.yaml"); DefaultMaxFileSizeMB=4; BatchSize=400; ProgressIntervalSec=4; SmartPrefilter=$true; FullScope=$false}
    }
    if ($Mode -eq "AgentMcp") {
        return [pscustomobject]@{Name="AgentMcp"; Description="AI Agent / MCP Scan - focused review for AI agent instruction files, MCP configs, tool permission surfaces, and prompt/tool misuse signals."; SkipDirs=$smartSkip; IncludeExtensions=@(".md",".json",".yml",".yaml",".toml",".txt"); IncludeFileNames=@("AGENTS.md","CLAUDE.md","GEMINI.md","copilot-instructions.md","mcp.json",".mcp.json","tasks.json","settings.json","launch.json"); DefaultMaxFileSizeMB=3; BatchSize=400; ProgressIntervalSec=4; SmartPrefilter=$true; FullScope=$false}
    }
    if ($Mode -eq "Deep") {
        return [pscustomobject]@{Name="Deep"; Description="Full Deep Scan - exhaustive broader text/code review. Slowest mode; intended for final research review."; SkipDirs=$deepSkip; IncludeExtensions=@($RulesDoc.settings.includeExtensions); IncludeFileNames=@($RulesDoc.settings.includeFileNames + $quickNames | Select-Object -Unique); DefaultMaxFileSizeMB=5; BatchSize=300; ProgressIntervalSec=5; SmartPrefilter=$true; FullScope=$true}
    }
    if ($Mode -eq "SmartDeep") {
        return [pscustomobject]@{Name="SmartDeep"; Description="Smart Deep Scan - recommended detailed behavior/context review. Uses strong prefilter and focused deep scan to reduce false positives without scanning every low-signal file heavily."; SkipDirs=$smartSkip; IncludeExtensions=$smartExt; IncludeFileNames=$quickNames; DefaultMaxFileSizeMB=4; BatchSize=300; ProgressIntervalSec=4; SmartPrefilter=$true; FullScope=$false}
    }
    return [pscustomobject]@{Name="Quick"; Description="Quick Scan - fast pre-open scan for high-risk project entry points, configs, scripts, secrets, CI, and AI-agent files."; SkipDirs=$quickSkip; IncludeExtensions=$quickExt; IncludeFileNames=$quickNames; DefaultMaxFileSizeMB=2; BatchSize=200; ProgressIntervalSec=3; SmartPrefilter=$true; FullScope=$false}
}
function Build-Set {
    param([object[]]$Items)
    $h = @{}
    foreach ($x in @($Items)) { if ($null -ne $x) { $h[[string]$x.ToLowerInvariant()] = $true } }
    return $h
}
function IncludedFile {
    param([System.IO.FileInfo]$File,$ExtSet,$NameSet)
    $name = $File.Name.ToLowerInvariant()
    if ($NameSet.ContainsKey($name)) { return $true }
    $ext = $File.Extension.ToLowerInvariant()
    if ($ExtSet.ContainsKey($ext)) { return $true }
    return $false
}
function CollectFiles {
    param([string]$Root,[string[]]$Skip,[string[]]$Exts,[string[]]$Names,[int64]$MaxBytes)
    $list = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $stats = [ordered]@{VisitedDirectories=0; EnumeratedFiles=0; SkippedFiles=0; ReadErrors=0}
    $skipSet = Build-Set -Items $Skip
    $extSet = Build-Set -Items $Exts
    $nameSet = Build-Set -Items $Names
    $stack = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $stack.Push((Get-Item -LiteralPath $Root))
    Wds-Status "Step 2/4: Collecting candidate files..." "SCAN"
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop(); $stats.VisitedDirectories++
        try { $dirs = $dir.GetDirectories() } catch { $stats.ReadErrors++; continue }
        foreach ($d in $dirs) { if (-not $skipSet.ContainsKey($d.Name.ToLowerInvariant())) { $stack.Push($d) } }
        try { $files = $dir.GetFiles() } catch { $stats.ReadErrors++; continue }
        foreach ($f in $files) {
            $stats.EnumeratedFiles++
            if (-not (IncludedFile -File $f -ExtSet $extSet -NameSet $nameSet)) { $stats.SkippedFiles++; continue }
            if ($f.Length -gt $MaxBytes) { $stats.SkippedFiles++; continue }
            $list.Add($f) | Out-Null
        }
        if ((-not $QuietProgress) -and (($stats.VisitedDirectories % 250) -eq 0)) {
            Wds-Status ("Collecting... dirs={0} files={1} candidates={2}" -f $stats.VisitedDirectories,$stats.EnumeratedFiles,$list.Count) "SCAN"
        }
    }
    return [pscustomobject]@{Files=$list; Stats=[pscustomobject]$stats}
}
function ProgressLine {
    param([int]$Percent,[int]$Current,[int]$Total,[string]$CurrentFile)
    if ($QuietProgress) { return }
    if ($Percent -lt 0) { $Percent = 0 }; if ($Percent -gt 100) { $Percent = 100 }
    $width = 24
    $filled = [int][math]::Floor(($Percent / 100.0) * $width)
    if ($filled -lt 0) { $filled = 0 }; if ($filled -gt $width) { $filled = $width }
    $bar = ("#" * $filled) + ("-" * ($width - $filled))
    $elapsedText = ""; $etaText = ""
    try {
        if ($script:ScanStartTime) {
            $elapsed = New-TimeSpan -Start $script:ScanStartTime -End (Get-Date)
            $elapsedText = " elapsed=" + ("{0:mm\:ss}" -f $elapsed)
            if (($Current -gt 0) -and ($Total -gt $Current) -and ($elapsed.TotalSeconds -gt 0)) {
                $rate = [double]$Current / [double]$elapsed.TotalSeconds
                if ($rate -gt 0) {
                    $remainingSec = [int](($Total - $Current) / $rate)
                    $etaText = " eta~" + ([TimeSpan]::FromSeconds($remainingSec).ToString("hh\:mm\:ss"))
                }
            }
        }
    } catch {}
    Write-Host ("[SCAN] {0,3}% [{1}] {2}/{3}{4}{5} {6}" -f $Percent,$bar,$Current,$Total,$elapsedText,$etaText,(ShortPath -Text $CurrentFile -MaxLength 80))
}
function ReadTextLinesSafe {
    param([string]$Path)
    try { return @(Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop) }
    catch {
        try { return @(Get-Content -LiteralPath $Path -ErrorAction Stop) }
        catch { throw }
    }
}

function ReadTextRawSafe {
    param([string]$Path)
    try { return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) }
    catch {
        try { return [System.IO.File]::ReadAllText($Path) }
        catch { throw }
    }
}
function SplitLinesFast {
    param([string]$Text)
    if ($null -eq $Text) { return @() }
    return @(([string]$Text).Replace("`r`n","`n").Replace("`r","`n").Split([char]10))
}
function Test-FastPrefilterHit {
    param([string]$Text,[string]$RelativePath,[string]$Mode)
    $hay = (([string]$RelativePath) + "`n" + ([string]$Text)).ToLowerInvariant()
    $strong = @(
        'invoke-webrequest','invoke-restmethod','encodedcommand','frombase64string','invoke-expression','iex ',
        'curl ','curl.exe','wget','start-process','child_process','execsync','spawn(','subprocess','os.system','eval(','exec(',
        'set-mppreference','add-mppreference','disablerealtimemonitoring','exclusionpath','exclusionprocess',
        'remove-item','rmdir /s','rd /s','del /s','cipher /w','vssadmin','shadowcopy','bcdedit',
        'schtasks','runonce','currentversion\run','startup','appdata','programdata',
        'openai_api_key','github_token','gh_token','npm_token','aws_secret_access_key','azure_client_secret','supabase_service_role_key',
        'database_url','private_key','begin private key','password','secret','api_key','api-key','token',
        'postinstall','preinstall','prepare','binding.gyp','mcpservers','servercommand','systemprompt','tool_call',
        'agents.md','claude.md','gemini.md','codex','cursor','secrets.','permissions:','uses:','run:'
    )
    foreach ($k in $strong) { if ($hay.Contains($k)) { return $true } }
    if ($Mode -eq 'Quick') { return $false }
    if ($Mode -eq 'SmartDeep') {
        $smartWeak = @("http://","https://","powershell","pwsh","cmd.exe","bash","sh ","workflow","github actions","private key","credential","secret","token","npm publish","pip install")
        foreach ($k in $smartWeak) { if ($hay.Contains($k)) { return $true } }
        return $false
    }
    $deep = @('download','upload','webhook','http://','https://','private key','credential','npm publish','pip install','docker login','github actions','workflow','powershell','pwsh','cmd.exe','bash','sh ')
    foreach ($k in $deep) { if ($hay.Contains($k)) { return $true } }
    return $false
}
function ProgressLine2 {
    param([int]$Percent,[int]$Current,[int]$Total,[string]$Stage,[string]$CurrentFile,[int]$PrefilterSkipped=0,[int]$FastHits=0)
    if ($QuietProgress) { return }
    if ($Percent -lt 0) { $Percent = 0 }; if ($Percent -gt 100) { $Percent = 100 }
    $width = 24
    $filled = [int][math]::Floor(($Percent / 100.0) * $width)
    if ($filled -lt 0) { $filled = 0 }; if ($filled -gt $width) { $filled = $width }
    $bar = ("#" * $filled) + ("-" * ($width - $filled))
    $elapsedText = ""; $etaText = ""; $rateText = ""
    try {
        if ($script:ScanStartTime) {
            $elapsed = New-TimeSpan -Start $script:ScanStartTime -End (Get-Date)
            $elapsedText = " elapsed=" + ("{0:hh\:mm\:ss}" -f $elapsed)
            if (($Current -gt 0) -and ($elapsed.TotalSeconds -gt 0)) {
                $rate = [double]$Current / [double]$elapsed.TotalSeconds
                $rateText = " rate=" + ([math]::Round($rate,1)) + "/s"
                if (($Total -gt $Current) -and ($rate -gt 0)) {
                    $remainingSec = [int](($Total - $Current) / $rate)
                    $etaText = " eta~" + ([TimeSpan]::FromSeconds($remainingSec).ToString("hh\:mm\:ss"))
                }
            }
        }
    } catch {}
    Write-Host ("[SCAN] {0,3}% [{1}] {2}/{3}{4}{5}{6} stage={7} skip={8} hit={9} file={10}" -f $Percent,$bar,$Current,$Total,$elapsedText,$etaText,$rateText,$Stage,$PrefilterSkipped,$FastHits,(ShortPath -Text $CurrentFile -MaxLength 64))
}

function NewHtmlReport {
    param([string]$Path,$Summary,[object[]]$Findings,[int]$MaxItems)
    $rows = New-Object System.Collections.Generic.List[string]
    $idx = 1
    foreach ($f in @($Findings | Select-Object -First $MaxItems)) {
        $cls = "risk-" + ([string]$f.risk_level).ToLowerInvariant()
        $anchor = [string]$f.anchor_id; if ([string]::IsNullOrWhiteSpace($anchor)) { $anchor = "finding-$idx" }
        $fileLink = ""; if (-not [string]::IsNullOrWhiteSpace([string]$f.file_uri)) { $fileLink = "<a class='link' href='$(HtmlSafe $f.file_uri)'>Open file</a>" }
        $vsLink = ""; if (-not [string]::IsNullOrWhiteSpace([string]$f.vscode_uri)) { $vsLink = "<a class='link' href='$(HtmlSafe $f.vscode_uri)'>Open in VS Code</a>" }
        $row = "<tr id='$(HtmlSafe $anchor)'><td class='num'>$idx</td><td><span class='pill $cls'>$(HtmlSafe $f.risk_level)</span><br><span class='muted'>$(HtmlSafe $f.confidence)</span></td><td><strong>$($f.evidence_total)</strong><br><span class='muted'>Base $($f.base_score) / Trigger $($f.trigger_score) / Impact $($f.impact_score) / Density $($f.density_score) / Correction $($f.context_correction)</span><br><span class='muted'><strong>Strict red gate:</strong> $(HtmlSafe $f.strict_red_gate)</span><br><span class='muted'><strong>Strict warning gate:</strong> $(HtmlSafe $f.strict_warning_gate)</span></td><td><strong>$(HtmlSafe $f.rule_id)</strong><br><span class='muted'>$(HtmlSafe $f.category)</span><br><span class='muted'>$(HtmlSafe $f.text_evidence)</span></td><td><strong>$(HtmlSafe $f.file_name)</strong><br><code>$(HtmlSafe $f.line_reference)</code><br><span class='muted'>Full path:</span><br><code>$(HtmlSafe $f.full_path)</code><br>$fileLink $vsLink</td><td><code>$(HtmlSafe $f.preview)</code></td><td><strong>Intent:</strong> $(HtmlSafe $f.intent_evidence) <span class='muted'>($(HtmlSafe $f.intent_confidence))</span><br><span class='muted'>$(HtmlSafe $f.intent_explanation)</span><br><br><strong>Behavior:</strong> $(HtmlSafe $f.behavior_tags)<br><span class='muted'><strong>Context:</strong> $(HtmlSafe $f.context_flags)</span><br><span class='muted'><strong>Interpretation:</strong> $(HtmlSafe $f.behavior_interpretation)</span><br><span class='muted'><strong>Missing evidence:</strong> $(HtmlSafe $f.missing_evidence)</span><br><span class='muted'><strong>Why not critical:</strong> $(HtmlSafe $f.why_not_critical)</span><br><span class='muted'><strong>False-positive class:</strong> $(HtmlSafe $f.false_positive_class)</span><br><span class='muted'><strong>Chain strength:</strong> $(HtmlSafe $f.behavior_chain_strength)</span><br><span class='muted'><strong>Red-gate reason:</strong> $(HtmlSafe $f.strict_red_reason)</span><br><span class='muted'><strong>Warning-gate reason:</strong> $(HtmlSafe $f.strict_warning_reason)</span><br><br><strong>Next:</strong> $(HtmlSafe $f.suggested_action)</td></tr>"
        $rows.Add($row) | Out-Null
        $idx++
    }
    if ($Findings.Count -eq 0) { $rows.Add("<tr><td colspan='7' class='empty'>No suspicious pattern found by current rules.</td></tr>") | Out-Null }
    $behaviorRows = New-Object System.Collections.Generic.List[string]
    foreach ($b in @($Summary.behavior_summary)) { $behaviorRows.Add("<tr><td>$(HtmlSafe $b.behavior)</td><td class='num'>$($b.findings)</td><td class='num'>$($b.files)</td></tr>") | Out-Null }
    if ($behaviorRows.Count -eq 0) { $behaviorRows.Add("<tr><td colspan='3' class='empty'>No behavior group detected by current rules.</td></tr>") | Out-Null }
    $rootRows = New-Object System.Collections.Generic.List[string]
    foreach ($rc in @($Summary.root_cause_summary | Select-Object -First 25)) {
        $rcls = "risk-" + ([string]$rc.risk_level).ToLowerInvariant()
        $rootRows.Add("<tr><td><span class='pill $rcls'>$(HtmlSafe $rc.risk_level)</span></td><td>$(HtmlSafe $rc.intent)</td><td><strong>$(HtmlSafe $rc.file_name)</strong><br><code>$(HtmlSafe $rc.line_reference)</code></td><td class='num'>$(HtmlSafe $rc.signal_count)</td><td><span class='muted'>$(HtmlSafe $rc.chain_strength)</span></td></tr>") | Out-Null
    }
    if ($rootRows.Count -eq 0) { $rootRows.Add("<tr><td colspan='5' class='empty'>No grouped root-cause review issue found.</td></tr>") | Out-Null }
    $topRows = New-Object System.Collections.Generic.List[string]
    $topIdx = 1
    foreach ($tf in @($Summary.root_cause_top_issues | Select-Object -First 10)) {
        $topCls = "risk-" + ([string]$tf.risk_level).ToLowerInvariant()
        $anchor = [string]$tf.anchor_id; if ([string]::IsNullOrWhiteSpace($anchor)) { $anchor = "finding-$topIdx" }
        $fileLink = ""; if (-not [string]::IsNullOrWhiteSpace([string]$tf.file_uri)) { $fileLink = "<a class='link' href='$(HtmlSafe $tf.file_uri)'>Open file</a>" }
        $vsLink = ""; if (-not [string]::IsNullOrWhiteSpace([string]$tf.vscode_uri)) { $vsLink = "<a class='link' href='$(HtmlSafe $tf.vscode_uri)'>Open in VS Code</a>" }
        $topRows.Add("<tr><td class='num'>$topIdx</td><td><span class='pill $topCls'>$(HtmlSafe $tf.risk_level)</span><br><span class='muted'>$(HtmlSafe $tf.signal_count) raw signals</span></td><td>$(HtmlSafe $tf.intent)<br><span class='muted'>$(HtmlSafe $tf.chain_strength)</span></td><td><strong>$(HtmlSafe $tf.file_name)</strong><br><code>$(HtmlSafe $tf.line_reference)</code></td><td><a class='link' href='#$(HtmlSafe $anchor)'>Jump to detail</a>$fileLink$vsLink<br><span class='muted'>$(HtmlSafe $tf.why_review)</span></td></tr>") | Out-Null
        $topIdx++
    }
    if ($topRows.Count -eq 0) { $topRows.Add("<tr><td colspan='5' class='empty'>No grouped review issue found.</td></tr>") | Out-Null }
    $extra = ""; if ($Findings.Count -gt $MaxItems) { $extra = "<p class='notice'>HTML report shows the first $MaxItems findings. TXT/JSON contain the full result set.</p>" }
    $html = @"
<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Waibon Dev Shield Trust Report</title>
<style>
:root{--bg:#0b1020;--card:#111827;--text:#e5e7eb;--muted:#9ca3af;--line:#374151;--blue:#2563eb;--orange:#ea580c;--red:#dc2626;--yellow:#ca8a04}body{margin:0;padding:24px;background:var(--bg);color:var(--text);font-family:Segoe UI,Arial,sans-serif;line-height:1.45}.container{max-width:1380px;margin:0 auto}.header{background:linear-gradient(135deg,#111827,#1f2937);border:1px solid var(--line);border-radius:18px;padding:24px;box-shadow:0 16px 45px rgba(0,0,0,.35)}h1{margin:0 0 8px;font-size:28px}.subtitle{color:var(--muted);margin:0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}.card{background:rgba(17,24,39,.88);border:1px solid var(--line);border-radius:14px;padding:14px}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.value{font-size:22px;font-weight:700;margin-top:4px}.scope{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:18px}.scope .item{background:rgba(37,99,235,.10);border:1px solid rgba(37,99,235,.35);border-radius:12px;padding:12px}.scope .item strong{display:block;color:#bfdbfe;margin-bottom:4px}.notice{background:#111827;border-left:4px solid var(--blue);padding:12px 14px;border-radius:10px;color:#dbeafe}.warning{background:#1f1711;border-left:4px solid var(--orange);padding:12px 14px;border-radius:10px;color:#ffedd5}table{width:100%;border-collapse:separate;border-spacing:0;margin-top:18px;overflow:hidden;border:1px solid var(--line);border-radius:14px}th,td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top}th{background:#111827;text-align:left}tr:nth-child(even)td{background:rgba(255,255,255,.02)}code{color:#e0f2fe;white-space:pre-wrap;word-break:break-word}.muted{color:var(--muted);font-size:13px}.num{text-align:right;color:var(--muted)}.pill{display:inline-block;padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700}.risk-critical{background:rgba(220,38,38,.18);color:#fecaca;border:1px solid rgba(220,38,38,.5)}.risk-warning{background:rgba(234,88,12,.18);color:#fed7aa;border:1px solid rgba(234,88,12,.5)}.risk-review{background:rgba(202,138,4,.18);color:#fef3c7;border:1px solid rgba(202,138,4,.5)}.risk-info{background:rgba(37,99,235,.18);color:#dbeafe;border:1px solid rgba(37,99,235,.5)}.empty{text-align:center;color:var(--muted);padding:32px}.footer{color:var(--muted);margin-top:20px;font-size:13px}.link{display:inline-block;margin:3px 6px 3px 0;padding:3px 8px;border:1px solid rgba(96,165,250,.55);border-radius:999px;color:#bfdbfe;text-decoration:none;background:rgba(37,99,235,.12)}@media(max-width:900px){.grid,.scope{grid-template-columns:1fr}body{padding:14px}}
</style></head><body><div class='container'><section class='header'><h1>Waibon Dev Shield v$($Summary.version)</h1><p class='subtitle'><strong>Evidence Fusion &amp; Intent-Aware Dev Safety Scanner</strong></p><p class='subtitle'>Scans developer project folders before opening or running work in VS Code / Cursor / Codex. It combines text evidence, context evidence, behavior evidence, chain evidence, and intent evidence before raising review priority.</p><div class='scope'><div class='item'><strong>Text evidence</strong>Raw commands, tokens, keywords, workflow, and config patterns. Text alone is not a verdict.</div><div class='item'><strong>Context evidence</strong>Docs, tests, examples, placeholders, detector rules, generated files, or active code/config.</div><div class='item'><strong>Behavior evidence</strong>Download, execution, credential, persistence, security modification, supply-chain, or agent surfaces.</div><div class='item'><strong>Chain evidence</strong>Related actions such as download -&gt; execute -&gt; persist or read secret -&gt; outbound send.</div><div class='item'><strong>Intent evidence</strong>Inferred purpose from combined evidence, not a claim of certain intent.</div></div><div class='grid'><div class='card'><div class='label'>Risk status</div><div class='value'>$(HtmlSafe $Summary.risk_status)</div></div><div class='card'><div class='label'>Scan mode</div><div class='value'>$($Summary.scan_mode)</div></div><div class='card'><div class='label'>Raw signals</div><div class='value'>$($Summary.raw_signals)</div></div><div class='card'><div class='label'>Unique review issues</div><div class='value'>$($Summary.unique_review_issues)</div></div></div><div class='grid'><div class='card'><div class='label'>Scanned files</div><div class='value'>$($Summary.scanned_files)</div></div></div><div class='grid'><div class='card'><div class='label'>Critical root causes</div><div class='value'>$($Summary.critical_root_causes)</div><div class='muted'>$($Summary.critical) raw signals / $($Summary.critical_files) files</div></div><div class='card'><div class='label'>Warning issues</div><div class='value'>$($Summary.warning_root_causes)</div><div class='muted'>$($Summary.warning) raw signals / $($Summary.warning_files) files</div></div><div class='card'><div class='label'>Info signals</div><div class='value'>$($Summary.info_findings)</div><div class='muted'>$($Summary.info_files) files</div></div><div class='card'><div class='label'>Passed files</div><div class='value'>$($Summary.passed_files)</div><div class='muted'>No current findings</div></div></div></section><p class='notice'><strong>Safety mode:</strong> Report only. No delete. No modify. No quarantine. No auto-run. Findings are evidence-based review signals, not malware verdicts.</p><p class='warning'><strong>Important:</strong> Browser file links may require permission or may be blocked by browser settings. Use the full path / VS Code link / copy path when needed.</p><p class='notice'><strong>Scan mode note:</strong> $(HtmlSafe $Summary.scan_mode_trust_note)</p><p class='notice'><strong>Strict red-gate policy:</strong> Red/CRITICAL requires high-proof evidence such as real secret with exfiltration, private-key proof in active context, or a strong destructive/download-execute-persistence chain.</p><table><thead><tr><th>Behavior group</th><th>Raw signals</th><th>Files</th></tr></thead><tbody>$($behaviorRows -join "`n")</tbody></table><p class='notice'><strong>Context reduction:</strong> Likely false-positive contexts detected in $($Summary.likely_false_positive_context_findings) findings. These may include docs, examples, tests, placeholders, comments, or detector-rule files.</p><p class='notice'><strong>Trust workflow:</strong> Local baseline loaded: $($Summary.trust_baseline_loaded). Trusted findings reduced: $($Summary.trusted_findings). Baseline file: $(HtmlSafe $Summary.trust_baseline_file)</p><p class='notice'><strong>Report diff:</strong> New $($Summary.report_diff.new_findings), resolved $($Summary.report_diff.resolved_findings), unchanged $($Summary.report_diff.unchanged_findings), risk increased $($Summary.report_diff.risk_increased), risk reduced $($Summary.report_diff.risk_reduced).</p><h2>Root-cause review issues</h2><table><thead><tr><th>Risk</th><th>Intent</th><th>Location</th><th>Raw signals</th><th>Chain</th></tr></thead><tbody>$($rootRows -join "`n")</tbody></table><h2>Top review issues first</h2><table><thead><tr><th>#</th><th>Risk</th><th>Intent / chain</th><th>Location</th><th>Open / why review</th></tr></thead><tbody>$($topRows -join "`n")</tbody></table><p class='notice'><strong>Summary:</strong> Raw signals $($Summary.raw_signals); Unique review issues $($Summary.unique_review_issues); Critical root causes $($Summary.critical_root_causes); Warning issues $($Summary.warning_root_causes); Review issues $($Summary.review_root_causes); Info signals $($Summary.info_findings); Passed $($Summary.passed_files) files.</p>$extra<table><thead><tr><th>#</th><th>Risk</th><th>Score / red gate</th><th>Rule / text</th><th>File location</th><th>Evidence preview</th><th>Intent, behavior, and next step</th></tr></thead><tbody>$($rows -join "`n")</tbody></table><p class='footer'>Developed by Mr.Thammarongsak Panichsawas (Thailand) | Project: www.zetaorigin.com | Follow: https://www.facebook.com/ZetaCoreAI</p></div></body></html>
"@
    $html | Out-File -LiteralPath $Path -Encoding UTF8
}

try {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectRoot = Split-Path -Parent $ScriptRoot
    if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = Read-Host "Paste target project folder path" }
    $TargetPath = (Resolve-Path -LiteralPath $TargetPath).Path.TrimEnd('\','/')
    if (-not (Test-Path -LiteralPath $TargetPath -PathType Container)) { throw "Target path not found: $TargetPath" }
    if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Join-Path $ProjectRoot "reports" }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    if ($CI) { $NoAutoOpenReport = $true }
    $RulesPath = Join-Path $ProjectRoot "rules\suspicious-patterns.json"
    if (-not (Test-Path -LiteralPath $RulesPath)) { throw "Rules file not found: $RulesPath" }
    $RulesText = Get-Content -LiteralPath $RulesPath -Raw -Encoding UTF8
    $RulesDoc = $RulesText | ConvertFrom-Json
    $RawRules = @($RulesDoc.rules)
    $ValidRules = New-Object System.Collections.Generic.List[object]
    $InvalidRules = 0
    foreach ($rr in $RawRules) {
        $pat = Get-RuleProp -Obj $rr -Name "pattern" -Default ""
        if ([string]::IsNullOrWhiteSpace($pat)) { $InvalidRules++; continue }
        try {
            [void][System.Text.RegularExpressions.Regex]::IsMatch("", [string]$pat)
            $ValidRules.Add($rr) | Out-Null
        } catch {
            $InvalidRules++
            Wds-Status ("Skipped invalid rule {0}: {1}" -f (Get-RuleProp -Obj $rr -Name "id" -Default "UNKNOWN"), $_.Exception.Message) "WARN"
        }
    }
    $RulesHash = (StringSha256 -Text $RulesText).Substring(0,12)
    $Profile = ScanProfile -Mode $ScanMode -RulesDoc $RulesDoc
    if ($MaxFileSizeMB -le 0) { $MaxFileSizeMB = [int]$Profile.DefaultMaxFileSizeMB }
    $MaxBytes = [int64]$MaxFileSizeMB * 1MB
    if ([string]::IsNullOrWhiteSpace($CacheDir)) { $CacheDir = Join-Path $ProjectRoot ".waibon-cache" }
    $CacheEnabled = -not $NoCache
    if ($CacheEnabled) { New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null }
    if ($ClearCache -and (Test-Path -LiteralPath $CacheDir)) { Remove-Item -LiteralPath $CacheDir -Recurse -Force; New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null }
    $TargetHash = (StringSha256 -Text ($TargetPath.ToLowerInvariant())).Substring(0,12)
    $CachePath = Join-Path $CacheDir ("wds_cache_{0}_{1}_{2}_{3}.json" -f $Profile.Name.ToLowerInvariant(),$TargetHash,$RulesHash,$Version.Replace(".","_"))
    Write-Host ""
    Write-Host "Scanning: $TargetPath"
    Write-Host "Mode    : $($Profile.Name)"
    Write-Host "Cache   : $CacheEnabled"
    Write-Host ""
    Show-WdsHeader
    Wds-Status "Waibon Dev Shield v$Version starting..." "INFO"
    Wds-Status "Mode: Scan + Report only. No delete. No modify. No quarantine." "OK"
    Wds-Status "Trust: Evidence-based risk report. Pattern match is not proof." "OK"
    Wds-Status "Evidence Fusion Engine: enabled | Intent Evidence: enabled | Strict Red/Warning Gates: enabled | Trust Workflow: enabled" "OK"
    Wds-Status "Target: $TargetPath" "INFO"
    Wds-Status "Scan Mode: $($Profile.Name) - $($Profile.Description)" "OK"
    Wds-Status "Rules loaded: $($ValidRules.Count) | Invalid rules skipped: $InvalidRules" "INFO"
    Wds-Status "Rules hash: $RulesHash" "INFO"
    Wds-Status "Max file size: $MaxFileSizeMB MB" "INFO"
    if ($BatchSize -le 0) { $BatchSize = [int]$Profile.BatchSize }
    if ($ProgressIntervalSec -le 0) { $ProgressIntervalSec = [int]$Profile.ProgressIntervalSec }
    if ($MaxWorkers -lt 1) { $MaxWorkers = 1 }
    if ($MaxWorkers -gt 4) { $MaxWorkers = 4 }
    Wds-Status ("Performance: batch={0} progress_interval={1}s workers={2} (limited parallel plan; stable scanner path uses batched sequential scan on Windows PowerShell)" -f $BatchSize,$ProgressIntervalSec,$MaxWorkers) "INFO"
    $CacheMap = @{}; $CacheHits = 0; $CacheMisses = 0; $CacheReused = 0; $CacheChanged = 0; $CacheReadErrors = 0; $CacheWriteErrors = 0
    $CacheStatus = "Disabled"
    if ($CacheEnabled) {
        if ($ForceFullScan) { $CacheStatus = "Enabled, force full scan requested"; Wds-Status "Force full scan requested; cache will be refreshed." "INFO" }
        elseif (Test-Path -LiteralPath $CachePath) {
            try { $cacheDoc = Get-Content -LiteralPath $CachePath -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($entry in @($cacheDoc.entries)) { $CacheMap[[string]$entry.relative_path.ToLowerInvariant()] = $entry }; $CacheStatus = "Enabled, loaded $($CacheMap.Count) entries"; Wds-Status "Cache loaded: $($CacheMap.Count) entries" "OK" }
            catch { $CacheReadErrors++; $CacheStatus = "Enabled, cache load failed, full scan will run"; Wds-Status "Cache read failed; full scan will run." "WARN" }
        } else { $CacheStatus = "Enabled, no existing cache; first scan will build cache"; Wds-Status "No cache found; this scan will build the first cache." "SCAN" }
        Wds-Status "Cache file: $CachePath" "INFO"
    }
    $collect = CollectFiles -Root $TargetPath -Skip $Profile.SkipDirs -Exts $Profile.IncludeExtensions -Names $Profile.IncludeFileNames -MaxBytes $MaxBytes
    $CandidateFiles = @($collect.Files); $Stats = $collect.Stats
    Wds-Status "Candidate files to scan ($($Profile.Name)): $($CandidateFiles.Count)" "OK"
    Wds-Status "Skipped before scan: $($Stats.SkippedFiles)" "INFO"
    $Findings = New-Object System.Collections.Generic.List[object]
    $NewCacheEntries = New-Object System.Collections.Generic.List[object]
    $ScannedFiles = 0; $ReadErrors = [int]$Stats.ReadErrors; $RuleErrors = 0; $FileProcessingErrors = 0; $TotalCandidates = $CandidateFiles.Count; $LastPrinted = -999
    if ($TotalCandidates -gt 0) { Wds-Status "Step 3/4: Scanning files with cache/incremental progress..." "SCAN" } else { Wds-Status "No candidate files found by current rules." "WARN" }
    $script:ScanStartTime = Get-Date
    $script:LastHeartbeatTime = Get-Date
    $PrefilterSkipped = 0
    $PrefilterHits = 0
    $SlowFiles = 0
    $MaxSingleFileSeconds = 20
    Wds-Status "Smart Indexed Scan Engine: cache-first reuse + cheap content prefilter + deep rule scan only on hits." "OK"
    if ($Profile.Name -eq "Deep") {
        Wds-Status "Full Deep mode uses staged scanning but keeps the broadest candidate scope. It may take longer on large repos." "INFO"
    } elseif ($Profile.Name -eq "SmartDeep") {
        Wds-Status "Smart Deep mode uses batch progress + focused prefilter + behavior rules only on higher-signal files." "INFO"
    }
    for ($fileIndex = 0; $fileIndex -lt $TotalCandidates; $fileIndex++) {
        $file = $CandidateFiles[$fileIndex]
        $relative = RelPath -FullPath $file.FullName -RootPath $TargetPath
        $percent = [int][math]::Floor((($fileIndex + 1) / [double]$TotalCandidates) * 100)
        $cacheKey = $relative.ToLowerInvariant()
        $lastWriteUtc = $file.LastWriteTimeUtc.ToString("o")
        $fileStart = Get-Date
        try {
            if ($CacheEnabled -and (-not $ForceFullScan) -and $CacheMap.ContainsKey($cacheKey)) {
                $ce = $CacheMap[$cacheKey]
                if (([int64]$ce.length -eq [int64]$file.Length) -and ([string]$ce.last_write_utc -eq $lastWriteUtc)) {
                    $CacheHits++
                    foreach ($cf in @($ce.findings)) { $Findings.Add($cf) | Out-Null; $CacheReused++ }
                    $NewCacheEntries.Add($ce) | Out-Null
                    $now = Get-Date
                    if ((($fileIndex + 1) -eq 1) -or (($fileIndex + 1) -eq $TotalCandidates) -or (($now - $script:LastHeartbeatTime).TotalSeconds -ge $ProgressIntervalSec) -or ((($fileIndex + 1) % $BatchSize) -eq 0)) {
                        ProgressLine2 -Percent $percent -Current ($fileIndex+1) -Total $TotalCandidates -Stage "cache" -CurrentFile $relative -PrefilterSkipped $PrefilterSkipped -FastHits $PrefilterHits
                        $script:LastHeartbeatTime = $now
                    }
                    continue
                }
            }
            $CacheMisses++; $CacheChanged++; $ScannedFiles++
            $FileFindings = New-Object System.Collections.Generic.List[object]
            $raw = ""
            try { $raw = [string](ReadTextRawSafe -Path $file.FullName) }
            catch {
                $ReadErrors++
                if ($CacheEnabled) { $NewCacheEntries.Add([pscustomobject]@{relative_path=$relative; length=[int64]$file.Length; last_write_utc=$lastWriteUtc; sha256=""; findings=@(); finding_count=0; prefilter="read_error"; scanned_at=(Get-Date).ToString("o")}) | Out-Null }
                continue
            }
            $prefilterHit = Test-FastPrefilterHit -Text $raw -RelativePath $relative -Mode $Profile.Name
            if (-not $prefilterHit) {
                $PrefilterSkipped++
                if ($CacheEnabled) { $NewCacheEntries.Add([pscustomobject]@{relative_path=$relative; length=[int64]$file.Length; last_write_utc=$lastWriteUtc; sha256=""; findings=@(); finding_count=0; prefilter="clean_fast_skip"; scanned_at=(Get-Date).ToString("o")}) | Out-Null }
                $now = Get-Date
                if ((($fileIndex + 1) -eq 1) -or (($fileIndex + 1) -eq $TotalCandidates) -or (($now - $script:LastHeartbeatTime).TotalSeconds -ge $ProgressIntervalSec) -or ((($fileIndex + 1) % $BatchSize) -eq 0)) {
                    ProgressLine2 -Percent $percent -Current ($fileIndex+1) -Total $TotalCandidates -Stage "prefilter" -CurrentFile $relative -PrefilterSkipped $PrefilterSkipped -FastHits $PrefilterHits
                    $script:LastHeartbeatTime = $now
                }
                continue
            }
            $PrefilterHits++
            $now = Get-Date
            if ((($fileIndex + 1) -eq 1) -or (($fileIndex + 1) -eq $TotalCandidates) -or (($now - $script:LastHeartbeatTime).TotalSeconds -ge $ProgressIntervalSec) -or ((($fileIndex + 1) % $BatchSize) -eq 0)) {
                ProgressLine2 -Percent $percent -Current ($fileIndex+1) -Total $TotalCandidates -Stage "behavior" -CurrentFile $relative -PrefilterSkipped $PrefilterSkipped -FastHits $PrefilterHits
                $script:LastHeartbeatTime = $now
            }
            $lines = @(SplitLinesFast -Text $raw)
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $line = [string]$lines[$i]
                foreach ($rule in $ValidRules) {
                    if (-not (RuleAppliesToContext -Rule $rule -Line $line -RelativePath $relative)) { continue }
                    $pat = Get-RuleProp -Obj $rule -Name "pattern" -Default ""
                    $matched = $false
                    try { $matched = Test-PatternSafe -Text $line -Pattern $pat } catch { $RuleErrors++; $matched = $false }
                    if ($matched) {
                        try {
                            $trust = TrustFields -Rule $rule -Line $line -RelativePath $relative
                            $behaviorTags = @(Get-BehaviorTags -Rule $rule -Line $line -RelativePath $relative)
                            $contextFlags = @(Get-ContextFlags -Line $line -RelativePath $relative)
                            $behaviorText = [string]($behaviorTags -join "; ")
                            $contextText = [string]($contextFlags -join "; ")
                            $interpretation = [string](Get-BehaviorInterpretation -Tags $behaviorTags -ContextFlags $contextFlags)
                            $missingEvidence = [string]((Get-MissingEvidence -Tags $behaviorTags -ContextFlags $contextFlags) -join "; ")
                            $finding = [pscustomobject]@{
                                risk_level = [string]$trust.risk_level; confidence = [string]$trust.confidence; risk_score = [int]$trust.risk_score; rule_id = [string]$trust.rule_id; category = [string]$trust.category; severity = [string]$trust.severity; file = [string]$relative; full_path=[string]$file.FullName; file_name=[string]$file.Name; line = [int]($i + 1); line_reference=([string]$relative + ":" + [string]($i + 1)); file_uri=(New-FileUri -Path $file.FullName); vscode_uri=(New-VSCodeUri -Path $file.FullName -Line ($i+1)); anchor_id=(New-FindingAnchorId -RelativePath $relative -Line ($i+1) -RuleId ([string]$trust.rule_id)); preview = [string](Mask-SensitiveLine -Line $line); behavior_tags = $behaviorText; context_flags = $contextText; behavior_interpretation = $interpretation; missing_evidence = $missingEvidence; why_flagged = [string]$trust.why_flagged; false_positive_note = [string]$trust.false_positive_note; suggested_action = [string]$trust.suggested_action; trust_policy = "single_signal_is_not_a_verdict"; cache_status = "fresh_scan"; engine_version = [string]$trust.engine_version; base_score = [int]$trust.base_score; trigger_score = [int]$trust.trigger_score; impact_score = [int]$trust.impact_score; density_score = [int]$trust.density_score; context_correction = [int]$trust.context_correction; evidence_total = [int]$trust.evidence_total; engine_risk = [string]$trust.engine_risk; engine_confidence = [string]$trust.engine_confidence; engine_explain = [string]$trust.engine_explain; false_positive_class=[string]$trust.false_positive_class; why_not_critical=[string]$trust.why_not_critical; behavior_chain_strength=[string]$trust.behavior_chain_strength; accuracy_calibration=[string]$trust.accuracy_calibration; text_evidence=[string]$trust.text_evidence; intent_evidence=[string]$trust.intent_evidence; intent_confidence=[string]$trust.intent_confidence; intent_explanation=[string]$trust.intent_explanation; strict_red_gate=[bool]$trust.strict_red_gate; strict_red_reason=[string]$trust.strict_red_reason
                            }
                            $Findings.Add($finding) | Out-Null
                            $FileFindings.Add($finding) | Out-Null
                        } catch { $RuleErrors++; continue }
                    }
                }
                if (($i % 500) -eq 0) {
                    $now2 = Get-Date
                    if (($now2 - $script:LastHeartbeatTime).TotalSeconds -ge $ProgressIntervalSec) {
                        ProgressLine2 -Percent $percent -Current ($fileIndex+1) -Total $TotalCandidates -Stage "behavior-lines" -CurrentFile ($relative + " line " + ($i+1)) -PrefilterSkipped $PrefilterSkipped -FastHits $PrefilterHits
                        $script:LastHeartbeatTime = $now2
                    }
                }
            }
            if (((Get-Date) - $fileStart).TotalSeconds -gt $MaxSingleFileSeconds) { $SlowFiles++ }
            if ($CacheEnabled) { $NewCacheEntries.Add([pscustomobject]@{relative_path=$relative; length=[int64]$file.Length; last_write_utc=$lastWriteUtc; sha256=(FileSha256Safe -Path $file.FullName); findings=@($FileFindings); finding_count=$FileFindings.Count; prefilter="behavior_hit"; scanned_at=(Get-Date).ToString("o")}) | Out-Null }
        } catch {
            $FileProcessingErrors++
            continue
        }
    }
    if ($CacheEnabled) {
        try { $cacheOut = [pscustomobject]@{schema_version=$Version; tool="Waibon Dev Shield"; version=$Version; target=$TargetPath; scan_mode=$Profile.Name; rules_hash=$RulesHash; generated=(Get-Date).ToString("o"); entries=@($NewCacheEntries); fast_index=@{prefilter_skipped=$PrefilterSkipped; prefilter_hits=$PrefilterHits; slow_files=$SlowFiles}}; $cacheOut | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $CachePath -Encoding UTF8; Wds-Status "Cache saved: $($NewCacheEntries.Count) file entries" "OK" }
        catch { $CacheWriteErrors++; Wds-Status "Cache write failed. Scan report will still be created." "WARN" }
    }
    Wds-Status "Step 4/4: Creating trust reports..." "SCAN"

    $TrustPolicy = Load-TrustPolicy -Root $TargetPath -ExplicitTrustFile $TrustFile
    $TrustedFindings = Apply-TrustBaseline -Findings $Findings -TrustPolicy $TrustPolicy
    if ($TrustPolicy.loaded) { Wds-Status "Trust baseline loaded: $($TrustPolicy.path) | trusted findings reduced: $TrustedFindings" "OK" }
    else { Wds-Status "No local trust baseline found. Optional file: $($TrustPolicy.path)" "INFO" }
    $PreviousMap = Load-PreviousScanIndex -ReportsDir $OutputDir
    $ReportDiff = Build-ReportDiff -Findings $Findings -PrevMap $PreviousMap
    $Critical = @($Findings | Where-Object { $_.risk_level -eq "CRITICAL" }).Count
    $Warning = @($Findings | Where-Object { $_.risk_level -eq "WARNING" }).Count
    $Review = @($Findings | Where-Object { $_.risk_level -eq "REVIEW" }).Count
    $Info = @($Findings | Where-Object { $_.risk_level -eq "INFO" }).Count
    $FileRiskMap = @{}
    foreach ($f in $Findings) {
        $fk = [string]$f.file
        if (-not $FileRiskMap.ContainsKey($fk)) { $FileRiskMap[$fk] = [string]$f.risk_level }
        elseif ((RiskRank -Risk ([string]$f.risk_level)) -gt (RiskRank -Risk ([string]$FileRiskMap[$fk]))) { $FileRiskMap[$fk] = [string]$f.risk_level }
    }
    $CriticalFiles = @($FileRiskMap.Values | Where-Object { $_ -eq "CRITICAL" }).Count
    $WarningFiles = @($FileRiskMap.Values | Where-Object { $_ -eq "WARNING" }).Count
    $ReviewFiles = @($FileRiskMap.Values | Where-Object { $_ -eq "REVIEW" }).Count
    $InfoFiles = @($FileRiskMap.Values | Where-Object { $_ -eq "INFO" }).Count
    $FilesWithFindings = $FileRiskMap.Count
    $PassedFiles = [int][math]::Max(0, ($TotalCandidates - $FilesWithFindings))
    $HeavyFindings = $Critical + $Warning
    $HeavyFiles = $CriticalFiles + $WarningFiles
    $TotalScore = 0; foreach ($f in $Findings) { $TotalScore += [int]$f.risk_score }
    $BehaviorSummary = @(BuildBehaviorSummary -Findings $Findings)
    $RootCauses = @(BuildRootCauseGroups -Findings $Findings)
    $UniqueReviewIssues = [int]$RootCauses.Count
    $CriticalRootCauses = @($RootCauses | Where-Object { $_.risk_level -eq "CRITICAL" }).Count
    $WarningRootCauses = @($RootCauses | Where-Object { $_.risk_level -eq "WARNING" }).Count
    $ReviewRootCauses = @($RootCauses | Where-Object { $_.risk_level -eq "REVIEW" }).Count
    $RootCauseTopIssues = @($RootCauses | Select-Object -First 10)
    $FalsePositiveContextFindings = @($Findings | Where-Object { ([string]$_.context_flags) -match "docs/examples/tests|markdown/documentation|detector-rule-context|placeholder-or-example|comment-line" }).Count
    $ScanModeTrustNote = Get-ScanModeTrustNote -Mode $Profile.Name
    $RiskStatus = "GREEN - NO CURRENT FINDINGS"
    if ($Critical -gt 0) { $RiskStatus = "RED - CRITICAL REVIEW NEEDED" }
    elseif ($Warning -gt 0) { $RiskStatus = "ORANGE - WARNING REVIEW NEEDED" }
    elseif (($Review + $Info) -gt 0) { $RiskStatus = "YELLOW - REVIEW RECOMMENDED" }
    $Sorted = @($Findings | Sort-Object @{Expression="risk_score";Descending=$true}, @{Expression="file";Descending=$false}, @{Expression="line";Descending=$false})
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $HtmlPath = Join-Path $OutputDir "WaibonDevShield_TrustReport_$stamp.html"
    $TxtPath = Join-Path $OutputDir "WaibonDevShield_TrustReport_$stamp.txt"
    $JsonPath = Join-Path $OutputDir "WaibonDevShield_TrustReport_$stamp.json"
    $LatestPath = Join-Path $OutputDir "latest-report-paths.json"
    $gen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Summary = [pscustomobject]@{ tool="Waibon Dev Shield"; version=$Version; scan_mode=$Profile.Name; scan_mode_description=$Profile.Description; generated=(Get-Date).ToString("o"); generated_display=$gen; target=$TargetPath; mode="scan_report_only"; trust_policy="single_signal_is_not_a_verdict"; behavior_evidence_engine="enabled"; accuracy_false_positive_reduction="enabled"; trust_workflow="enabled"; trust_baseline_loaded=[bool]$TrustPolicy.loaded; trust_baseline_file=$TrustPolicy.path; trusted_findings=$TrustedFindings; report_diff=$ReportDiff; scan_mode_trust_note=$ScanModeTrustNote; likely_false_positive_context_findings=$FalsePositiveContextFindings; behavior_summary=@($BehaviorSummary); cache_enabled=[bool]$CacheEnabled; cache_status_text=$CacheStatus; cache_file=$CachePath; cache_hits=$CacheHits; cache_misses=$CacheMisses; cache_reused_findings=$CacheReused; cache_changed_files_scanned=$CacheChanged; cache_read_errors=$CacheReadErrors; cache_write_errors=$CacheWriteErrors; risk_status=$RiskStatus; total_score=$TotalScore; visited_directories=[int]$Stats.VisitedDirectories; enumerated_files=[int]$Stats.EnumeratedFiles; candidate_files=$TotalCandidates; scanned_files=$ScannedFiles; skipped_files=[int]$Stats.SkippedFiles; read_errors=$ReadErrors; rule_errors=$RuleErrors; file_processing_errors=$FileProcessingErrors; prefilter_skipped=$PrefilterSkipped; prefilter_hits=$PrefilterHits; slow_files=$SlowFiles; raw_signals=$Findings.Count; findings=$Findings.Count; unique_review_issues=$UniqueReviewIssues; root_cause_summary=@($RootCauses); root_cause_top_issues=@($RootCauseTopIssues); critical_root_causes=$CriticalRootCauses; warning_root_causes=$WarningRootCauses; review_root_causes=$ReviewRootCauses; critical=$Critical; warning=$Warning; review=$Review; info=$Info; heavy_findings=$HeavyFindings; heavy_files=$HeavyFiles; review_findings=$Review; review_files=$ReviewFiles; info_findings=$Info; info_files=$InfoFiles; files_with_findings=$FilesWithFindings; passed_files=$PassedFiles; critical_files=$CriticalFiles; warning_files=$WarningFiles; review_files_detail=$ReviewFiles; info_files_detail=$InfoFiles }
    $rep = New-Object System.Collections.Generic.List[string]
    $rep.Add("WAIBON DEV SHIELD v$Version - TRUST REPORT") | Out-Null
    $rep.Add("Evidence Fusion & Intent-Aware Pre-Open Guard") | Out-Null
    $rep.Add("============================================================") | Out-Null
    $rep.Add("Evidence Fusion Scope") | Out-Null
    $rep.Add("- Download -> execute behavior") | Out-Null
    $rep.Add("- Secret/token/private-key exposure signals") | Out-Null
    $rep.Add("- Package install hooks and supply-chain surfaces") | Out-Null
    $rep.Add("- GitHub Actions, VS Code tasks, Git hooks, auto-run workflow") | Out-Null
    $rep.Add("- AI agent instruction files and MCP/agent configs") | Out-Null
    $rep.Add("- Security-setting modification or Defender exclusion behavior") | Out-Null
    $rep.Add("- Persistence, obfuscation, destructive, or exfiltration-like chains") | Out-Null
    $rep.Add("- Context reduction for docs, examples, tests, placeholders, and detector rules") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("Developed by        : Mr.Thammarongsak Panichsawas (Thailand)") | Out-Null
    $rep.Add("Project             : www.zetaorigin.com") | Out-Null
    $rep.Add("Follow              : https://www.facebook.com/ZetaCoreAI") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("Mode                : Scan + Report only") | Out-Null
    $rep.Add("Scan Mode           : $($Profile.Name)") | Out-Null
    $rep.Add("Trust Policy        : Single signal is not a verdict. Pattern match is not proof.") | Out-Null
    $rep.Add("Behavior Evidence Engine: Enabled - behavior-chain review, not proof of malware") | Out-Null
    $rep.Add("Trust Workflow       : Enabled - local trust baseline and report diff") | Out-Null
    $rep.Add("Trust Baseline      : $($TrustPolicy.path) | Loaded=$($TrustPolicy.loaded) | Trusted findings=$TrustedFindings") | Out-Null
    $rep.Add("Cache Status        : $CacheStatus") | Out-Null
    $rep.Add("Generated           : $gen") | Out-Null
    $rep.Add("Target              : $TargetPath") | Out-Null
    $rep.Add("Risk Status         : $RiskStatus") | Out-Null
    $rep.Add("Raw Signals         : $($Findings.Count)`nUnique Review Issues: $UniqueReviewIssues") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("SUMMARY COUNTS") | Out-Null
    $rep.Add("- Critical root causes              : $CriticalRootCauses issues ($Critical raw signals / $CriticalFiles files)`n- Warning issues                    : $WarningRootCauses issues ($Warning raw signals / $WarningFiles files)") | Out-Null
    $rep.Add("- Review issues                     : $ReviewRootCauses issues ($Review raw signals / $ReviewFiles files)") | Out-Null
    $rep.Add("- Info signals                      : $Info findings / $InfoFiles files") | Out-Null
    $rep.Add("- Passed / no current finding files : $PassedFiles files") | Out-Null
    $rep.Add("- Likely false-positive contexts    : $FalsePositiveContextFindings findings") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("REPORT DIFF") | Out-Null
    $rep.Add("- New findings      : $($ReportDiff.new_findings)") | Out-Null
    $rep.Add("- Resolved findings : $($ReportDiff.resolved_findings)") | Out-Null
    $rep.Add("- Unchanged findings: $($ReportDiff.unchanged_findings)") | Out-Null
    $rep.Add("- Risk increased    : $($ReportDiff.risk_increased)") | Out-Null
    $rep.Add("- Risk reduced      : $($ReportDiff.risk_reduced)") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("TOP ROOT-CAUSE REVIEW ISSUES FIRST") | Out-Null
    $topIdx2 = 1
    foreach ($tf in @($Sorted | Select-Object -First 10)) { $rep.Add(("- #{0} {1} | {2} | {3}:{4} | {5}" -f $topIdx2,$tf.risk_level,$tf.behavior_chain_strength,$tf.file,$tf.line,$tf.rule_id)) | Out-Null; $topIdx2++ }
    if ($topIdx2 -eq 1) { $rep.Add("- No top findings to review.") | Out-Null }
    $rep.Add("") | Out-Null
    $rep.Add("BEHAVIOR EVIDENCE SUMMARY") | Out-Null
    if ($BehaviorSummary.Count -eq 0) { $rep.Add("- No behavior group detected by current rules.") | Out-Null }
    else { foreach ($b in $BehaviorSummary) { $rep.Add(("- {0}: {1} findings / {2} files" -f $b.behavior,$b.findings,$b.files)) | Out-Null } }
    $rep.Add("") | Out-Null
    $rep.Add("SCAN MODE NOTE") | Out-Null
    $rep.Add("- $ScanModeTrustNote") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("Read Errors         : $ReadErrors") | Out-Null
    $rep.Add("Rule Errors         : $RuleErrors") | Out-Null
    $rep.Add("File Errors         : $FileProcessingErrors") | Out-Null
    $rep.Add("Fast Index Skips    : $PrefilterSkipped") | Out-Null
    $rep.Add("Behavior Deep Hits  : $PrefilterHits") | Out-Null
    $rep.Add("Slow Files Observed : $SlowFiles") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("IMPORTANT") | Out-Null
    $rep.Add("- This tool is not an antivirus.") | Out-Null
    $rep.Add("- It does not delete, modify, quarantine, or execute target files.") | Out-Null
    $rep.Add("- A finding is a signal that needs context review, not proof of malware.") | Out-Null
    $rep.Add("- False positives must be treated as product defects and improved through rules/allowlists later.") | Out-Null
    $rep.Add("") | Out-Null
    $rep.Add("FINDINGS") | Out-Null
    $rep.Add("============================================================") | Out-Null
    if ($Findings.Count -eq 0) { $rep.Add("No suspicious pattern found by current rules.") | Out-Null }
    else { $idx = 1; foreach ($f in $Sorted) { $rep.Add("") | Out-Null; $rep.Add("[$idx] Risk: $($f.risk_level) | Confidence: $($f.confidence) | Rule: $($f.rule_id)") | Out-Null; $rep.Add("Category       : $($f.category)") | Out-Null; $rep.Add("File           : $($f.file)") | Out-Null; $rep.Add("File Name      : $($f.file_name)") | Out-Null; $rep.Add("Full Path      : $($f.full_path)") | Out-Null; $rep.Add("Line           : $($f.line)") | Out-Null; $rep.Add("Line Reference : $($f.line_reference)") | Out-Null; $rep.Add("Open File URI  : $($f.file_uri)") | Out-Null; $rep.Add("VS Code URI    : $($f.vscode_uri)") | Out-Null; $rep.Add("Evidence       : $($f.preview)") | Out-Null; $rep.Add("Text Evidence  : $($f.text_evidence)") | Out-Null; $rep.Add("Intent Evidence: $($f.intent_evidence) | Confidence: $($f.intent_confidence)") | Out-Null; $rep.Add("Intent Why     : $($f.intent_explanation)") | Out-Null; $rep.Add("Strict Red Gate: $($f.strict_red_gate) | $($f.strict_red_reason)") | Out-Null; $rep.Add("Behavior       : $($f.behavior_tags)") | Out-Null; $rep.Add("Context        : $($f.context_flags)") | Out-Null; $rep.Add("Interpretation : $($f.behavior_interpretation)") | Out-Null; $rep.Add("Missing Proof  : $($f.missing_evidence)") | Out-Null; $rep.Add("Why Not Critical: $($f.why_not_critical)") | Out-Null; $rep.Add("False+ Class   : $($f.false_positive_class)") | Out-Null; $rep.Add("Chain Strength : $($f.behavior_chain_strength)") | Out-Null; $rep.Add("Accuracy Calib : $($f.accuracy_calibration)") | Out-Null; $rep.Add("Evidence Score : Total=$($f.evidence_total) | Base=$($f.base_score) Trigger=$($f.trigger_score) Impact=$($f.impact_score) Density=$($f.density_score) ContextCorrection=$($f.context_correction)") | Out-Null; $rep.Add("Score Why      : $($f.engine_explain)") | Out-Null; $rep.Add("Why            : $($f.why_flagged)") | Out-Null; $rep.Add("False+         : $($f.false_positive_note)") | Out-Null; $rep.Add("Next           : $($f.suggested_action)") | Out-Null; $idx++ } }
    $rep | Out-File -LiteralPath $TxtPath -Encoding UTF8
    [pscustomobject]@{summary=$Summary; findings=@($Sorted)} | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $JsonPath -Encoding UTF8
    NewHtmlReport -Path $HtmlPath -Summary $Summary -Findings $Sorted -MaxItems $MaxHtmlFindings
    $LastScanIndexPath = Save-CurrentScanIndex -ReportsDir $OutputDir -Findings $Findings -Version $Version -Target $TargetPath -ScanMode $Profile.Name
    [pscustomobject]@{tool="Waibon Dev Shield"; version=$Version; generated=(Get-Date).ToString("o"); target=$TargetPath; scan_mode=$Profile.Name; risk_status=$RiskStatus; txt_report=$TxtPath; json_report=$JsonPath; html_report=$HtmlPath; summary=$Summary} | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $LatestPath -Encoding UTF8
    Wds-Status "Scan complete." "OK"
    Wds-Status "Scan Mode: $($Profile.Name)" "OK"
    Wds-Status "Evidence Fusion Engine: enabled | Intent Evidence: enabled | Strict Red/Warning Gates: enabled | Trust Workflow: enabled" "OK"
    Wds-Status "Risk Status: $RiskStatus" "WARN"
    Wds-Status "Summary: RawSignals=$($Findings.Count) | UniqueReviewIssues=$UniqueReviewIssues | CriticalRootCauses=$CriticalRootCauses | WarningIssues=$WarningRootCauses | ReviewIssues=$ReviewRootCauses | InfoSignals=$Info | PassedFiles=$PassedFiles" "OK"
    Wds-Status "Root-cause grouping: $UniqueReviewIssues review issues from $($Findings.Count) raw signals" "OK"
    Wds-Status "Behavior groups: $($BehaviorSummary.Count) | Likely false-positive contexts: $FalsePositiveContextFindings raw signals" "OK"
    foreach ($b in @($BehaviorSummary | Select-Object -First 8)) { Wds-Status ("Behavior: {0} = {1} findings / {2} files" -f $b.behavior,$b.findings,$b.files) "INFO" }
    Wds-Status "Scan mode note: $ScanModeTrustNote" "INFO"
    Wds-Status "Cache hits: $CacheHits | misses: $CacheMisses | changed scanned: $CacheChanged | reused findings: $CacheReused" "OK"
    Wds-Status "Fast index: prefilter skipped=$PrefilterSkipped | behavior deep hits=$PrefilterHits | slow files=$SlowFiles" "OK"
    Wds-Status "Trust baseline: loaded=$($TrustPolicy.loaded) | trusted findings=$TrustedFindings | file=$($TrustPolicy.path)" "OK"
    Wds-Status "Report diff: new=$($ReportDiff.new_findings) | resolved=$($ReportDiff.resolved_findings) | unchanged=$($ReportDiff.unchanged_findings) | risk up=$($ReportDiff.risk_increased) | risk down=$($ReportDiff.risk_reduced)" "OK"
    Wds-Status "Read errors: $ReadErrors | Rule errors: $RuleErrors | File errors: $FileProcessingErrors" "OK"
    Wds-Status "HTML report: $HtmlPath" "OK"
    Wds-Status "TXT report : $TxtPath" "OK"
    Wds-Status "JSON report: $JsonPath" "OK"
    Wds-Status "Latest pointer: $LatestPath" "OK"
    Wds-Status "Last scan index: $LastScanIndexPath" "OK"
    $ExitCode = 0
    if ($FailOn -eq "Critical" -and $Critical -gt 0) { $ExitCode = 2 }
    elseif ($FailOn -eq "Warning" -and (($Critical + $Warning) -gt 0)) { $ExitCode = 2 }
    if ($CI -and $ExitCode -ne 0) { Wds-Status "CI fail-on policy triggered: $FailOn" "ERROR" }
    if (-not $NoAutoOpenReport) {
        try {
            Wds-Status "Opening HTML report in default browser..." "INFO"
            Start-Process -FilePath $HtmlPath | Out-Null
        } catch {
            Wds-Status "Could not open HTML report automatically. Open it manually from the path above." "WARN"
        }
    }
    exit $ExitCode
} catch {
    Wds-Status $_.Exception.Message "ERROR"
    exit 1
}
