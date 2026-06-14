@echo off
setlocal
cd /d "%~dp0"
if not exist "scripts\Waibon-DevShield-Scan.ps1" (
  echo [ERROR] This launcher must be run from the extracted project folder.
  echo Please right-click the ZIP and choose Extract All first.
  pause
  exit /b 1
)
cls
echo ============================================================
echo  WAIBON DEV SHIELD v0.6.0
echo  Evidence Fusion ^& Intent-Aware Dev Safety Scanner
echo ============================================================
echo.
echo What this tool does:
echo  Scans developer project folders before opening or running work
echo  in VS Code / Cursor / Codex.
echo.
echo Evidence Fusion Layers:
echo  - Text Evidence      : raw commands, tokens, keywords, config patterns
echo  - Context Evidence   : docs, tests, examples, placeholders, active code
echo  - Behavior Evidence  : download, execute, credential, persistence, CI, agent surfaces
echo  - Chain Evidence     : related actions such as download -^> execute -^> persist
echo  - Intent Evidence    : inferred purpose from combined evidence
echo.
echo Important:
echo  A text match alone is not a verdict.
echo  Risk levels are based on combined evidence, context, behavior,
echo  chain, and inferred intent before review priority is raised.
echo.
echo Trust Workflow:
echo  Optional local .waibon-trust.json can reduce known/expected findings
echo  for this repository only. Report diff shows new/resolved/unchanged findings.
echo.
echo Safety Mode: Report only. No delete. No modify. No quarantine.
echo Findings are evidence-based review signals, not malware verdicts.
echo Red/CRITICAL requires high-proof behavior or secret evidence.
echo.
echo Developed by: Mr.Thammarongsak Panichsawas (Thailand)
echo Project     : www.zetaorigin.com
echo Follow      : https://www.facebook.com/ZetaCoreAI
echo ============================================================
echo.

set /p TARGET=Paste target project folder path: 
echo.
echo Choose scan profile:
echo   1 = Quick Scan
echo       Fast preliminary pre-open review.
echo.
echo   2 = Smart Deep Scan  ^(recommended detailed mode^)
echo       Balanced performance, behavior/context review, lower false positives.
echo.
echo   3 = Full Deep Scan
echo       Broadest review and slowest mode.
echo.
echo   4 = Secret ^& Token Scan
echo       Focused review for .env, private keys, tokens, and credential exposure.
echo.
echo   5 = Supply-chain Scan
echo       Focused review for package hooks, install scripts, CI/CD, dependency surfaces.
echo.
echo   6 = AI Agent / MCP Scan
echo       Focused review for AI agent instruction files and MCP/tool configs.
set /p SCANMODE=Select 1-6 [2]: 
if "%SCANMODE%"=="1" (set MODE=Quick) else if "%SCANMODE%"=="3" (set MODE=Deep) else if "%SCANMODE%"=="4" (set MODE=Secrets) else if "%SCANMODE%"=="5" (set MODE=SupplyChain) else if "%SCANMODE%"=="6" (set MODE=AgentMcp) else (set MODE=SmartDeep)
echo.
echo Choose cache mode:
echo   1 = Incremental cache   (recommended; skip unchanged files)
echo   2 = Force full scan     (ignore old cache, refresh after scan)
echo   3 = Clear cache first   (delete current cache, then rebuild)
echo   4 = No cache            (do not read or write cache)
set /p CACHEMODE=Select 1, 2, 3, or 4 [1]: 
set CACHEARGS=
if "%CACHEMODE%"=="2" set CACHEARGS=-ForceFullScan
if "%CACHEMODE%"=="3" set CACHEARGS=-ClearCache
if "%CACHEMODE%"=="4" set CACHEARGS=-NoCache
echo.
echo Choose performance mode:
echo   1 = Balanced console output   (recommended)
echo   2 = Quiet/light console output (faster, fewer lines)
set /p PERF=Select 1 or 2 [1]: 
set PERFARGS=-BatchSize 300 -ProgressIntervalSec 4
if "%PERF%"=="2" set PERFARGS=-BatchSize 600 -ProgressIntervalSec 7 -QuietProgress
echo.
echo Optional CI/fail mode:
echo   1 = Normal desktop mode     (open HTML report after scan)
echo   2 = CI mode fail on CRITICAL (no auto-open report)
echo   3 = CI mode fail on WARNING+ (no auto-open report)
set /p CIMODE=Select 1, 2, or 3 [1]: 
set CIARGS=
if "%CIMODE%"=="2" set CIARGS=-CI -FailOn Critical
if "%CIMODE%"=="3" set CIARGS=-CI -FailOn Warning
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Waibon-DevShield-Scan.ps1" -TargetPath "%TARGET%" -ScanMode %MODE% %CACHEARGS% %PERFARGS% %CIARGS%
echo.
echo Done. HTML report should open automatically in normal desktop mode.
echo Check the reports folder:
echo "%~dp0reports"
echo.
pause
