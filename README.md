# Waibon Dev Shield v0.6.0

**Evidence Fusion & Intent-Aware Dev Safety Scanner**

Waibon Dev Shield is a local, report-only Windows safety scanner for developer project folders. It helps review a project before opening or running work in VS Code, Cursor, Codex, or other AI coding tools.

It combines multiple evidence layers before raising review priority:

- **Text Evidence**: raw commands, tokens, keywords, workflow/config patterns.
- **Context Evidence**: docs, tests, examples, placeholders, detector rules, generated files, active code/config.
- **Behavior Evidence**: download, execute, credential, persistence, CI/CD, supply-chain, and agent surfaces.
- **Chain Evidence**: related actions such as download -> execute -> persist, or secret -> outbound send.
- **Intent Evidence**: inferred purpose from combined evidence. This is an evidence-based review signal, not a claim of certain intent.

## Safety model

Waibon Dev Shield is **not an antivirus** and does not guarantee safety.

Default behavior:

- No delete
- No modify
- No quarantine
- No target-file execution
- Local report generation only

A text match alone is not a verdict. Risk levels are based on combined evidence, context, behavior, chain, and inferred intent.

## Quick start

1. Extract the ZIP first. Do not run from inside the ZIP.
2. Double-click `START-WaibonDevShield.cmd`.
3. Paste the target project folder path.
4. Choose a scan profile.
5. Review the generated HTML report.

## Launchers

- `START-WaibonDevShield.cmd` — scan and report.
- `START-WaibonPreOpenGuard.cmd` — scan before opening VS Code, Cursor, or Codex.

## Scan profiles

- **Quick Scan**: fast preliminary pre-open review.
- **Smart Deep Scan**: balanced behavior/context review; recommended detailed mode.
- **Full Deep Scan**: broadest review and slowest mode.
- **Secret & Token Scan**: focused credential exposure review.
- **Supply-chain Scan**: focused package hooks / install scripts / CI review.
- **AI Agent / MCP Scan**: focused AI agent instruction and tool-config review.

## Output

Reports are written to the `reports` folder:

- HTML report
- TXT report
- JSON report
- latest-report-paths.json

The HTML report includes raw signals, unique review issues, root-cause grouping, file location, full path, line reference, Open file link, Open in VS Code link, behavior/intent summary, missing evidence, and next-step guidance.

## Developer

Developed by **Mr.Thammarongsak Panichsawas (Thailand)**

Project: `www.zetaorigin.com`  
Follow: `https://www.facebook.com/ZetaCoreAI`


<p align="center">
  <img src="docs/images/html-report-summary.png" alt="Waibon Dev Shield HTML Report" width="900">
</p>
