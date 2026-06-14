# Behavior Evidence Scope

Waibon Dev Shield scans developer project folders for behavior-risk evidence before opening or running work in VS Code, Cursor, or Codex.

It looks for:

- Download -> execute behavior
- Secret/token/private-key exposure signals
- Package install hooks and supply-chain surfaces
- GitHub Actions, VS Code tasks, Git hooks, and auto-run workflow
- AI agent instruction files and MCP/agent configs
- Security-setting modification or Defender exclusion behavior
- Persistence, obfuscation, destructive, or exfiltration-like chains
- Context reduction for docs, examples, tests, placeholders, comments, and detector rules

Findings are review signals, not malware verdicts.
