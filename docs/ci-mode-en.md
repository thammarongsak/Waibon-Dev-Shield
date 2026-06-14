# CI Mode

Command-line options:

```powershell
.\scripts\Waibon-DevShield-Scan.ps1 -TargetPath . -ScanMode SmartDeep -CI -FailOn Critical
.\scripts\Waibon-DevShield-Scan.ps1 -TargetPath . -ScanMode SmartDeep -CI -FailOn Warning
```

CI mode disables automatic HTML opening. Exit code is `2` when fail policy is triggered.
