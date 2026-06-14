# CI Mode

ตัวอย่างคำสั่ง:

```powershell
.\scripts\Waibon-DevShield-Scan.ps1 -TargetPath . -ScanMode SmartDeep -CI -FailOn Critical
.\scripts\Waibon-DevShield-Scan.ps1 -TargetPath . -ScanMode SmartDeep -CI -FailOn Warning
```

CI mode จะไม่เปิด HTML อัตโนมัติ และจะคืน exit code `2` เมื่อเงื่อนไข fail ถูกเรียกใช้
