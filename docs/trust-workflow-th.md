# Trust Workflow

Trust Workflow คือระบบให้ผู้ใช้ลดระดับรายการเตือนที่ตรวจสอบแล้วว่าเป็นบริบทที่ตั้งใจใช้ใน repo นี้

ให้สร้างไฟล์ `.waibon-trust.json` ไว้ที่ root ของ repo เป้าหมาย รองรับ:

- `trusted_files`: ไฟล์ตรง, path prefix ที่ลงท้าย `/`, หรือ pattern แบบ `*`
- `trusted_rules`: rule ID ที่ยอมรับใน repo นี้
- `trusted_pairs`: คู่ file + rule ID
- `trusted_fingerprints`: fingerprint ของ finding จาก report

รายการที่ trust แล้วจะไม่ถูกลบหรือซ่อน แต่ลดเป็น INFO และมี `trusted=true` กับ `trust_reason` ในรายงาน
