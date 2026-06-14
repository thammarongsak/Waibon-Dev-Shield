# ขอบเขต Behavior Evidence

Waibon Dev Shield ใช้ตรวจโฟลเดอร์โปรเจกต์ของนักพัฒนาก่อนเปิดหรือรันงานใน VS Code, Cursor หรือ Codex

ระบบไม่ได้ตัดสินจากคำเดี่ยว ๆ แต่ดูหลักฐานเชิงพฤติกรรม เช่น:

- ดาวน์โหลดแล้วรันต่อ
- สัญญาณการเปิดเผย secret/token/private key
- package install hook และพื้นผิว supply-chain
- GitHub Actions, VS Code tasks, Git hooks และ workflow ที่รันอัตโนมัติ
- ไฟล์คำสั่งของ AI agent และ MCP/agent config
- การแก้ security setting หรือ Defender exclusion
- persistence, obfuscation, destructive behavior หรือ exfiltration-like chain
- การลดระดับความเสี่ยงเมื่อพบว่าเป็น docs, examples, tests, placeholders, comments หรือ detector rules

ผลตรวจคือสัญญาณสำหรับให้มนุษย์รีวิว ไม่ใช่คำตัดสินว่าเป็นมัลแวร์
