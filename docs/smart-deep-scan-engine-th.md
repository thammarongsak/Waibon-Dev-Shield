# Smart Deep Scan Engine

Smart Deep Scan คือโหมดตรวจละเอียดที่แนะนำให้ใช้เป็นหลัก ระหว่าง Quick Scan กับ Full Deep Scan

แนวคิดคือไม่ตรวจหนักทุกไฟล์ตั้งแต่แรก แต่ใช้การคัดกรองเร็ว แล้วค่อยตรวจเชิงพฤติกรรมกับไฟล์ที่มีสัญญาณมากพอ

ขั้นตอนหลัก:

1. เก็บข้อมูลไฟล์และ candidate
2. คัดกรองเร็วด้วย prefilter
3. ตรวจ behavior evidence เฉพาะไฟล์ที่มีสัญญาณ
4. ลด false positive จาก docs / examples / tests / placeholder / detector rule
5. สร้างรายงาน HTML / TXT / JSON

ระบบยังเป็น report-only: ไม่ลบ ไม่แก้ ไม่กักไฟล์ และไม่รันไฟล์เป้าหมาย
