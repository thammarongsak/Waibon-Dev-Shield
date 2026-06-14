# Smart Indexed Scan Engine (v0.6.0)

Waibon Dev Shield v0.6.0 เพิ่มความเร็วโดยไม่ลดหลักการตรวจแบบมีหลักฐาน ด้วยการแบ่งงานเป็นชั้น ๆ:

1. **Metadata / candidate index** — เก็บข้อมูลไฟล์และข้ามโฟลเดอร์ build/cache ที่ไม่จำเป็น
2. **Cache-first reuse** — ใช้ผลเดิมกับไฟล์ที่ไม่เปลี่ยน
3. **Cheap content prefilter** — ตรวจคำ/สัญญาณเบื้องต้นแบบเร็ว ก่อนยิง rule หนัก
4. **Behavior deep scan** — ตรวจลึกเฉพาะไฟล์ที่มีสัญญาณพฤติกรรม
5. **Context reduction** — ลด false positive จาก docs, tests, examples, placeholders และ detector-rule contexts

เครื่องมือนี้ยังเป็น Report only ไม่ลบ ไม่แก้ ไม่กักไฟล์ และไม่รันไฟล์เป้าหมาย Findings คือสัญญาณให้รีวิว ไม่ใช่คำตัดสินว่าเป็นมัลแวร์
