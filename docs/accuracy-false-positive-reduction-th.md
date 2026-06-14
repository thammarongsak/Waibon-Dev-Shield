# Accuracy + False Positive Reduction

v0.6.0 ลดการเตือนเกินจริงโดยดูบริบทก่อนยกระดับความเสี่ยง

ระบบจะแยกบริบทที่อาจเป็น false positive เช่น เอกสาร ตัวอย่าง test placeholder detector rule generated file และ comment

CRITICAL จะขึ้นยากขึ้น ต้องมีหลักฐานหนัก เช่น key/token ที่เหมือนใช้งานจริง หรือพฤติกรรมเป็น chain ชัดเจน
