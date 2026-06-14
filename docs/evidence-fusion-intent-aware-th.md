# Evidence Fusion & Intent-Aware Review

Waibon Dev Shield v0.6.0 ใช้หลักฐานหลายชั้นก่อนให้ระดับความเสี่ยง

## ชั้นหลักฐาน

1. Text Evidence: ข้อความ คำสั่ง token keyword และ pattern จาก config/workflow
2. Context Evidence: ดูว่าอยู่ใน code จริง docs examples tests placeholder detector rule generated output หรือ lockfile
3. Behavior Evidence: ดูว่ามีพฤติกรรมอะไร เช่น download execute อ่าน secret แก้ security setting persist หรือ publish
4. Chain Evidence: ดูว่าพฤติกรรมหลายอย่างต่อกันเป็นลำดับหรือไม่ เช่น download -> execute -> persist
5. Intent Evidence: อนุมานเจตนาจากหลักฐานรวมทั้งหมด เป็นสัญญาณเพื่อให้คนรีวิว ไม่ใช่คำตัดสินแน่นอน

## เหตุผล

รายงานความปลอดภัยถ้าให้ระดับแรงเกินหลักฐาน อาจทำให้โปรเจกต์คนอื่นเสียชื่อได้ v0.6.0 จึงถือว่า text match เป็นหลักฐานดิบเท่านั้น และต้องใช้หลักฐานหลายชั้นก่อนยกระดับความเสี่ยง
