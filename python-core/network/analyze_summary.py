import re
from pathlib import Path

DEFAULT_FILE = Path(__file__).parent / "output-packet.txt"

def analyze_summary(text_file=None):
    if text_file is None:
        text_file = DEFAULT_FILE
    
    if not text_file.exists():
        print(f"❌ ไม่พบไฟล์: {text_file}")
        return
    
    with open(text_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    print("=== AetherCore Summary Analyzer (Gepard 3.0) ===")
    print("ไฟล์นี้คือ output จาก parser เก่า → วิเคราะห์ได้เลย\n")
    
    # ดึงข้อมูลทั้งหมด
    packets = re.findall(r'Packet\s+\d+\s+\|\s+Len=\s*(\d+)\s+\|\s+Opcode=(0x[0-9A-F]+)', content)
    
    gepard_count = 0
    print(f"พบทั้งหมด {len(packets)} packet\n")
    print("Opcode ที่สำคัญ (Gepard 3.0):")
    print("-" * 60)
    
    for length, opcode in packets:
        note = ""
        if opcode in ["0xCEE9", "0xDF3E"]:
            note = "🚨 Gepard Heartbeat / Anti-Bot Check"
            gepard_count += 1
        elif int(length) > 40000:
            note = "🚨 ขนาดใหญ่พิเศษ (น่าจะ Gepard)"
        
        print(f"Opcode: {opcode} | Len: {length:5} | {note}")
    
    print(f"\nสรุป Gepard Pattern: พบ {gepard_count} ครั้ง (0xCEE9 + 0xDF3E)")
    print("→ นี่คือจุดที่ Gepard 3.0 ตรวจหนักที่สุด (ต้อง Randomize ให้เหมือนคนเล่น)")

if __name__ == "__main__":
    analyze_summary()