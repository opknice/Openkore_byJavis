import re
import os
from pathlib import Path

DEFAULT_FILE = Path(__file__).parent / "output-packet.txt"

def extract_timings(text_file=None):
    if text_file is None:
        text_file = DEFAULT_FILE
    if not os.path.exists(text_file):
        print(f"❌ ไม่พบไฟล์: {text_file}")
        return
    
    with open(text_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Regex ใหม่ที่จับเวลาได้แม่นยำขึ้น
    times = re.findall(r'(\d+\.\d{6,})\s+', content)
    times = [float(t) for t in times]
    
    print("=== AetherCore Timing Analyzer v2 (Gepard Detection) ===")
    print(f"พบ {len(times)} timestamps\n")
    
    if len(times) < 2:
        print("❌ ไม่พบเวลา (ไฟล์อาจไม่มี Time column)")
        return
    
    print("Delay (วินาที) | Pattern")
    print("-" * 50)
    for i in range(1, len(times)):
        delay = times[i] - times[i-1]
        flag = ""
        if delay < 0.01: flag = "⚡ เร็วเกินมนุษย์"
        elif abs(delay - 0.3) < 0.01 or abs(delay - 0.2) < 0.01: flag = "🔁 Fixed Delay (Gepard ตรวจ)"
        print(f"{delay:8.3f}     | {flag}")

if __name__ == "__main__":
    extract_timings()