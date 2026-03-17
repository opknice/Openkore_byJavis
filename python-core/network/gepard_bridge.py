import subprocess
import json
import time
from randomization_engine import GepardRandomizer

engine = GepardRandomizer()

def call_perl_core(command):
    """ส่งคำสั่งไปให้ Perl Core แล้วรอผล"""
    try:
        result = subprocess.run(
            ["perl", "src/openkore.pl", command], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        return result.stdout.strip()
    except:
        return "Perl Core ไม่ตอบกลับ"

while True:
    # รับคำสั่งจาก Perl (หรือเราจะให้ Perl ส่งมา)
    action = input("Perl ส่ง action มา: ") or "heartbeat"  # ทดสอบ
    
    if action == "heartbeat":
        engine.respond_to_heartbeat("0xCEE9")
    else:
        engine.simulate_human_action()
    
    # ส่งผลกลับไปให้ Perl
    print(json.dumps({"status": "ok", "delay": time.time()}))
    
    time.sleep(0.5)  # หน่วงเล็กน้อยเหมือนคนเล่น