import random
import time
import json
from pathlib import Path

class GepardRandomizer:
    def __init__(self):
        self.last_heartbeat = 0
        print("🚀 Gepard Randomization Engine เริ่มทำงาน (Bamboo Server)")

    def get_random_delay(self, base=0.3):
        """Random delay แบบมนุษย์ (0.15 - 0.45 วินาที)"""
        return base + random.uniform(-0.15, 0.15)

    def respond_to_heartbeat(self, opcode):
        """ตอบ Gepard Heartbeat แบบสุ่มเวลา"""
        if opcode in ["0xCEE9", "0xDF3E"]:
            delay = self.get_random_delay(0.25)
            time.sleep(delay)
            print(f"✅ ตอบ Gepard Heartbeat (Opcode {opcode}) ด้วย delay {delay:.3f}s")
            return True
        return False

    def simulate_human_action(self):
        """จำลองการกดปุ่ม/เดินแบบมนุษย์"""
        actions = ["walk", "attack", "loot", "skill"]
        action = random.choice(actions)
        delay = self.get_random_delay(0.2)
        time.sleep(delay)
        print(f"👤 Simulate Human: {action} (delay {delay:.3f}s)")

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    engine = GepardRandomizer()
    
    # ทดสอบกับ pattern ที่เราพบ
    for i in range(5):
        engine.respond_to_heartbeat("0xCEE9")
        engine.simulate_human_action()
        print("-" * 40)
    
    print("\n✅ Randomization Engine พร้อมใช้แล้ว!")
    print("ขั้นต่อไป: เราจะนำ engine นี้ไปเชื่อมกับ Perl Core")