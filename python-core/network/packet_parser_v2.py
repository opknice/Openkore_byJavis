import struct
import re
import os
from pathlib import Path

# หาไฟล์อัตโนมัติ
DEFAULT_FILE = Path(__file__).parent / "output-packet.txt"

def parse_ro_packet(data: bytes):
    if len(data) < 4:
        return None, None, b''
    length = struct.unpack_from('<H', data, 0)[0]
    opcode = struct.unpack_from('<H', data, 2)[0]
    payload = data[4:length] if length <= len(data) else data[4:]
    return length, f"0x{opcode:04X}", payload

def detect_gepard_pattern(opcode: str, payload_len: int):
    if opcode in ["0xCEE9", "0xDF3E"]:
        return "🚨 Gepard 3.0 Anti-Bot Check Packet!"
    if payload_len > 40000:
        return "🚨 ขนาดใหญ่พิเศษ (Gepard Heartbeat)"
    if payload_len in [2, 6, 12, 14]:
        return "⚠️ Packet ขนาดเล็กซ้ำ (Timing Check)"
    return ""

def analyze_capture(text_file=None):
    if text_file is None:
        text_file = DEFAULT_FILE
    if not os.path.exists(text_file):
        print(f"❌ ไม่พบไฟล์: {text_file}")
        return
    
    with open(text_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Regex ใหม่ที่แข็งแรงขึ้น (รองรับ format Wireshark จริง)
    hex_blocks = re.findall(r'(?:[0-9a-fA-F]{2}\s+){8,}', content)
    
    print("=== AetherCore Packet Parser v3 (Bamboo Server + Gepard 3.0) ===")
    print(f"Client: BamBoo_Client.exe | วิเคราะห์จาก {text_file.name}\n")
    
    packet_count = 0
    for block in hex_blocks:
        try:
            clean_hex = re.sub(r'\s+', '', block)
            pkt_bytes = bytes.fromhex(clean_hex)
            length, opcode, payload = parse_ro_packet(pkt_bytes)
            
            if length and length > 0:
                packet_count += 1
                note = detect_gepard_pattern(opcode, len(payload))
                print(f"Packet {packet_count:3d} | Len={length:5d} | Opcode={opcode} | Payload={len(payload):4d} bytes")
                if note:
                    print(f"   {note}")
        except:
            continue
    
    print(f"\n✅ วิเคราะห์เสร็จ! พบ {packet_count} packet")

if __name__ == "__main__":
    analyze_capture()