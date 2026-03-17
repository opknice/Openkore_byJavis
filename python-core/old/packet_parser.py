import struct
import re

def parse_ro_packet(data: bytes):
    """Parse RO Packet: [2 bytes length LE] [2 bytes opcode] [payload]"""
    if len(data) < 4:
        return None, None, None
    
    length = struct.unpack_from('<H', data, 0)[0]   # Little Endian
    opcode = struct.unpack_from('<H', data, 2)[0]
    payload = data[4:]
    
    return length, f"0x{opcode:04X}", payload

def analyze_capture(text_file="Phase1.txt"):
    with open(text_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # หา hex data ทั้งหมดจาก Wireshark export
    hex_blocks = re.findall(r'([0-9a-fA-F ]{8,})', content)
    
    print("=== AetherCore Packet Analyzer (Bamboo Server) ===")
    for i, block in enumerate(hex_blocks):
        try:
            clean_hex = ''.join(block.split())
            pkt_bytes = bytes.fromhex(clean_hex)
            length, opcode, payload = parse_ro_packet(pkt_bytes)
            if length:
                print(f"Packet {i:3d} | Len={length:5d} | Opcode={opcode} | Payload={len(payload)} bytes")
                if b"Bamboo Ragnarok" in payload:
                    print("   >>> พบ Server Welcome Message!")
        except:
            pass  # ข้าม packet ที่ไม่ใช่ RO

if __name__ == "__main__":
    analyze_capture()