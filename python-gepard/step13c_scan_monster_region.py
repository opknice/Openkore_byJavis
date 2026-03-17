# step13c_scan_monster_region.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID     = 17172
KNOWN_MON_ADDR = 0x1C4DF950  # confirmed monster
MAP_W, MAP_H   = 320, 320
MON_HP_MAX     = 500          # HP monster ไม่เกิน 500

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype       = ctypes.c_void_p
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.VirtualQueryEx.restype    = ctypes.c_size_t

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value]

def read_u32(h, addr):
    d = read_mem(h, addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

def is_valid_monster(x, y, hp):
    return 0 < x < MAP_W and 0 < y < MAP_H and 0 < hp <= MON_HP_MAX

print("="*50)
print("  Step 13c - Scan Monster Region")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)

# scan region รอบๆ known monster address
# ลอง stride 16 bytes (จาก context dump)
STRIDE = 16
print(f"Scanning around 0x{KNOWN_MON_ADDR:08X} stride={STRIDE}...")
print(f"{'Addr':12} {'X':5} {'Y':5} {'HP':6}  Status")
print("-"*45)

monsters = []
for i in range(-50, 200):
    addr = KNOWN_MON_ADDR + i * STRIDE
    x  = read_u32(h, addr)
    y  = read_u32(h, addr + 4)
    hp = read_u32(h, addr + 8)
    if is_valid_monster(x, y, hp):
        print(f"  0x{addr:08X}  {x:5} {y:5} {hp:6}  ✓ MONSTER")
        monsters.append(addr)

print(f"\nTotal monsters found: {len(monsters)}")

# หา array base (entry แรก)
if monsters:
    array_base = min(monsters)
    print(f"Array base estimate: 0x{array_base:08X}")

    # monitor live
    print(f"\nMonitoring {len(monsters)} monsters (10 วิ)...")
    print("ตี monster ด้วยครับ!")
    for tick in range(20):
        line = f"[{tick:02d}] "
        for addr in monsters[:5]:
            x  = read_u32(h, addr)
            y  = read_u32(h, addr + 4)
            hp = read_u32(h, addr + 8)
            line += f"({x},{y})hp={hp} | "
        print(line)
        time.sleep(0.5)

    print(f"\n✅ MON_ARRAY_BASE   = 0x{array_base:08X}")
    print(f"✅ MON_STRIDE       = {STRIDE}")
    print(f"✅ MON_COUNT        = {len(monsters)}")

print("\nDone!")