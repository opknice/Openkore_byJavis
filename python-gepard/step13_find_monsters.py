# step13_find_monsters.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID    = 22840
PLAYER_X_ADDR = 0x015C0EE4
PLAYER_Y_ADDR = 0x015C0EE8
MAP_W, MAP_H  = 300, 300

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

def get_regions(h):
    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress",ctypes.c_void_p),
                    ("AllocationBase",ctypes.c_void_p),
                    ("AllocationProtect",wt.DWORD),
                    ("RegionSize",ctypes.c_size_t),
                    ("State",wt.DWORD),
                    ("Protect",wt.DWORD),
                    ("Type",wt.DWORD)]
    regions = []
    addr = 0x10000
    while addr < 0x7FFF0000:
        mbi = MBI()
        if not kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        if (mbi.State == 0x1000 and
            mbi.Protect in {0x02, 0x04} and
            0x1000 <= mbi.RegionSize <= 0x200000):
            regions.append((addr, mbi.RegionSize))
        addr += max(mbi.RegionSize, 0x1000)
    return regions

def scan_xy(h, regions, mx, my):
    p = struct.pack('<II', mx, my)
    found = []
    for base, size in regions:
        data = read_mem(h, base, min(size, 0x50000))
        i = 0
        while i <= len(data) - 8:
            if data[i:i+8] == p:
                found.append(base + i)
            i += 4
    return found

print("="*50)
print("  Step 13 - Find Monster Array")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)
px = read_u32(h, PLAYER_X_ADDR)
py = read_u32(h, PLAYER_Y_ADDR)
print(f"Player pos: ({px},{py})")

regions = get_regions(h)
print(f"Regions: {len(regions)}")

# ── SCAN 1: หา monster position ──
print("\nเดินเข้าหา Monster แล้วดู X,Y ของมัน")
print("(กด Alt เพื่อดู label หรือดูจาก minimap)")
line = input("พิมพ์ X Y ของ Monster: ").split()
mx1, my1 = int(line[0]), int(line[1])

print(f"\nScanning for monster at ({mx1},{my1})...")
candidates = scan_xy(h, regions, mx1, my1)
print(f"Found {len(candidates)} addresses")
for c in candidates[:10]:
    # ดู HP ที่ offset +8
    hp = read_u32(h, c + 8)
    print(f"  0x{c:08X}  hp[+8]={hp}")

# ── SCAN 2: เดินไปอีกจุด narrow down ──
print("\nเดินไปอีกจุด แล้วพิมพ์ X Y ใหม่:")
line2 = input("X Y ใหม่ของ Monster: ").split()
mx2, my2 = int(line2[0]), int(line2[1])

confirmed = []
for c in candidates:
    cx = read_u32(h, c)
    cy = read_u32(h, c + 4)
    if cx == mx2 and cy == my2:
        confirmed.append(c)

print(f"\nConfirmed: {len(confirmed)} addresses")
for c in confirmed:
    hp  = read_u32(h, c + 8)
    print(f"  MONSTER_ADDR = 0x{c:08X}  hp={hp}")

# ── Monitor: ดู live data ──
if confirmed:
    print(f"\nMonitoring 0x{confirmed[0]:08X} (10 วิ)...")
    print("ตี monster เพื่อดู HP ลด")
    addr = confirmed[0]
    for i in range(20):
        x  = read_u32(h, addr)
        y  = read_u32(h, addr + 4)
        hp = read_u32(h, addr + 8)
        print(f"  [{i:02d}] pos=({x},{y}) hp={hp}")
        time.sleep(0.5)

print("\nDone!")