# step11_find_xy.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID = 3448

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype       = ctypes.c_void_p
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.VirtualQueryEx.restype    = ctypes.c_size_t

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value]

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

def scan_value(h, regions, value):
    pat = struct.pack('<I', value)
    found = []
    for base, size in regions:
        data = read_mem(h, base, min(size, 0x50000))
        i = 0
        while i <= len(data) - 4:
            if data[i:i+4] == pat:
                found.append(base + i)
            i += 4
    return found

def narrow(h, addrs, value):
    pat = struct.pack('<I', value)
    return [a for a in addrs
            if read_mem(h, a, 4) == pat]

print("="*50)
print("  Step 11 - Find Player X,Y")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)
regions = get_regions(h)
print(f"Regions: {len(regions)}")

print("\nดูตำแหน่ง X,Y ในเกม (minimap หรือ alt+click)")
line = input("พิมพ์ X Y ตำแหน่งที่ 1: ").split()
x1, y1 = int(line[0]), int(line[1])

print(f"Scanning for X={x1}...")
candidates = scan_value(h, regions, x1)
print(f"Found {len(candidates)} addresses with X={x1}")

# กรองที่ Y อยู่ใกล้ๆ (offset +4)
pairs = []
for xa in candidates:
    d = read_mem(h, xa + 4, 4)
    if len(d) == 4 and struct.unpack('<I', d)[0] == y1:
        pairs.append(xa)
print(f"XY pairs found: {len(pairs)}")
for p in pairs[:10]:
    print(f"  0x{p:08X}")

print("\nเดินไปตำแหน่งใหม่แล้วพิมพ์ X Y:")
line2 = input("X Y ตำแหน่งที่ 2: ").split()
x2, y2 = int(line2[0]), int(line2[1])

confirmed = []
for xa in pairs:
    cx = struct.unpack('<I', read_mem(h, xa, 4))[0]
    cy = struct.unpack('<I', read_mem(h, xa+4, 4))[0]
    if cx == x2 and cy == y2:
        confirmed.append(xa)

if confirmed:
    print(f"\n✅ PLAYER_X_ADDR = 0x{confirmed[0]:08X}")
    print(f"✅ PLAYER_Y_ADDR = 0x{confirmed[0]+4:08X}")
else:
    print("ไม่เจอ ลองเดินไปอีกจุดแล้วพิมพ์ X Y:")
    line3 = input("X Y ตำแหน่งที่ 3: ").split()
    x3, y3 = int(line3[0]), int(line3[1])
    confirmed2 = []
    for xa in pairs:
        cx = struct.unpack('<I', read_mem(h, xa, 4))[0]
        cy = struct.unpack('<I', read_mem(h, xa+4, 4))[0]
        if cx == x3 and cy == y3:
            confirmed2.append(xa)
    if confirmed2:
        print(f"\n✅ PLAYER_X_ADDR = 0x{confirmed2[0]:08X}")
        print(f"✅ PLAYER_Y_ADDR = 0x{confirmed2[0]+4:08X}")
    else:
        print("ไม่เจอ — ลอง restart แล้วรันใหม่ครับ")

print("\nDone!")