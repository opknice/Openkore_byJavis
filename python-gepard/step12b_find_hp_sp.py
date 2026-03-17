# step12b_find_hp_sp.py
import ctypes, ctypes.wintypes as wt
import struct, re

TARGET_PID    = 22840
PLAYER_X_ADDR = 0x015C0EE4
PLAYER_Y_ADDR = 0x015C0EE8

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

def parse_input(text):
    """รองรับ '187 187' หรือ '187/187' หรือ '187 / 187'"""
    nums = re.findall(r'\d+', text)
    return int(nums[0]), int(nums[1])

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

def scan_pair(h, regions, v1, v2):
    p1 = struct.pack('<I', v1)
    p2 = struct.pack('<I', v2)
    found = []
    for base, size in regions:
        data = read_mem(h, base, min(size, 0x50000))
        i = 0
        while i <= len(data) - 8:
            if data[i:i+4] == p1 and data[i+4:i+8] == p2:
                found.append(base + i)
            i += 4
    return found

def narrow(h, candidates, v1, v2):
    result = []
    for addr in candidates:
        if read_u32(h, addr) == v1 and read_u32(h, addr+4) == v2:
            result.append(addr)
    return result

print("="*50)
print("  Step 12b - Find HP/SP Address")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)
px = read_u32(h, PLAYER_X_ADDR)
py = read_u32(h, PLAYER_Y_ADDR)
print(f"Player pos: ({px},{py})")

regions = get_regions(h)
print(f"Regions: {len(regions)}")

# ── SCAN 1 ──
print("\nพิมพ์ HP/HP_MAX และ SP/SP_MAX จากเกม")
print("รูปแบบ: '187 187' หรือ '187/187' ก็ได้")
hp1, hpmax1 = parse_input(input("HP / HP_MAX: "))
sp1, spmax1 = parse_input(input("SP / SP_MAX: "))
print(f"Input: HP={hp1}/{hpmax1}  SP={sp1}/{spmax1}")

print(f"\nScanning...")
hp_cands = scan_pair(h, regions, hp1, hpmax1)
sp_cands = scan_pair(h, regions, sp1, spmax1)
print(f"HP candidates: {len(hp_cands)}")
print(f"SP candidates: {len(sp_cands)}")

# ── SCAN 2 — ให้ HP/SP เปลี่ยน ──
print("\n" + "="*40)
print("ทำให้ HP/SP เปลี่ยนก่อนครับ:")
print("  HP ลด → ให้ monster ตี")
print("  SP ลด → ใช้ skill")
print("="*40)
input("กด Enter เมื่อ HP/SP เปลี่ยนแล้ว...")

hp2, hpmax2 = parse_input(input("HP / HP_MAX ใหม่: "))
sp2, spmax2 = parse_input(input("SP / SP_MAX ใหม่: "))

confirmed_hp = narrow(h, hp_cands, hp2, hpmax2)
confirmed_sp = narrow(h, sp_cands, sp2, spmax2)

print(f"\nConfirmed HP: {len(confirmed_hp)}")
for a in confirmed_hp:
    print(f"  HP_ADDR    = 0x{a:08X}")
    print(f"  HPMAX_ADDR = 0x{a+4:08X}")

print(f"\nConfirmed SP: {len(confirmed_sp)}")
for a in confirmed_sp:
    print(f"  SP_ADDR    = 0x{a:08X}")
    print(f"  SPMAX_ADDR = 0x{a+4:08X}")

# ── Bonus: dump รอบๆ X,Y ──
print(f"\nDump รอบๆ PLAYER_X_ADDR:")
base = PLAYER_X_ADDR - 32
data = read_mem(h, base, 128)
for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    hex_s = ' '.join(f'{b:02X}' for b in chunk)
    real_a = base + i
    vals = []
    for j in range(0, 13, 4):
        v = struct.unpack_from('<I', chunk, j)[0]
        if 1 <= v <= 99999:
            vals.append(f"[+{j}]={v}")
    mark  = "  ◄ " + ", ".join(vals) if vals else ""
    mark2 = "  ◄◄ X,Y" if real_a == PLAYER_X_ADDR else ""
    print(f"  0x{real_a:08X}  {hex_s}{mark2}{mark}")

print("\nDone!")