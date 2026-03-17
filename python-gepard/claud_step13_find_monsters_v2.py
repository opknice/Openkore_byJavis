# step14_proximity_scan.py
# หา Monster ทุกตัวในจอโดยใช้ Player position เป็น anchor
import ctypes, ctypes.wintypes as wt
import struct, time, math

# ── Config ──────────────────────────────────────────────
TARGET_PID    = 22840
PLAYER_X_ADDR = 0x015C0EE4
PLAYER_Y_ADDR = 0x015C0EE8
HP_ADDR       = 0x015D8668

MAP_MAX_X     = 512   # ขนาด map สูงสุด (ปรับตาม map จริง)
MAP_MAX_Y     = 512
SIGHT_RANGE   = 25    # range ที่มองเห็น monster บน screen

# scan เฉพาะ range ใกล้ player address
SCAN_BASE = (PLAYER_X_ADDR - 0x800000) & 0xFFF00000
SCAN_END  =  PLAYER_X_ADDR + 0x800000
# ────────────────────────────────────────────────────────

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype       = ctypes.c_void_p
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.VirtualQueryEx.restype    = ctypes.c_size_t

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    ok  = kernel32.ReadProcessMemory(
        h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok else b''

def read_u32(h, addr):
    d = read_mem(h, addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
    ]

def get_regions(h, start, end):
    regions = []
    addr = max(start, 0x10000)
    while addr < min(end, 0x7FFF0000):
        mbi = MBI()
        if not kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        if (mbi.State == 0x1000 and
            mbi.Protect in {0x02, 0x04, 0x20, 0x40}):
            regions.append((addr, mbi.RegionSize))
        addr += max(mbi.RegionSize, 0x1000)
    return regions

# ── Core: Proximity Scan ─────────────────────────────────
def proximity_scan(h, regions, px, py, radius=SIGHT_RANGE):
    """
    หาทุก address ที่มี value คล้าย:
      [X near px][Y near py][???][???]...
    """
    x_min = max(0,         px - radius)
    x_max = min(MAP_MAX_X, px + radius)
    y_min = max(0,         py - radius)
    y_max = min(MAP_MAX_Y, py + radius)

    candidates = []

    for base, size in regions:
        chunk = min(size, 0x200000)
        data  = read_mem(h, base, chunk)
        if len(data) < 8:
            continue

        i = 0
        while i <= len(data) - 8:
            # อ่าน X และ Y จาก offset i
            vx = struct.unpack_from('<I', data, i)[0]
            vy = struct.unpack_from('<I', data, i+4)[0]

            # กรอง: ทั้ง X และ Y ต้องอยู่ใน range
            if (x_min <= vx <= x_max and
                y_min <= vy <= y_max):

                addr = base + i

                # ข้ามถ้าเป็น player เอง
                if addr == PLAYER_X_ADDR:
                    i += 4
                    continue

                dist = math.sqrt((vx - px)**2 + (vy - py)**2)
                candidates.append({
                    'addr': addr,
                    'x':    vx,
                    'y':    vy,
                    'dist': dist,
                })
            i += 4

    # เรียงตาม distance จาก player
    candidates.sort(key=lambda c: c['dist'])
    return candidates

def filter_valid_entities(h, candidates):
    """
    กรอง false positives โดยดู field ถัดไป
    entity ที่ valid น่าจะมี:
      - offset +8  (HP?) ต้องเป็น value สมเหตุสมผล
      - offset +12 (HPMAX?) >= offset +8
      - ไม่ใช่ทุก field เป็น 0
    """
    valid = []
    for c in candidates:
        addr = c['addr']
        f8   = read_u32(h, addr + 8)
        f12  = read_u32(h, addr + 12)
        f16  = read_u32(h, addr + 16)
        f20  = read_u32(h, addr + 20)

        # กรอง: fields ถัดไปต้องไม่ใช่ pointer หรือ garbage
        if f8 > 10_000_000:    # ใหญ่เกิน = น่าจะเป็น pointer
            continue
        if f8 == 0 and f12 == 0:  # ทั้งคู่ 0 = น่าจะเป็น empty slot
            continue

        c['f8']  = f8
        c['f12'] = f12
        c['f16'] = f16
        c['f20'] = f20
        valid.append(c)

    return valid

def print_entities(entities, label="Entities"):
    print(f"\n  {label} ({len(entities)} ตัว):")
    print(f"  {'Addr':>10}  {'X':>5}  {'Y':>5}  {'Dist':>6}  "
          f"{'[+8]':>8}  {'[+12]':>8}  {'[+16]':>8}")
    print("  " + "─" * 65)
    for e in entities[:20]:
        print(f"  0x{e['addr']:08X}  "
              f"{e['x']:5}  {e['y']:5}  {e['dist']:6.1f}  "
              f"{e['f8']:8}  {e['f12']:8}  {e['f16']:8}")

# ── MAIN ────────────────────────────────────────────────
print("=" * 60)
print("  Step 14 - Proximity Scan (Monster Finder)")
print("=" * 60)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)
if not h:
    print(f"ERROR: OpenProcess failed")
    exit(1)

px = read_u32(h, PLAYER_X_ADDR)
py = read_u32(h, PLAYER_Y_ADDR)
hp = read_u32(h, HP_ADDR)
print(f"Player pos : ({px}, {py})")
print(f"Player HP  : {hp}")
print(f"Sight range: ±{SIGHT_RANGE} tiles")

regions = get_regions(h, SCAN_BASE, SCAN_END)
mb = sum(s for _, s in regions) / 1024 / 1024
print(f"Regions    : {len(regions)}  ({mb:.1f} MB)")

# ── Scan รอบแรก ──────────────────────────────────────────
print(f"\nScanning...", end='', flush=True)
t0 = time.time()
raw = proximity_scan(h, regions, px, py)
print(f" {len(raw)} raw hits  ({time.time()-t0:.1f}s)")

filtered = filter_valid_entities(h, raw)
print_entities(filtered, "Filtered entities near player")

if not filtered:
    print("\nไม่เจอ — ลอง:")
    print(f"  1. ขยาย SIGHT_RANGE (ปัจจุบัน {SIGHT_RANGE})")
    print(f"  2. ขยาย SCAN_BASE/SCAN_END")
    print(f"  3. ปรับ MAP_MAX_X/Y ให้ตรงกับ map จริง")
    exit(0)

# ── Live monitor: scan ซ้ำๆ ──────────────────────────────
print(f"\n{'='*60}")
print(f"  Live Monitor (กด Ctrl+C หยุด)")
print(f"{'='*60}")
print("เดินไปรอบๆ แล้วดูว่า entity list เปลี่ยนตามไหม")
print("ถ้า entity ที่ 'ใกล้ player' เปลี่ยนไปตาม = เจอ monster array แล้ว\n")

try:
    frame = 0
    while True:
        frame += 1
        px = read_u32(h, PLAYER_X_ADDR)
        py = read_u32(h, PLAYER_Y_ADDR)

        raw      = proximity_scan(h, regions, px, py)
        entities = filter_valid_entities(h, raw)

        print(f"\r[{frame}] Player({px},{py}) "
              f"| Nearby entities: {len(entities)}     ", end='', flush=True)

        # แสดง entity list ทุก 3 วิ
        if frame % 6 == 1:
            print()
            print_entities(entities, f"Frame {frame}")

        time.sleep(0.5)

except KeyboardInterrupt:
    print("\n\nหยุด monitor")

# ── สรุป ─────────────────────────────────────────────────
print(f"\n{'─'*60}")
print("วิเคราะห์ผล:")
print("  ถ้าเห็น address เดิมซ้ำๆ แสดงว่าเป็น monster struct จริง")
print("  ถ้า address เปลี่ยนตลอด แสดงว่า false positive")
print("\nขั้นต่อไป:")
print("  1. เอา address ที่ซ้ำๆ ไปดู offset pattern")
print("  2. หา stride (ขนาด struct) = addr[1] - addr[0]")
print("  3. ถ้า stride คงที่ = เจอ array แล้วค่ะ!")
print("\nDone!")