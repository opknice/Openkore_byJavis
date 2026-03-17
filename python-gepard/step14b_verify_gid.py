# step14b_verify_gid.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID    = 17172
PLAYER_X_ADDR = 0x015C0EE4

# candidates จาก step14
GID_CANDIDATES = {
    "0x015C0EC4+0":  0x015C0EC4,
    "0x015C0EC4+4":  0x015C0EC8,
    "0x015C0EC4+12": 0x015C0ED0,
}

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype       = ctypes.c_void_p
kernel32.ReadProcessMemory.restype = wt.BOOL

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value]

def read_u32(h, addr):
    d = read_mem(h, addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

print("="*50)
print("  Step 14b - Verify GID")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)

# อ่านค่าเริ่มต้น
print("Initial values:")
initial = {}
for name, addr in GID_CANDIDATES.items():
    val = read_u32(h, addr)
    initial[name] = val
    print(f"  {name} = 0x{val:08X} ({val})")

# monitor 10 วิ — เดิน/ตี monster ระหว่างนี้
print("\nMonitoring 10 วิ (เดิน/ตี monster ด้วยครับ)...")
print(f"{'Tick':5} | {'0x015C0EC4':12} | {'0x015C0EC8':12} | {'0x015C0ED0':12}")
print("-"*55)

for tick in range(20):
    vals = []
    for name, addr in GID_CANDIDATES.items():
        v = read_u32(h, addr)
        vals.append(f"0x{v:08X}")
    changed = " ← changed!" if any(
        read_u32(h, addr) != initial[name]
        for name, addr in GID_CANDIDATES.items()
    ) else ""
    print(f"  [{tick:02d}]  {' | '.join(vals)}{changed}")
    time.sleep(0.5)

print("\nResult:")
for name, addr in GID_CANDIDATES.items():
    final = read_u32(h, addr)
    status = "✅ STABLE = GID!" if final == initial[name] else "❌ Changed = not GID"
    print(f"  {name} = 0x{final:08X}  {status}")

print("\nDone!")