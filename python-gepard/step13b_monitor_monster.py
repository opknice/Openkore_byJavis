# step13b_monitor_monster.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID = 22840

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
print("  Step 13b - Monitor Monster Addresses")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)

# candidates จาก step 13
candidates = [0x1C4DF950, 0x1C4DF9C0]

# dump context ของแต่ละ address ก่อน
print("Context dump:")
for addr in candidates:
    print(f"\n0x{addr:08X}:")
    data = read_mem(h, addr - 16, 48)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        real_a = addr - 16 + i
        mark = " ◄" if real_a == addr else ""
        print(f"  0x{real_a:08X}  {hex_s}{mark}")

# stride ระหว่าง 2 addresses
stride = 0x1C4DF9C0 - 0x1C4DF950
print(f"\nStride between addresses: 0x{stride:X} = {stride} bytes")

# monitor live
print(f"\nMonitoring live (15 วิ) — ตี monster ด้วยครับ!")
print(f"{'Time':5} | {'Addr1 X,Y,HP':25} | {'Addr2 X,Y,HP':25}")
print("-"*60)

for i in range(30):
    row = f"[{i:02d}]  "
    for addr in candidates:
        x  = read_u32(h, addr)
        y  = read_u32(h, addr + 4)
        hp = read_u32(h, addr + 8)
        row += f"({x},{y}) hp={hp:<6} | "
    print(row)
    time.sleep(0.5)

# scan array จาก base
print(f"\nScanning array from 0x{candidates[0]:08X}...")
base = candidates[0]
print(f"{'Offset':8} {'Addr':12} {'X':5} {'Y':5} {'HP':8}")
print("-"*45)
for i in range(-3, 10):
    addr = base + i * stride
    x  = read_u32(h, addr)
    y  = read_u32(h, addr + 4)
    hp = read_u32(h, addr + 8)
    valid = "✓" if (0 < x < 320 and 0 < y < 320 and 0 < hp < 100000) else ""
    print(f"  [{i:+2d}]  0x{addr:08X}  {x:5} {y:5} {hp:8} {valid}")

print("\nDone!")