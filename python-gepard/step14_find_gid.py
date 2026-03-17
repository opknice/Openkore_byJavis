# step14_find_gid.py
import ctypes, ctypes.wintypes as wt
import struct

TARGET_PID    = 17172
PLAYER_X_ADDR = 0x015C0EE4

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
print("  Step 14 - Find Player GID")
print("="*50)

h = kernel32.OpenProcess(0x1F0FFF, False, TARGET_PID)

# dump 512 bytes รอบๆ X,Y address
print(f"Dump รอบๆ PLAYER_X_ADDR (0x{PLAYER_X_ADDR:08X}):")
print(f"{'Addr':12} {'Hex':48}  {'Values'}")
print("-"*80)

base = PLAYER_X_ADDR - 256
data = read_mem(h, base, 512)

for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    hex_s = ' '.join(f'{b:02X}' for b in chunk)
    real_a = base + i
    mark = "  ◄◄ X,Y" if real_a == PLAYER_X_ADDR else ""

    # แสดง values ที่น่าสนใจ
    vals = []
    for j in range(0, 13, 4):
        v = struct.unpack_from('<I', chunk, j)[0]
        # GID มักเป็น 0x10000000 - 0xFFFFFFFF (large number)
        if 0x10000000 <= v <= 0xFFFFFFFE:
            vals.append(f"[+{j}]=0x{v:08X}←GID?")
        elif 1 <= v <= 9999:
            vals.append(f"[+{j}]={v}")

    mark2 = "  " + ", ".join(vals) if vals else ""
    print(f"  0x{real_a:08X}  {hex_s}{mark}{mark2}")

print("\nDone! ดูค่าที่มี ←GID? ครับ")
print("GID จะเป็นตัวเลขใหญ่ unique ไม่เปลี่ยนตลอด session")