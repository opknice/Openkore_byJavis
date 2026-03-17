# step7_offset_fix.py
import ctypes, ctypes.wintypes as wt
import struct

TARGET_PID = 19272
LOCAL_PORT = 54879

ntdll    = ctypes.WinDLL('ntdll')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype        = ctypes.c_void_p
kernel32.DuplicateHandle.restype    = wt.BOOL
kernel32.CloseHandle.restype        = wt.BOOL
kernel32.GetCurrentProcess.restype  = ctypes.c_void_p
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong
ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
ws2.getsockname.restype = ctypes.c_int
ws2.send.restype        = ctypes.c_int

PROCESS_ALL_ACCESS    = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 0x00000002

print("="*50)
print("  Step 7 - Socket (Offset Fix)")
print("="*50)

# Query
buf_size = ctypes.c_ulong(0x40000)
for _ in range(10):
    buf    = ctypes.create_string_buffer(buf_size.value)
    ret_sz = ctypes.c_ulong(0)
    status = ntdll.NtQuerySystemInformation(
        16, buf, buf_size, ctypes.byref(ret_sz))
    if status == 0:
        break
    buf_size.value = ret_sz.value + 0x10000

count = struct.unpack_from('<I', buf.raw, 0)[0]
print(f"Total handles: {count}")

# 64-bit: SYSTEM_HANDLE_TABLE_ENTRY_INFO = 24 bytes
# SYSTEM_HANDLE_INFORMATION header:
#   offset 0: ULONG NumberOfHandles (4 bytes)
#   offset 4: padding (4 bytes) ← 64-bit alignment
#   offset 8: array starts ← แก้จาก 4 เป็น 8
ARRAY_OFFSET = 8   # ← fix สำคัญ
ENTRY_SIZE   = 24

data = buf.raw
pid_handles = []

for i in range(count):
    off = ARRAY_OFFSET + i * ENTRY_SIZE
    if off + ENTRY_SIZE > len(data):
        break
    pid = struct.unpack_from('<H', data, off)[0]      # UniqueProcessId
    hv  = struct.unpack_from('<H', data, off + 6)[0]  # HandleValue
    if pid == TARGET_PID:
        pid_handles.append(hv)

print(f"PID {TARGET_PID}: {len(pid_handles)} handles")
if pid_handles:
    print(f"Handles: {[hex(h) for h in pid_handles[:30]]}")

# dup และ test
cur = kernel32.GetCurrentProcess()
rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
found_sock = 0

print(f"\nTesting {len(pid_handles)} handles...")
for hv in pid_handles:
    lh = wt.HANDLE()
    ok = kernel32.DuplicateHandle(
        ctypes.c_void_p(rem), ctypes.c_void_p(hv),
        ctypes.c_void_p(cur), ctypes.byref(lh),
        0, False, DUPLICATE_SAME_ACCESS)
    if not ok:
        continue
    lb = ctypes.create_string_buffer(128)
    ll = ctypes.c_int(128)
    if ws2.getsockname(ctypes.c_uint(lh.value), lb, ctypes.byref(ll)) == 0:
        lport = struct.unpack_from('>H', lb.raw, 2)[0]
        print(f"  Socket: 0x{hv:04X} → port={lport}")
        if lport == LOCAL_PORT:
            found_sock = lh.value
            print(f"  ✓ GAME SOCKET! dup=0x{found_sock:08X}")
            break
    kernel32.CloseHandle(lh)

kernel32.CloseHandle(ctypes.c_void_p(rem))

if found_sock:
    pkt = struct.pack('<HI', 0x007E, 0)
    b   = ctypes.create_string_buffer(pkt)
    r   = ws2.send(ctypes.c_uint(found_sock), b, len(pkt), 0)
    print(f"\n[SEND] → {r} bytes {'✓' if r > 0 else '✗'}")
    print(f"✅ SOCKET_HANDLE = 0x{found_sock:08X}")
else:
    print(f"\n✗ ไม่เจอ socket")

print("\nDone!")