# step4_socket_fixed.py
import ctypes, ctypes.wintypes as wt
import struct

TARGET_PID  = 19272
LOCAL_PORT  = 54879

ntdll    = ctypes.WinDLL('ntdll')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype        = ctypes.c_void_p
kernel32.DuplicateHandle.restype    = wt.BOOL
kernel32.CloseHandle.restype        = wt.BOOL
kernel32.GetCurrentProcess.restype  = ctypes.c_void_p
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong  # ← fix unsigned

ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
ws2.getsockname.restype = ctypes.c_int
ws2.send.restype        = ctypes.c_int

PROCESS_ALL_ACCESS    = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 0x00000002

class SYSTEM_HANDLE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("ProcessId",        ctypes.c_ulong),
        ("ObjectTypeNumber", ctypes.c_ubyte),
        ("Flags",            ctypes.c_ubyte),
        ("Handle",           ctypes.c_ushort),
        ("Object",           ctypes.c_void_p),
        ("GrantedAccess",    ctypes.c_ulong),
    ]

print("="*50)
print("  Step 4 - Find Socket (Fixed)")
print("="*50)

# ── Query system handles ──
buf_size = ctypes.c_ulong(0x40000)
buf      = None
for _ in range(10):
    buf    = ctypes.create_string_buffer(buf_size.value)
    ret_sz = ctypes.c_ulong(0)
    status = ntdll.NtQuerySystemInformation(
        16, buf, buf_size, ctypes.byref(ret_sz))
    print(f"  NtQuery status=0x{status:08X} buf={buf_size.value} needed={ret_sz.value}")
    if status == 0:
        break
    if ret_sz.value > 0:
        buf_size.value = ret_sz.value + 0x10000
    else:
        buf_size.value *= 2

if status != 0:
    print(f"NtQuerySystemInformation failed: 0x{status:08X}")
    # ลอง workaround อื่น
    print("\nลองวิธี WSASocket enumerate แทน...")
    exit()

count = struct.unpack_from('<I', buf.raw, 0)[0]
print(f"Total handles: {count}")

# ── หา handles ของ process ──
entry_size = ctypes.sizeof(SYSTEM_HANDLE_ENTRY)
pid_handles = []
for i in range(count):
    off = 4 + i * entry_size
    if off + entry_size > len(buf.raw):
        break
    e = SYSTEM_HANDLE_ENTRY.from_buffer_copy(buf.raw[off:off+entry_size])
    if e.ProcessId == TARGET_PID:
        pid_handles.append(int(e.Handle))

print(f"PID {TARGET_PID} has {len(pid_handles)} handles")
print(f"First 30: {[hex(h) for h in pid_handles[:30]]}")

# ── dup และ test getsockname ──
cur = kernel32.GetCurrentProcess()
rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
found_sock = 0

print(f"\nTesting each handle for socket on port {LOCAL_PORT}...")
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
    r  = ws2.getsockname(ctypes.c_uint(lh.value), lb, ctypes.byref(ll))
    if r == 0:
        lport = struct.unpack_from('>H', lb.raw, 2)[0]
        print(f"  handle=0x{hv:04X} → socket local_port={lport}")
        if lport == LOCAL_PORT:
            found_sock = lh.value
            print(f"  ✓ GAME SOCKET! dup=0x{found_sock:08X}")
            break
    kernel32.CloseHandle(lh)

kernel32.CloseHandle(ctypes.c_void_p(rem))

if found_sock:
    # test send heartbeat
    pkt = struct.pack('<HI', 0x007E, 0)
    b   = ctypes.create_string_buffer(pkt)
    r   = ws2.send(ctypes.c_uint(found_sock), b, len(pkt), 0)
    print(f"\n[SEND TEST] 0x007E → {r} bytes {'✓' if r > 0 else '✗'}")
    print(f"\n✅ SOCKET_HANDLE = 0x{found_sock:08X}")
else:
    print("\n✗ Socket ไม่เจอ")
    print("  handles ทั้งหมดที่เป็น socket:")

print("\nDone!")