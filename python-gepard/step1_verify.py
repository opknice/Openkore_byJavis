# step1_verify.py
import ctypes, ctypes.wintypes as wt
import struct, subprocess

PROCESS_NAME = "BamBoo_Client.exe"
TARGET_PID   = 19272
TARGET_IP    = "136.110.172.32"
TARGET_PORT  = 24656
LOCAL_PORT   = 54879

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype        = ctypes.c_void_p
kernel32.ReadProcessMemory.restype  = wt.BOOL
kernel32.DuplicateHandle.restype    = wt.BOOL
kernel32.CloseHandle.restype        = wt.BOOL
kernel32.GetCurrentProcess.restype  = ctypes.c_void_p
ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
ws2.getsockname.restype = ctypes.c_int
ws2.getpeername.restype = ctypes.c_int
ws2.send.restype        = ctypes.c_int

PROCESS_ALL_ACCESS    = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 0x00000002

def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n   = ctypes.c_size_t(0)
    kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value]

def read_u32(h, addr):
    d = read_mem(h, addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

print("="*50)
print("  Step 1 - Verify Process + Socket")
print("="*50)

# 1. Open Process
h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
if h:
    print(f"[PROCESS] ✓ Opened PID={TARGET_PID}")
else:
    print(f"[PROCESS] ✗ Failed! Run as Administrator?")
    exit()

# 2. Find Socket via Dup
print(f"\n[SOCKET] Scanning handles...")
cur = kernel32.GetCurrentProcess()
rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
found_sock = 0

for hv in range(4, 0x10000, 4):
    lh = wt.HANDLE()
    ok = kernel32.DuplicateHandle(
        ctypes.c_void_p(rem), ctypes.c_void_p(hv),
        ctypes.c_void_p(cur), ctypes.byref(lh),
        0, False, DUPLICATE_SAME_ACCESS)
    if not ok:
        continue
    pb = ctypes.create_string_buffer(128)
    pl = ctypes.c_int(128)
    if ws2.getpeername(ctypes.c_uint(lh.value), pb, ctypes.byref(pl)) == 0:
        port = struct.unpack_from('>H', pb.raw, 2)[0]
        ip   = '.'.join(str(b) for b in pb.raw[4:8])
        lb = ctypes.create_string_buffer(128)
        ll = ctypes.c_int(128)
        ws2.getsockname(ctypes.c_uint(lh.value), lb, ctypes.byref(ll))
        lport = struct.unpack_from('>H', lb.raw, 2)[0]
        print(f"  handle=0x{hv:04X}  {ip}:{port}  local={lport}")
        if port == TARGET_PORT:
            found_sock = lh.value
            print(f"  ✓ GAME SOCKET FOUND! dup_handle=0x{found_sock:08X}")
            break
    kernel32.CloseHandle(lh)

kernel32.CloseHandle(ctypes.c_void_p(rem))

if not found_sock:
    print("[SOCKET] ✗ Not found")

# 3. Test send (ส่ง sync packet ดู)
if found_sock:
    print(f"\n[SEND TEST] Sending sync packet 0x007E...")
    # 0x007E = client heartbeat (ปลอดภัย ไม่ทำอะไร)
    pkt = struct.pack('<HI', 0x007E, 0)
    buf = ctypes.create_string_buffer(pkt)
    r   = ws2.send(ctypes.c_uint(found_sock), buf, len(pkt), 0)
    print(f"  send() returned {r} (expected {len(pkt)})")
    print(f"  {'✓ Socket works!' if r == len(pkt) else '✗ Send failed'}")

print("\n[DONE] Paste output มาให้ดูครับ!")