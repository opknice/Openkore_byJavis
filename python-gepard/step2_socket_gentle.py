# step2_socket_gentle.py
import ctypes, ctypes.wintypes as wt
import struct, time

TARGET_PID   = 19272
TARGET_PORT  = 24656
LOCAL_PORT   = 54879  # จาก netstat

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype        = ctypes.c_void_p
kernel32.DuplicateHandle.restype    = wt.BOOL
kernel32.CloseHandle.restype        = wt.BOOL
kernel32.GetCurrentProcess.restype  = ctypes.c_void_p
ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
ws2.getsockname.restype = ctypes.c_int
ws2.getpeername.restype = ctypes.c_int
ws2.send.restype        = ctypes.c_int

PROCESS_ALL_ACCESS    = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 0x00000002

print("="*50)
print("  Step 2 - Find Socket (Gentle)")
print("="*50)

h   = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
cur = kernel32.GetCurrentProcess()
rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)

found_sock  = 0
found_origH = 0

# scan ทีละน้อย มี delay และหยุดทันทีที่เจอ
for hv in range(4, 0x4000, 4):
    lh = wt.HANDLE()
    ok = kernel32.DuplicateHandle(
        ctypes.c_void_p(rem), ctypes.c_void_p(hv),
        ctypes.c_void_p(cur), ctypes.byref(lh),
        0, False, DUPLICATE_SAME_ACCESS)
    if not ok:
        continue

    # ลอง getsockname เช็ค local port
    lb = ctypes.create_string_buffer(128)
    ll = ctypes.c_int(128)
    if ws2.getsockname(ctypes.c_uint(lh.value), lb, ctypes.byref(ll)) == 0:
        lport = struct.unpack_from('>H', lb.raw, 2)[0]
        if lport == LOCAL_PORT:
            found_sock  = lh.value
            found_origH = hv
            print(f"[SOCKET] ✓ Found! orig=0x{hv:04X} dup=0x{found_sock:08X}")
            break

    kernel32.CloseHandle(lh)
    # delay เล็กน้อย ไม่ให้ aggressive
    if hv % 400 == 0:
        time.sleep(0.01)

kernel32.CloseHandle(ctypes.c_void_p(rem))

if not found_sock:
    # ลอง range สูงกว่า
    print("[SOCKET] ไม่เจอใน 0x0004-0x4000 ลอง 0x4000-0x10000...")
    rem2 = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
    for hv in range(0x4000, 0x10000, 4):
        lh = wt.HANDLE()
        ok = kernel32.DuplicateHandle(
            ctypes.c_void_p(rem2), ctypes.c_void_p(hv),
            ctypes.c_void_p(cur), ctypes.byref(lh),
            0, False, DUPLICATE_SAME_ACCESS)
        if not ok:
            continue
        lb = ctypes.create_string_buffer(128)
        ll = ctypes.c_int(128)
        if ws2.getsockname(ctypes.c_uint(lh.value), lb, ctypes.byref(ll)) == 0:
            lport = struct.unpack_from('>H', lb.raw, 2)[0]
            if lport == LOCAL_PORT:
                found_sock  = lh.value
                found_origH = hv
                print(f"[SOCKET] ✓ Found! orig=0x{hv:04X} dup=0x{found_sock:08X}")
                break
        kernel32.CloseHandle(lh)
        if hv % 400 == 0:
            time.sleep(0.01)
    kernel32.CloseHandle(ctypes.c_void_p(rem2))

if found_sock:
    # test ส่ง heartbeat
    print(f"\n[TEST] Sending heartbeat 0x007E...")
    pkt = struct.pack('<HI', 0x007E, 0)
    buf = ctypes.create_string_buffer(pkt)
    r   = ws2.send(ctypes.c_uint(found_sock), buf, len(pkt), 0)
    print(f"  Result: {r} bytes sent ({'✓' if r > 0 else '✗'})")
    print(f"\n✓ SOCKET_HANDLE = 0x{found_sock:08X}")
    print(f"✓ ORIG_HANDLE   = 0x{found_origH:04X}")
else:
    print("[SOCKET] ✗ ไม่เจอเลย — Gepard อาจ protect socket handles")

print("\nDone! Paste output มาครับ")