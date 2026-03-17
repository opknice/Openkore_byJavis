# step10_getpeername.py
import ctypes, ctypes.wintypes as wt
import struct, socket

TARGET_PID  = 17172
SERVER_IP   = "136.110.172.32"
SERVER_PORT = 24656

ntdll    = ctypes.WinDLL('ntdll')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype        = ctypes.c_void_p
kernel32.DuplicateHandle.restype    = wt.BOOL
kernel32.CloseHandle.restype        = wt.BOOL
kernel32.GetCurrentProcess.restype  = ctypes.c_void_p
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong
ws2 = ctypes.WinDLL('ws2_32', use_last_error=True)
ws2.getpeername.restype = ctypes.c_int
ws2.getsockname.restype = ctypes.c_int
ws2.send.restype        = ctypes.c_int

PROCESS_ALL_ACCESS    = 0x1F0FFF
DUPLICATE_SAME_ACCESS = 0x00000002

# แปลง server IP เป็น bytes
server_ip_bytes = socket.inet_aton(SERVER_IP)

print("="*50)
print("  Step 10 - Find Socket via getpeername")
print("="*50)
print(f"Looking for connection to {SERVER_IP}:{SERVER_PORT}")

# Query handles
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
data  = buf.raw

# หา handles ของ TARGET_PID
pid_bytes = struct.pack('<H', TARGET_PID)
pid_handles = []
for i in range(count):
    off = 8 + i * 24
    if off + 24 > len(data): break
    if data[off:off+2] == pid_bytes:
        hv = struct.unpack_from('<H', data, off + 6)[0]
        pid_handles.append(hv)

print(f"PID {TARGET_PID}: {len(pid_handles)} handles")

# dup ทีละตัว ใช้ getpeername เช็ค remote address
cur = kernel32.GetCurrentProcess()
rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
found_sock  = 0
found_hv    = 0
all_sockets = []

for hv in pid_handles:
    lh = wt.HANDLE()
    ok = kernel32.DuplicateHandle(
        ctypes.c_void_p(rem), ctypes.c_void_p(hv),
        ctypes.c_void_p(cur), ctypes.byref(lh),
        0, False, DUPLICATE_SAME_ACCESS)
    if not ok:
        continue

    # ลอง getpeername
    pb = ctypes.create_string_buffer(128)
    pl = ctypes.c_int(128)
    r  = ws2.getpeername(ctypes.c_uint(lh.value), pb, ctypes.byref(pl))
    if r == 0:
        rport = struct.unpack_from('>H', pb.raw, 2)[0]
        rip   = socket.inet_ntoa(pb.raw[4:8])
        all_sockets.append((hv, rip, rport, lh.value))
        print(f"  Socket: 0x{hv:04X} → {rip}:{rport}")
        if rip == SERVER_IP and rport == SERVER_PORT:
            found_sock = lh.value
            found_hv   = hv
            print(f"  ✓ GAME SOCKET FOUND!")
            break
        continue

    kernel32.CloseHandle(lh)

kernel32.CloseHandle(ctypes.c_void_p(rem))

print(f"\nAll sockets found: {len(all_sockets)}")
for hv, ip, port, _ in all_sockets:
    print(f"  0x{hv:04X} → {ip}:{port}")

if found_sock:
    # test send
    pkt = struct.pack('<HI', 0x007E, 0)
    b   = ctypes.create_string_buffer(pkt)
    r   = ws2.send(ctypes.c_uint(found_sock), b, len(pkt), 0)
    print(f"\n[SEND] heartbeat → {r} bytes {'✓' if r > 0 else '✗'}")
    print(f"\n✅ SOCKET_HANDLE  = 0x{found_sock:08X}")
    print(f"✅ ORIG_HANDLE    = 0x{found_hv:04X}")
else:
    print(f"\n✗ Game socket ไม่เจอ")
    print(f"  ถ้า all_sockets = 0 → Gepard hook getpeername ด้วย")
    print(f"  ถ้า all_sockets > 0 → IP:Port ไม่ตรง")

print("\nDone!")