# step9_find_pid.py
import ctypes, ctypes.wintypes as wt
import struct

TARGET_PID = 17172   # เปลี่ยนจาก 19272
LOCAL_PORT = 59081   # เปลี่ยนจาก 54879

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
print("  Step 9 - Find PID in raw buffer")
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
data  = buf.raw
print(f"Count = {count}")
print(f"Target PID = {TARGET_PID} (0x{TARGET_PID:04X})")

# ค้นหา PID ใน buffer โดยตรง
pid_bytes = struct.pack('<H', TARGET_PID)
print(f"Searching for bytes: {pid_bytes.hex()}")

positions = []
i = 8  # เริ่มหลัง header
while i < min(len(data) - 2, 8 + count * 24):
    if data[i:i+2] == pid_bytes:
        positions.append(i)
    i += 24  # step entry size

print(f"Found PID at {len(positions)} entries")

if positions:
    print(f"\nFirst 5 entries with PID={TARGET_PID}:")
    for pos in positions[:5]:
        chunk = data[pos:pos+24]
        hex_s = ' '.join(f'{b:02X}' for b in chunk)
        pid = struct.unpack_from('<H', chunk, 0)[0]
        hv  = struct.unpack_from('<H', chunk, 6)[0]
        print(f"  offset={pos} hex={hex_s}")
        print(f"    PID={pid} Handle=0x{hv:04X}")

    # เก็บ handle values
    pid_handles = []
    for pos in positions:
        hv = struct.unpack_from('<H', data, pos + 6)[0]
        pid_handles.append(hv)

    print(f"\nAll handles ({len(pid_handles)}): {[hex(h) for h in pid_handles]}")

    # dup และ test socket
    cur = kernel32.GetCurrentProcess()
    rem = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, TARGET_PID)
    found_sock = 0

    print(f"\nTesting for socket port={LOCAL_PORT}...")
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
        print(f"\n✗ Socket ไม่เจอ")
        print(f"  → Gepard อาจซ่อน socket handle")
        print(f"  → ต้องใช้วิธีอื่น")
else:
    print(f"\nPID {TARGET_PID} ไม่เจอใน buffer เลย!")
    print(f"อาจเป็นเพราะ:")
    print(f"  1. PID เปลี่ยนแล้ว (restart game?)")
    print(f"  2. Entry size ไม่ใช่ 24")
    print(f"\nลอง check PID ปัจจุบัน:")
    import subprocess
    out = subprocess.check_output('tasklist | findstr BamBoo', shell=True).decode()
    print(f"  {out.strip()}")

print("\nDone!")