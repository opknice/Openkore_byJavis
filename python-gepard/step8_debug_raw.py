# step8_debug_raw.py
import ctypes, ctypes.wintypes as wt
import struct

TARGET_PID = 19272

ntdll = ctypes.WinDLL('ntdll')
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong

print("="*50)
print("  Step 8 - Debug Raw Bytes")
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
print(f"Count = {count}")

# dump 128 bytes แรก เพื่อดู structure จริงๆ
print(f"\nFirst 128 bytes of buffer:")
for i in range(0, 128, 16):
    chunk = buf.raw[i:i+16]
    hex_s = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  [{i:3d}] {hex_s}")

# ลอง entry sizes ทุกแบบ
print(f"\nTrying different entry sizes and offsets:")
for entry_size in [16, 24, 32]:
    for start_off in [4, 8]:
        hits = 0
        for i in range(min(count, 1000)):
            off = start_off + i * entry_size
            if off + entry_size > len(buf.raw):
                break
            # ลอง ProcessId เป็น USHORT ที่ offset ต่างๆ
            for pid_off in [0, 2, 4]:
                try:
                    pid = struct.unpack_from('<H', buf.raw, off + pid_off)[0]
                    if pid == TARGET_PID:
                        hv = struct.unpack_from('<H', buf.raw, off + pid_off + 4)[0]
                        hits += 1
                except: pass
        if hits > 0:
            print(f"  entry_size={entry_size} start={start_off}: {hits} hits for PID={TARGET_PID}")

print("\nDone! Paste output มาครับ")