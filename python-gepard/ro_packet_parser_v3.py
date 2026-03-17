# ro_packet_parser_v3.py
# แก้ไข: stream alignment, encryption detection, memory cross-check
# ต้องรันใฐานะ Administrator
# pip install pydivert

import pydivert
import struct, time, os, ctypes, ctypes.wintypes as wt
import logging
from datetime import datetime

# ── Config ──────────────────────────────────────────────
SERVER_IP   = "136.110.172.32"
SERVER_PORT = 24656
LOG_DIR     = "ro_logs"

# Memory addresses (จาก Log v1)
TARGET_PID    = 0           # 0 = auto-detect จาก process name
PLAYER_X_ADDR = 0x015C0EE4
PLAYER_Y_ADDR = 0x015C0EE8
HP_ADDR       = 0x015D8668
HPMAX_ADDR    = 0x015D866C
SP_ADDR       = 0x015D8670
SPMAX_ADDR    = 0x015D8674

MONSTER_TYPE_MIN = 1000
# ────────────────────────────────────────────────────────

# ── Logger ───────────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)
_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

class MsFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created)
        return ct.strftime('%H:%M:%S') + f'.{ct.microsecond // 1000:03d}'

def make_logger(name, path):
    lg = logging.getLogger(name)
    lg.setLevel(logging.DEBUG)
    h = logging.FileHandler(path, encoding='utf-8')
    h.setFormatter(MsFormatter('%(asctime)s %(message)s'))
    lg.addHandler(h)
    return lg

log_main = make_logger("main",    f"{LOG_DIR}/ro_session_{_ts}.log")
log_raw  = make_logger("raw",     f"{LOG_DIR}/ro_raw_{_ts}.log")
log_unk  = make_logger("unknown", f"{LOG_DIR}/ro_unknown_{_ts}.log")
log_sum  = make_logger("summary", f"{LOG_DIR}/ro_summary_{_ts}.log")
log_ver  = make_logger("verify",  f"{LOG_DIR}/ro_verify_{_ts}.log")  # ← ใหม่

# console handler
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(message)s'))
log_main.addHandler(sh)

def LOG(msg):  log_main.info(msg)
def LOGR(msg): log_raw.debug(msg)
def LOGU(msg): log_unk.debug(msg)
def LOGV(msg): log_ver.info(msg);  log_main.info(msg)

# ── Memory Reader ─────────────────────────────────────────
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.restype       = ctypes.c_void_p
kernel32.ReadProcessMemory.restype = wt.BOOL

_mem_handle = None

def init_memory(pid):
    global _mem_handle
    if pid == 0:
        pid = _find_pid("BamBoo_Client.exe")
    if pid:
        _mem_handle = kernel32.OpenProcess(0x10, False, pid)
        LOG(f"  [MEM   ] Attached PID={pid} handle=0x{_mem_handle or 0:X}")
    else:
        LOG("  [MEM   ] WARNING: ไม่พบ BamBoo_Client.exe")

def _find_pid(exe_name):
    import subprocess
    try:
        out = subprocess.check_output(
            ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/NH', '/FO', 'CSV'],
            stderr=subprocess.DEVNULL).decode()
        for line in out.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
                return int(parts[1])
    except Exception:
        pass
    return 0

def read_u32(addr):
    if not _mem_handle:
        return None
    buf = ctypes.create_string_buffer(4)
    n   = ctypes.c_size_t(0)
    ok  = kernel32.ReadProcessMemory(
        _mem_handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n))
    if ok and n.value == 4:
        return struct.unpack('<I', buf.raw)[0]
    return None

def mem_snapshot():
    """อ่านค่าจาก memory ทั้งหมดในครั้งเดียว"""
    return {
        'x':     read_u32(PLAYER_X_ADDR),
        'y':     read_u32(PLAYER_Y_ADDR),
        'hp':    read_u32(HP_ADDR),
        'hpmax': read_u32(HPMAX_ADDR),
        'sp':    read_u32(SP_ADDR),
        'spmax': read_u32(SPMAX_ADDR),
    }

# ── Known packet table: switch → (name, fixed_len) ───────
# -1 = variable (bytes 2-3 = length)
# 0  = unknown length
PACKETS = {
    # Server → Client
    0x0073: ("map_loaded",         11),
    0x0078: ("actor_exists",       -1),
    0x007B: ("actor_exists2",      -1),
    0x007C: ("map_actor",          -1),
    0x0080: ("actor_removed",       7),
    0x0086: ("actor_moved",        16),
    0x0087: ("actor_moved2",       -1),  # ← เพิ่ม (เห็นใน Wireshark)
    0x0088: ("damage",             29),
    0x008D: ("public_chat",        -1),
    0x0095: ("actor_name",         30),
    0x009A: ("system_chat",        -1),
    0x00B0: ("stat_info",           8),
    0x00B6: ("actor_coords",        6),
    0x00BD: ("stats_info",         -1),
    0x0141: ("stat_info2",         14),
    0x0195: ("actor_name2",        30),
    0x022C: ("actor_spawned",      -1),
    0x02AE: ("init_encrypt",       -1),  # key exchange
    0x02EE: ("actor_display",      -1),
    0x083E: ("init_encrypt2",      -1),
    0x0856: ("actor_display4",     -1),
    0x09FD: ("actor_display2",     -1),
    0x09FF: ("actor_display3",     -1),
    # ── Bamboo-specific / confirmed from logs ──────────────
    0x0000: ("null_packet",        -1),  # skill/item list entries
    0x0001: ("signal_01",           2),  # ← FIX: 2-byte signal (ไม่ใช่ variable)
    0x013A: ("signal_13a",          2),  # ← FIX: 2-byte signal
    0x1901: ("signal_1901",         2),  # 2-byte signal
    0x1A01: ("signal_1a01",         2),  # 2-byte signal
    0xFD00: ("signal_fd00",         8),  # 8-byte signal
    0xFE00: ("signal_fe00",         8),  # 8-byte signal
    # Client → Server
    0x0072: ("map_login",          -1),
    0x0436: ("map_login2",         -1),
    0x007D: ("map_loaded_ack",      2),
    0x0085: ("walk",               -1),
    0x0089: ("action",             -1),
    0x009F: ("item_take",          -1),
}

# ── Encryption ────────────────────────────────────────────
class Decryptor:
    def __init__(self):
        self.k1 = self.k2 = self.k3 = self.cur = 0
        self.on = False

    def set_keys(self, k1, k2, k3):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.cur = k1; self.on = True
        LOG(f"  [CRYPT ] KEYS SET k1=0x{k1:08X} k2=0x{k2:08X} k3=0x{k3:08X}")
        LOGV(f"[VERIFY] Encryption keys captured — decryption active")

    def decrypt(self, enc_sw):
        if not self.on or self.cur == 0:
            return enc_sw, False
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk = (self.cur >> 16) & 0x7FFF
        return (enc_sw ^ xk) & 0xFFFF, True

    def reset(self):
        self.cur = self.k1
        LOG("  [CRYPT ] key reset")

crypt = Decryptor()

# ── Entity tracker ────────────────────────────────────────
class Tracker:
    def __init__(self):
        self.E = {}   # id → entity dict
        self.N = {}   # id → name

    def update(self, eid, **kw):
        if eid not in self.E:
            self.E[eid] = {'id': eid, 'x': 0, 'y': 0,
                           'type': 0, 'name': '', 'last': time.time()}
        self.E[eid].update(kw)
        self.E[eid]['last'] = time.time()
        if eid in self.N:
            self.E[eid]['name'] = self.N[eid]

    def set_name(self, eid, name):
        self.N[eid] = name
        if eid in self.E:
            self.E[eid]['name'] = name

    def remove(self, eid):
        self.E.pop(eid, None)

    def cleanup(self):
        now = time.time()
        for k in [k for k, v in self.E.items() if now - v['last'] > 30]:
            del self.E[k]

    def monsters(self):
        return [e for e in self.E.values() if e['type'] >= MONSTER_TYPE_MIN]

    def players(self):
        return [e for e in self.E.values()
                if 0 < e['type'] < MONSTER_TYPE_MIN]

tracker = Tracker()

# ── Coord helpers ─────────────────────────────────────────
def dec3(b):
    return (b[0] << 2) | (b[1] >> 6), ((b[1] & 0x3F) << 4) | (b[2] >> 4), b[2] & 0xF

def dec6(b):
    return ((b[0] << 2) | (b[1] >> 6),
            ((b[1] & 0x3F) << 4) | (b[2] >> 4),
            ((b[2] & 0xF) << 6) | (b[3] >> 2),
            ((b[3] & 3) << 8) | b[4])

def up(fmt, data, off=0):
    sz = struct.calcsize(fmt)
    if off + sz > len(data): return None
    return struct.unpack_from(fmt, data, off)

# ── Packet handlers ───────────────────────────────────────
_last_verify = 0

def verify_with_memory(stat_name, packet_val):
    """เทียบค่าจาก packet กับ memory"""
    global _last_verify
    addr_map = {'HP': HP_ADDR, 'HPMAX': HPMAX_ADDR,
                'SP': SP_ADDR, 'SPMAX': SPMAX_ADDR}
    addr = addr_map.get(stat_name)
    if not addr:
        return
    mem_val = read_u32(addr)
    if mem_val is None:
        return
    match = "✅ MATCH" if packet_val == mem_val else f"❌ DIFF (mem={mem_val})"
    LOGV(f"  [VERIFY] {stat_name}: packet={packet_val} mem=0x{addr:08X}={mem_val} {match}")

def handle_stat_info(data):
    r = up('<HI', data, 2)
    if not r: return
    t, v = r
    names = {
        1:'BaseEXP', 2:'JobEXP',
        5:'HP', 6:'HPMAX', 7:'SP', 8:'SPMAX',
        9:'StatusPts', 11:'BaseLv', 12:'SkillPts',
        22:'BaseEXPMax', 23:'JobEXPMax',
        24:'Weight', 25:'MaxWeight',
        # combat stats (จาก log: types 41,43-46,48-53)
        41:'Attack',    43:'ItemDef',  44:'PlusDef',
        45:'MDef',      46:'PlusMDef', 48:'Hit',
        49:'Flee',      50:'PlusFlee', 51:'Critical',
        52:'PlusCrit',  53:'ASPD',
    }
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT  ] {n} = {v}")
    verify_with_memory(n, v)

def handle_stat_info2(data):
    # Format: switch(2) + type(4) + base(4) + bonus(4) = 14 bytes
    # ← FIX: type ต้องใช้ 'I' (4 bytes) ไม่ใช่ 'H' (2 bytes)
    r = up('<III', data, 2)
    if not r: return
    t, base, plus = r
    names = {13:'STR', 14:'AGI', 15:'VIT', 16:'INT', 17:'DEX', 18:'LUK'}
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT2 ] {n} base={base} bonus={plus} total={base+plus}")

def handle_actor_coords(data):
    """0x00B6: actor_coords — ID(4) + coords(3) + ... (6 bytes total)"""
    if len(data) < 6: return
    r = up('<I', data, 2)
    if not r: return
    eid = r[0]
    if len(data) >= 7:
        x, y, _ = dec3(data[4:7])
        tracker.update(eid, x=x, y=y)
        e = tracker.E.get(eid, {})
        label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
        LOG(f"  [{label:7s}] 0x{eid:08X} pos=({x},{y})")

def handle_actor_moved(data):
    if len(data) < 16: return
    r = up('<I6sI', data, 2)
    if not r: return
    eid, coords, tick = r
    fx, fy, tx, ty = dec6(coords)
    tracker.update(eid, x=tx, y=ty)
    e = tracker.E.get(eid, {})
    label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
    LOG(f"  [{label:7s}] 0x{eid:08X} ({fx},{fy})→({tx},{ty})")

def handle_actor_display(data, sw):
    try:
        if sw == 0x022C:
            r = up('<HH4sHHHIH', data, 0)
            if not r: return
            _, _, rid, _, _, _, _, jtype = r
            eid = struct.unpack('<I', rid)[0]
            for off in [46, 50, 54, 42, 38]:
                if off + 3 <= len(data):
                    x, y, _ = dec3(data[off:off+3])
                    if 0 < x < 2000 and 0 < y < 2000:
                        tracker.update(eid, x=x, y=y, type=jtype)
                        label = "MONSTER" if jtype >= MONSTER_TYPE_MIN else "player"
                        name  = tracker.N.get(eid, '')
                        LOG(f"  [{label:7s}] 0x{eid:08X} type={jtype} ({x},{y}) {name}")
                        break
        else:
            if len(data) < 12: return
            eid = struct.unpack_from('<I', data, 4)[0]
            for type_off in [14, 16, 18]:
                t = up('<H', data, type_off)
                if t and t[0] > 0:
                    for co in [54, 58, 50, 46]:
                        if co + 3 <= len(data):
                            x, y, _ = dec3(data[co:co+3])
                            if 0 < x < 2000 and 0 < y < 2000:
                                tracker.update(eid, x=x, y=y, type=t[0])
                                label = "MONSTER" if t[0] >= MONSTER_TYPE_MIN else "player"
                                LOG(f"  [{label:7s}] 0x{eid:08X} type={t[0]} ({x},{y})")
                                break
                    break
    except Exception:
        pass

def handle_actor_removed(data):
    if len(data) < 7: return
    r = up('<IB', data, 2)
    if not r: return
    eid, _ = r
    e = tracker.E.get(eid, {})
    label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
    LOG(f"  [REMOVE] 0x{eid:08X} ({label}) {e.get('name','')}")
    tracker.remove(eid)

def handle_actor_name(data):
    if len(data) < 30: return
    r = up('<I24s', data, 2)
    if not r: return
    eid, raw = r
    name = raw.split(b'\x00')[0].decode('utf-8', errors='replace').strip()
    tracker.set_name(eid, name)
    LOG(f"  [NAME  ] 0x{eid:08X} → '{name}'")

def handle_init_encrypt(data):
    """0x02AE / 0x083E — server ส่ง encryption keys"""
    # ลอง format: sw(2) + k1(4) + k2(4) + k3(4)
    r = up('<III', data, 2)
    if r:
        crypt.set_keys(*r)
        return
    # ลอง offset 4
    r = up('<III', data, 4)
    if r:
        crypt.set_keys(*r)
        return
    LOG(f"  [CRYPT ] init_encrypt received [{len(data)}B] hex={data[:16].hex()}")

# ── Dispatcher ────────────────────────────────────────────
_seen_unk = {}

def dispatch(data, direction):
    if len(data) < 2:
        return

    raw_sw = struct.unpack_from('<H', data, 0)[0]
    sw     = raw_sw
    dec    = False

    # decrypt ถ้า client→server และ encryption เปิดอยู่
    if direction == "→" and crypt.on:
        sw, dec = crypt.decrypt(raw_sw)

    # log raw
    enc_tag = f" [enc→0x{sw:04X}]" if dec else ""
    LOGR(f"{direction} 0x{sw:04X} [{len(data)}B]{enc_tag} {data[:32].hex(' ')}")

    info = PACKETS.get(sw)

    if info is None:
        if sw not in _seen_unk:
            _seen_unk[sw] = 0
            LOGU(f"{direction} 0x{sw:04X} [{len(data)}B] {data[:32].hex(' ')}")
        _seen_unk[sw] += 1
        if _seen_unk[sw] <= 2:
            LOG(f"  [?????] {direction} 0x{sw:04X} [{len(data)}B]{enc_tag}")
        return

    name, _ = info

    # suppress noisy packets จาก log หลัก
    _silent = {'null_packet', 'signal_01', 'signal_13a',
               'signal_1901', 'signal_1a01', 'signal_fd00', 'signal_fe00'}
    if name not in _silent:
        LOG(f"\n{direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_tag}")

    d = data if not dec else struct.pack('<H', sw) + data[2:]

    if sw in (0x02AE, 0x083E): handle_init_encrypt(d)
    elif sw == 0x0086:          handle_actor_moved(d)
    elif sw == 0x00B6:          handle_actor_coords(d)
    elif sw in (0x022C, 0x09FD, 0x09FF, 0x0856,
                0x02EE, 0x0078, 0x007B, 0x007C):
        handle_actor_display(d, sw)
    elif sw == 0x0080:          handle_actor_removed(d)
    elif sw in (0x0095, 0x0195): handle_actor_name(d)
    elif sw == 0x00B0:          handle_stat_info(d)
    elif sw == 0x0141:          handle_stat_info2(d)
    elif sw == 0x0073:
        crypt.reset()
        snap = mem_snapshot()
        LOG(f"  [MAP   ] Entered game | memory: {snap}")
    elif sw in (0x0001, 0x013A, 0x1901, 0x1A01):
        pass  # 2-byte signal packets — รับทราบเงียบๆ
    elif sw in (0xFD00, 0xFE00):
        pass  # 8-byte signal packets — รับทราบเงียบๆ
    elif sw == 0x0000:
        pass  # null/skill/item entries — suppress flood

# ── Stream buffer with sync ───────────────────────────────
class StreamBuf:
    def __init__(self, direction):
        self.buf = b''
        self.dir = direction
        self.synced = False

    def feed(self, data):
        self.buf += data
        self._sync()
        self._process()

    def _sync(self):
        """หา packet boundary แรกในกรณีที่เริ่มกลางทาง"""
        if self.synced:
            return
        # หา switch ที่รู้จักใน buffer
        for i in range(min(len(self.buf) - 1, 64)):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS:
                if i > 0:
                    LOG(f"  [SYNC  ] {self.dir} skipped {i} bytes to sync at 0x{sw:04X}")
                self.buf    = self.buf[i:]
                self.synced = True
                return
        # ไม่เจอเลย — ถ้า buffer ใหญ่แล้วให้ drop ส่วนหน้า
        if len(self.buf) > 32:
            self.buf    = self.buf[-8:]
            self.synced = False

    def _process(self):
        while len(self.buf) >= 2:
            sw   = struct.unpack_from('<H', self.buf, 0)[0]
            info = PACKETS.get(sw)
            plen = info[1] if info else 0

            if plen == -1:  # variable length
                if len(self.buf) < 4: break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 32768:
                    self.buf    = self.buf[1:]
                    self.synced = False
                    self._sync()
                    continue

            elif plen == 0:  # unknown switch
                # ── suppress encrypted client→server 2-byte noise ──
                if self.dir == "→" and len(self.buf) == 2:
                    break  # รอ data เพิ่ม
                if self.dir == "→" and len(self.buf) >= 4:
                    maybe = struct.unpack_from('<H', self.buf, 2)[0]
                    if 4 <= maybe <= 4096:
                        plen = maybe
                    else:
                        # encrypted 2-byte — log ไว้แต่ไม่แสดงบน console
                        LOGR(f"→ [ENC] 0x{sw:04X} [2B] {self.buf[:2].hex()}")
                        self.buf = self.buf[2:]
                        continue
                elif len(self.buf) >= 4:
                    maybe = struct.unpack_from('<H', self.buf, 2)[0]
                    if 4 <= maybe <= 4096:
                        plen = maybe
                    else:
                        dispatch(self.buf[:2], self.dir)
                        self.buf = self.buf[2:]
                        continue
                else:
                    break

            if len(self.buf) < plen:
                break

            dispatch(self.buf[:plen], self.dir)
            self.buf = self.buf[plen:]

# ── Summary ───────────────────────────────────────────────
def summary():
    tracker.cleanup()
    snap = mem_snapshot()
    lines = [
        f"\n{'═'*60}",
        f"  SUMMARY  {datetime.now().strftime('%H:%M:%S')}",
        f"{'─'*60}",
    ]
    if snap:
        lines.append(
            f"  Memory  : pos=({snap['x']},{snap['y']}) "
            f"HP={snap['hp']}/{snap['hpmax']} "
            f"SP={snap['sp']}/{snap['spmax']}")

    m = sorted(tracker.monsters(), key=lambda e: e.get('x', 0))
    p = sorted(tracker.players(),  key=lambda e: e.get('x', 0))
    lines += [f"\n  Monsters ({len(m)}):"]
    for e in m:
        lines.append(f"    0x{e['id']:08X}  ({e['x']},{e['y']})  {e.get('name', 'type='+str(e['type']))}")
    lines += [f"\n  Players ({len(p)}):"]
    for e in p:
        lines.append(f"    0x{e['id']:08X}  ({e['x']},{e['y']})  {e.get('name', '')}")
    lines.append(f"{'═'*60}")

    txt = '\n'.join(lines)
    LOG(txt)
    log_sum.info(txt)

# ── MAIN ─────────────────────────────────────────────────
def main():
    LOG("=" * 60)
    LOG("  RO Packet Parser v3")
    LOG(f"  Server : {SERVER_IP}:{SERVER_PORT}")
    LOG(f"  Logs   : {os.path.abspath(LOG_DIR)}/ro_*_{_ts}.log")
    LOG("=" * 60)

    init_memory(TARGET_PID)

    # verify memory ครั้งแรก
    snap = mem_snapshot()
    if snap and snap['x']:
        LOGV(f"[VERIFY] Initial memory: pos=({snap['x']},{snap['y']}) "
             f"HP={snap['hp']}/{snap['hpmax']} SP={snap['sp']}/{snap['spmax']}")

    LOG("\nรัน BamBoo_Client แล้ว login ได้เลย (ควรเริ่มก่อน login map)")
    LOG("กด Ctrl+C หยุด\n")

    buf_sv = StreamBuf("←")
    buf_cl = StreamBuf("→")

    flt = (f"tcp and "
           f"(ip.DstAddr=={SERVER_IP} or ip.SrcAddr=={SERVER_IP}) and "
           f"(tcp.DstPort=={SERVER_PORT} or tcp.SrcPort=={SERVER_PORT})")

    last_sum = time.time()

    try:
        with pydivert.WinDivert(flt) as w:
            for pkt in w:
                w.send(pkt)
                if not pkt.tcp or not pkt.payload:
                    continue
                payload = bytes(pkt.payload)
                if len(payload) < 2:
                    continue
                if pkt.dst_addr == SERVER_IP:
                    buf_cl.feed(payload)
                else:
                    buf_sv.feed(payload)

                if time.time() - last_sum > 15:
                    summary()
                    last_sum = time.time()

    except KeyboardInterrupt:
        LOG("\nหยุด")
        summary()
        LOG(f"\nUnknown switches: {len(_seen_unk)} ค่า")
        for sw, cnt in sorted(_seen_unk.items(), key=lambda x: -x[1])[:20]:
            LOG(f"  0x{sw:04X}  x{cnt}")

    except Exception as e:
        LOG(f"Error: {e}")
        LOG("ต้องรันใฐานะ Administrator")

if __name__ == '__main__':
    main()
