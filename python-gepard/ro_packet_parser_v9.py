# ro_packet_parser_v9.py
# ================================================================
#  Changes from v8:
#  [FIX]  StreamBuf._sync(): instead of discarding unrecognised
#         leading bytes, every 2-byte chunk is pushed to enc_buf
#         so the KeyExtractor sees ALL client packets from the very
#         first byte — the 47-byte Gepard handshake that was
#         previously dropped is now captured.
#  [NEW]  raw log records the full 47 pre-sync bytes verbatim so
#         we can inspect the Gepard handshake offline.
#  [NEW]  LOGR format: unified "0xSW [NB] hex" so pre-sync bytes
#         appear in ro_raw_*.log for analysis.
# ================================================================
# Requirements: pip install pydivert
# Must run as Administrator
# ================================================================

import struct, time, os, ctypes, ctypes.wintypes as wt
import logging
from datetime import datetime
from collections import defaultdict, deque

# ── Config ──────────────────────────────────────────────────────
SERVER_IP    = "136.110.172.32"
MAP_PORT     = 24656           # known map server port
LOG_DIR      = "ro_logs"
OPENKORE_DIR = "openkore_out"

TARGET_PID    = 0
PLAYER_X_ADDR = 0x015C0EE4
PLAYER_Y_ADDR = 0x015C0EE8
HP_ADDR       = 0x015D8668
HPMAX_ADDR    = 0x015D866C
SP_ADDR       = 0x015D8670
SPMAX_ADDR    = 0x015D8674

MONSTER_TYPE_MIN = 1000

# ── Logger ───────────────────────────────────────────────────────
os.makedirs(LOG_DIR,      exist_ok=True)
os.makedirs(OPENKORE_DIR, exist_ok=True)
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
log_ver  = make_logger("verify",  f"{LOG_DIR}/ro_verify_{_ts}.log")
log_dec  = make_logger("decrypt", f"{LOG_DIR}/ro_decrypt_{_ts}.log")
log_key  = make_logger("keys",    f"{LOG_DIR}/ro_keys_{_ts}.log")  # [NEW] key extraction log

sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(message)s'))
log_main.addHandler(sh)

def LOG(msg):  log_main.info(msg)
def LOGR(msg): log_raw.debug(msg)
def LOGU(msg): log_unk.debug(msg)
def LOGV(msg): log_ver.info(msg); log_main.info(msg)
def LOGD(msg): log_dec.info(msg)
def LOGK(msg): log_key.info(msg); log_main.info(msg)  # [NEW]

# ── Memory Reader ────────────────────────────────────────────────
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
    TH32CS_SNAPPROCESS = 0x00000002
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",wt.DWORD),("cntUsage",wt.DWORD),("th32ProcessID",wt.DWORD),
            ("th32DefaultHeapID",ctypes.POINTER(ctypes.c_ulong)),("th32ModuleID",wt.DWORD),
            ("cntThreads",wt.DWORD),("th32ParentProcessID",wt.DWORD),
            ("pcPriClassBase",ctypes.c_long),("dwFlags",wt.DWORD),
            ("szExeFile",ctypes.c_char * 260),
        ]
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value: return 0
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = 0
    if k32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode('utf-8', errors='replace')
            if name.lower() == exe_name.lower():
                pid = entry.th32ProcessID; break
            if not k32.Process32Next(snap, ctypes.byref(entry)): break
    k32.CloseHandle(snap)
    return pid

def read_u32(addr):
    if not _mem_handle: return None
    buf = ctypes.create_string_buffer(4)
    n   = ctypes.c_size_t(0)
    ok  = kernel32.ReadProcessMemory(_mem_handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n))
    if ok and n.value == 4: return struct.unpack('<I', buf.raw)[0]
    return None

def mem_snapshot():
    return {k: read_u32(a) for k, a in [
        ('x', PLAYER_X_ADDR), ('y', PLAYER_Y_ADDR), ('hp', HP_ADDR),
        ('hpmax', HPMAX_ADDR), ('sp', SP_ADDR), ('spmax', SPMAX_ADDR),
    ]}

# ── Known packet table ───────────────────────────────────────────
PACKETS = {
    # Server → Client
    0x0069: ("login_success",      -1),
    0x006A: ("login_error",         3),
    0x0071: ("char_server",        -1),
    0x0072: ("map_login",          -1),
    0x0073: ("map_loaded",         11),
    0x0078: ("actor_exists",       -1),
    0x007B: ("actor_exists2",      -1),
    0x007C: ("map_actor",          -1),
    0x0080: ("actor_removed",       7),
    0x0086: ("actor_moved",        16),
    0x0087: ("actor_moved2",       -1),
    0x0088: ("damage",             29),
    0x008D: ("public_chat",        -1),
    0x0095: ("actor_name",         30),
    0x009A: ("system_chat",        -1),
    0x00A0: ("item_appeared",      -1),
    0x00AC: ("item_list",          -1),
    0x00B0: ("stat_info",           8),
    0x00B6: ("actor_coords",        6),
    0x00BD: ("stats_info",         -1),
    0x00BE: ("stat_info_single",   -1),
    0x0141: ("stat_info2",         14),
    0x0195: ("actor_name2",        30),
    0x01D7: ("actor_display5",     -1),
    0x01DA: ("login_pin",          -1),
    0x0283: ("server_broadcast",   -1),
    0x022C: ("actor_spawned",      -1),
    0x02AE: ("init_encrypt",       -1),  # Gepard key exchange — may be on any server port
    0x02EE: ("actor_display",      -1),
    0x083E: ("init_encrypt2",      -1),  # Gepard key exchange alt
    0x0AC4: ("gepard_auth",        -1),  # BamBoo Gepard auth packet — contains session keys!
    0x0856: ("actor_display4",     -1),
    0x09FD: ("actor_display2",     -1),
    0x09FF: ("actor_display3",     -1),
    0x0B1D: ("batch_packet",       -1),
    0x0BD3: ("actor_display6",     -1),
    0x2E19: ("map_char_info",      -1),
    0x4753: ("map_login_ack",      -1),
    0x79E8: ("batch_actor2",       -1),
    0x0000: ("null_packet",        -1),
    0x0001: ("signal_01",           2),
    0x013A: ("signal_13a",          2),
    0x1430: ("signal_1430",         2),
    0x1901: ("signal_1901",         2),
    0x1A01: ("signal_1a01",         2),
    0xFD00: ("signal_fd00",         8),
    0xFE00: ("signal_fe00",         8),
    # Client → Server
    0x0064: ("login",              -1),
    0x0065: ("select_char_server", -1),
    0x0066: ("select_char",        -1),
    0x0067: ("make_char",          -1),
    0x0068: ("delete_char",        -1),
    0x007D: ("map_loaded_ack",      2),
    0x0085: ("walk",               -1),
    0x0089: ("action",             -1),
    0x009F: ("item_take",          -1),
    0x00A7: ("item_use",           -1),
    0x00F5: ("item_drop",          -1),
    0x0113: ("skill_use_pos",      -1),
    0x0116: ("skill_use",          -1),
    0x0436: ("map_login2",         -1),
}

# ── EncBuffer ─────────────────────────────────────────────────────
class EncBuffer:
    def __init__(self, maxlen=512):
        self.buf    = deque(maxlen=maxlen)
        self.total  = 0

    def push(self, enc_sw):
        self.buf.append((enc_sw, time.time()))
        self.total += 1

    def replay(self, k1, k2, k3):
        """Replay entire buffer through key set. Returns (hits, total)."""
        hits = 0
        cur  = k1
        for enc_sw, _ in self.buf:
            cur     = (cur * k3 + k2) & 0xFFFFFFFF
            xk      = (cur >> 16) & 0x7FFF
            real_sw = (enc_sw ^ xk) & 0xFFFF
            known   = real_sw in PACKETS
            if known: hits += 1
            LOGD(f"REPLAY enc=0x{enc_sw:04X} → 0x{real_sw:04X} "
                 f"({'✓ '+PACKETS[real_sw][0] if known else '✗'})")
        return hits, len(self.buf)

enc_buf = EncBuffer()

# ── Gepard LCG Decryptor ─────────────────────────────────────────
class GepardDecryptor:
    def __init__(self):
        self.k1 = self.k2 = self.k3 = self.cur = 0
        self.on   = False
        self.hits = 0
        self.miss = 0
        self.source = ""    # which packet/port provided the keys

    def set_keys(self, k1, k2, k3, source=""):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.cur = k1; self.on  = True
        self.hits = self.miss = 0
        self.source = source
        LOG(f"  [CRYPT ] Keys SET k1=0x{k1:08X} k2=0x{k2:08X} k3=0x{k3:08X} "
            f"src={source} k3_odd={bool(k3&1)}")
        LOGK(f"KEYS_SET source={source} k1={k1:#010x} k2={k2:#010x} k3={k3:#010x} odd={k3&1}")
        LOGV("[VERIFY] Gepard encryption keys captured — decryption active")

    def decrypt(self, enc_sw):
        if not self.on or self.cur == 0:
            return enc_sw, False, False
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk       = (self.cur >> 16) & 0x7FFF
        real_sw  = (enc_sw ^ xk) & 0xFFFF
        verified = real_sw in PACKETS
        if verified: self.hits += 1
        else:
            self.miss += 1
            LOGD(f"MISS enc=0x{enc_sw:04X} xk=0x{xk:04X} → 0x{real_sw:04X} "
                 f"cur=0x{self.cur:08X}")
        return real_sw, True, verified

    def reset(self):
        self.cur  = self.k1
        self.hits = self.miss = 0
        LOG("  [CRYPT ] LCG reset (map_loaded)")

    @property
    def accuracy(self):
        total = self.hits + self.miss
        return 100 * self.hits / total if total else 0.0

crypt = GepardDecryptor()

# ── Key Extractor ─────────────────────────────────────────────────
#
#  Called for ANY large server packet on ANY port.
#  Scans every 4-byte-aligned offset for a (k1, k2, k3) triple that:
#    1. Has k2 != 0 and k3 != 0  (non-degenerate LCG)
#    2. Scores >= MIN_HITS when decrypting enc_buf contents
#
#  [FIX v6] k3 odd-bit check REMOVED — BamBoo uses even k3 values.
#
#  When enc_buf is empty (keys arrive before any ENC?), the extractor
#  stores keys speculatively. Accuracy will be verified on first ENC?.

class KeyExtractor:
    MIN_RATIO   = 0.6     # require ≥60% hits when buffer has ≥3 entries
    MIN_HITS    = 1       # absolute minimum regardless of buffer size

    def __init__(self, enc_buffer):
        self.enc_buf      = enc_buffer
        self.attempts     = 0
        self.pending_keys = None   # (k1,k2,k3,source) — stored but not yet activated
                                   # waiting for first ENC? to confirm

    def _score(self, k1, k2, k3):
        n   = min(10, len(self.enc_buf.buf))
        if n == 0:
            return 0, 0
        cur  = k1
        hits = 0
        for enc_sw, _ in list(self.enc_buf.buf)[:n]:
            cur     = (cur * k3 + k2) & 0xFFFFFFFF
            xk      = (cur >> 16) & 0x7FFF
            real_sw = (enc_sw ^ xk) & 0xFFFF
            if real_sw in PACKETS: hits += 1
        return hits, n

    def _best_candidate(self, data, source):
        """Scan data for best (k1,k2,k3) triple. Returns triple or None."""
        best_score, best_triple, best_offset = self.MIN_HITS - 1, None, -1
        buf_size = len(self.enc_buf.buf)

        for offset in range(2, len(data) - 11):
            try:
                k1, k2, k3 = struct.unpack_from('<III', data, offset)
            except struct.error:
                break
            if k2 == 0 or k3 == 0:
                continue
            self.attempts += 1
            score, checked = self._score(k1, k2, k3)
            if score > best_score:
                best_score, best_triple, best_offset = score, (k1, k2, k3), offset

        if best_triple:
            k1, k2, k3 = best_triple
            checked_n = min(10, buf_size)
            ratio     = best_score / checked_n if checked_n else 0
            LOGK(f"KEY_CANDIDATE source={source} off={best_offset} "
                 f"score={best_score}/{checked_n} ({ratio*100:.0f}%) "
                 f"k1={k1:#010x} k2={k2:#010x} k3={k3:#010x}")
            if ratio >= self.MIN_RATIO or checked_n < 3:
                return best_triple
        return None

    def try_packet(self, data, source=""):
        """Scan data for keys. Stores speculative if no ENC? yet.
        Skips if keys already confirmed (crypt.on + hits > 0)."""
        # Skip only if keys are truly confirmed (accuracy > 0)
        if crypt.on and crypt.hits > 0:
            return True

        buf_size = len(self.enc_buf.buf)
        LOGK(f"KEY_SCAN source={source} len={len(data)} enc_buf={buf_size} "
             f"hex={data[:32].hex(' ')}")

        triple = self._best_candidate(data, source)

        if triple is None and buf_size == 0:
            # No ENC? yet — store as pending (do NOT activate crypt yet)
            if len(data) >= 16:
                k1, k2, k3 = struct.unpack_from('<III', data, 4)
                if k2 != 0 and k3 != 0:
                    LOGK(f"KEY_PENDING source={source} off=4 "
                         f"k1={k1:#010x} k2={k2:#010x} k3={k3:#010x}")
                    # Only store if no pending yet, or this source is 0x0AC4 (higher priority)
                    if self.pending_keys is None or '0x0AC4' in source:
                        self.pending_keys = (k1, k2, k3, source)
            return False

        if triple:
            k1, k2, k3 = triple
            crypt.set_keys(k1, k2, k3, source=f"{source}[scored]")
            hits, total = self.enc_buf.replay(k1, k2, k3)
            LOG(f"  [CRYPT ] Retroactive replay: {hits}/{total} hits")
            self.pending_keys = None
            return True

        return False

    def try_packet_force(self, data, source=""):
        """Force-scan data for keys even if crypt.on — used for 0x0AC4
        which carries authoritative session keys and must override speculative."""
        # Save current crypt state and temporarily allow re-keying
        old_on   = crypt.on
        old_hits = crypt.hits
        crypt.on   = False   # temporarily disable so try_packet scans
        crypt.hits = 0
        result = self.try_packet(data, source)
        if not result:
            # Restore previous state if we didn't find better keys
            crypt.on   = old_on
            crypt.hits = old_hits
        return result

    def activate_pending(self, enc_sw):
        """Called when first ENC? arrives and we have pending (unconfirmed) keys.
        Tries the pending triple; if it decrypts to a known opcode, confirm it."""
        if not self.pending_keys:
            return False
        k1, k2, k3, source = self.pending_keys
        cur = k1
        cur     = (cur * k3 + k2) & 0xFFFFFFFF
        xk      = (cur >> 16) & 0x7FFF
        real_sw = (enc_sw ^ xk) & 0xFFFF
        if real_sw in PACKETS:
            LOGK(f"KEY_PENDING_CONFIRMED source={source} "
                 f"enc=0x{enc_sw:04X}→0x{real_sw:04X} ({PACKETS[real_sw][0]})")
            crypt.set_keys(k1, k2, k3, source=f"{source}[pending→confirmed]")
            self.pending_keys = None
            return True
        else:
            LOGK(f"KEY_PENDING_FAILED source={source} "
                 f"enc=0x{enc_sw:04X}→0x{real_sw:04X} (unknown) — discarding pending")
            self.pending_keys = None
            return False

key_extractor = KeyExtractor(enc_buf)

# ── OpenKore Collector ───────────────────────────────────────────
class PacketCollector:
    def __init__(self):
        self.seen = defaultdict(lambda: {
            'name': '???', 'lengths': defaultdict(int),
            'min_len': 9999, 'max_len': 0,
            'samples': [], 'count': 0, 'direction': '?',
        })

    def record(self, sw, name, data, direction):
        e = self.seen[sw]
        e['name'] = name; e['count'] += 1; e['direction'] = direction
        ln = len(data)
        e['lengths'][ln] += 1
        e['min_len'] = min(e['min_len'], ln)
        e['max_len'] = max(e['max_len'], ln)
        if len(e['samples']) < 4:
            e['samples'].append(data[:64])

    def _guess_len(self, sw):
        info = PACKETS.get(sw)
        if info:
            _, d = info
            if d > 0:  return 'fixed',    d
            if d == -1: return 'variable', -1
        sizes = self.seen.get(sw, {}).get('lengths', {})
        if not sizes:        return 'unknown', 0
        if len(sizes) == 1:  return 'fixed',   list(sizes.keys())[0]
        return 'variable', -1

    def _fields(self, sw):
        samples = self.seen.get(sw, {}).get('samples', [])
        if len(samples) < 2: return "# need more samples"
        ml = min(len(s) for s in samples)
        if ml < 3: return "# too short"
        hints = []; i = 2
        while i < ml:
            if i + 4 <= ml:
                bv = [s[i:i+4] for s in samples if len(s) >= i+4]
                if len(set(bv)) == 1:
                    hints.append(f"off+{i}: const u32=0x{struct.unpack_from('<I',bv[0])[0]:08X}"); i += 4; continue
                hints.append(f"off+{i}: vary u32"); i += 4; continue
            if i + 2 <= ml:
                b2 = [s[i:i+2] for s in samples if len(s) >= i+2]
                val = struct.unpack_from('<H', b2[0])[0]
                hints.append(f"off+{i}: {'const' if len(set(b2))==1 else 'vary'} u16"
                             + (f"=0x{val:04X}" if len(set(b2))==1 else ""))
                i += 2; continue
            i += 1
        return ("# " + ", ".join(hints[:6])) if hints else "# (no pattern)"

    def export_openkore(self, prefix):
        recv = f"{prefix}_recvpackets.txt"
        stub = f"{prefix}_packets_stub.pm"
        rl = [
            "# OpenKore recvpackets — ro_packet_parser_v6",
            f"# Session  : {_ts}",
            f"# Server   : {SERVER_IP}",
            f"# Gepard   : accuracy={crypt.accuracy:.1f}% hits={crypt.hits} miss={crypt.miss}",
            f"# Keys src : {crypt.source or 'none'}",
            "# VERIFY each entry before use in production", "",
        ]
        sl = ["# OpenKore packets.pm stub", f"# {_ts}", "", "%packets = ("]
        for sw in sorted(self.seen.keys()):
            e = self.seen[sw]; lt, lv = self._guess_len(sw)
            ok = lv if lt in ('fixed','variable') else 0
            rl.append(f"{sw:04X} {ok:5d}   # {e['name']} ({e['direction']}) seen={e['count']}x")
            sl.append(f"    '{sw:04X}' => ['{e['name']}', '', [], {max(ok,0)}],  {self._fields(sw)}")
        sl.append(");")
        with open(recv, 'w', encoding='utf-8') as f: f.write('\n'.join(rl))
        with open(stub, 'w', encoding='utf-8') as f: f.write('\n'.join(sl))
        LOG(f"  [EXPORT] {recv}"); LOG(f"  [EXPORT] {stub}")
        return recv, stub

collector = PacketCollector()

# ── Entity Tracker ───────────────────────────────────────────────
class Tracker:
    def __init__(self):
        self.E = {}; self.N = {}

    def update(self, eid, **kw):
        if eid not in self.E:
            self.E[eid] = {'id': eid, 'x': 0, 'y': 0, 'type': 0, 'name': '', 'last': time.time()}
        self.E[eid].update(kw); self.E[eid]['last'] = time.time()
        if eid in self.N: self.E[eid]['name'] = self.N[eid]

    def set_name(self, eid, name):
        self.N[eid] = name
        if eid in self.E: self.E[eid]['name'] = name

    def remove(self, eid): self.E.pop(eid, None)

    def cleanup(self):
        now = time.time()
        for k in [k for k,v in self.E.items() if now-v['last'] > 30]:
            del self.E[k]

    def monsters(self): return [e for e in self.E.values() if e['type'] >= MONSTER_TYPE_MIN]
    def players(self):  return [e for e in self.E.values() if 0 < e['type'] < MONSTER_TYPE_MIN]

tracker = Tracker()

# ── Coord helpers ────────────────────────────────────────────────
def dec3(b):
    return (b[0]<<2)|(b[1]>>6), ((b[1]&0x3F)<<4)|(b[2]>>4), b[2]&0xF

def dec6(b):
    return ((b[0]<<2)|(b[1]>>6), ((b[1]&0x3F)<<4)|(b[2]>>4),
            ((b[2]&0xF)<<6)|(b[3]>>2), ((b[3]&3)<<8)|b[4])

def up(fmt, data, off=0):
    sz = struct.calcsize(fmt)
    if off + sz > len(data): return None
    return struct.unpack_from(fmt, data, off)

# ── Generic inner-packet walker ───────────────────────────────────
_ACTOR_INNER = {
    0x00B6, 0x0078, 0x007B, 0x007C, 0x0080, 0x0086, 0x0087,
    0x0088, 0x0095, 0x0195, 0x022C, 0x02EE, 0x0856, 0x09FD, 0x09FF, 0x0BD3,
}

def walk_inner(data, direction, allowed=None):
    dispatched = 0; i = 0
    while i + 2 <= len(data):
        sw   = struct.unpack_from('<H', data, i)[0]
        info = PACKETS.get(sw)
        if info is None or (allowed and sw not in allowed): i += 1; continue
        _, plen = info
        if plen > 0:
            if i + plen <= len(data):
                dispatch(data[i:i+plen], direction); dispatched += 1; i += plen
            else: i += 1
        elif plen == -1:
            if i + 4 > len(data): break
            vlen = struct.unpack_from('<H', data, i+2)[0]
            if 4 <= vlen <= len(data)-i:
                dispatch(data[i:i+vlen], direction); dispatched += 1; i += vlen
            else: i += 1
        else: i += 1
    return dispatched

# ── Packet Handlers ───────────────────────────────────────────────
def verify_with_memory(stat_name, packet_val):
    addr_map = {'HP':HP_ADDR,'HPMAX':HPMAX_ADDR,'SP':SP_ADDR,'SPMAX':SPMAX_ADDR}
    addr = addr_map.get(stat_name)
    if not addr: return
    mem_val = read_u32(addr)
    if mem_val is None: return
    match = "✅ MATCH" if packet_val == mem_val else f"❌ DIFF mem={mem_val}"
    LOGV(f"  [VERIFY] {stat_name}: pkt={packet_val} mem@0x{addr:08X} {match}")

def handle_stat_info(data):
    r = up('<HI', data, 2)
    if not r: return
    t, v = r
    names = {1:'BaseEXP',2:'JobEXP',5:'HP',6:'HPMAX',7:'SP',8:'SPMAX',
             9:'StatusPts',11:'BaseLv',12:'SkillPts',22:'BaseEXPMax',23:'JobEXPMax',
             24:'Weight',25:'MaxWeight',41:'Attack',43:'ItemDef',44:'PlusDef',
             45:'MDef',46:'PlusMDef',48:'Hit',49:'Flee',50:'PlusFlee',
             51:'Critical',52:'PlusCrit',53:'ASPD',}
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT  ] {n} = {v}")
    verify_with_memory(n, v)

def handle_stat_info2(data):
    r = up('<III', data, 2)
    if not r: return
    t, base, plus = r
    names = {13:'STR',14:'AGI',15:'VIT',16:'INT',17:'DEX',18:'LUK'}
    LOG(f"  [STAT2 ] {names.get(t,f'type={t}')} base={base} bonus={plus} total={base+plus}")

def handle_actor_coords(data):
    """
    0x00B6 — 6-byte actor coordinate packet.

    [FIX v6] Corrected decode: try data[2:5] first (Layout B) since it gives
    varying x values per entity (makes physical sense). Fall back to data[3:6]
    (Layout A) if Layout B is out of map bounds.

    Entity ID: reading u32 from offset 2 embeds the coord bytes — the low byte
    of eid (data[2]) is the only truly unique part per entity when coords are
    constant; byte 5 (data[5]) appears to be a session-scoped entity slot/type.
    """
    if len(data) < 6: return
    eid = struct.unpack_from('<I', data, 2)[0]  # full u32 for tracker key

    # Try Layout B first: coordinate at data[2:5]
    xB, yB, dB = dec3(data[2:5])
    if 0 < xB < 1024 and 0 < yB < 1024:
        tracker.update(eid, x=xB, y=yB)
        e     = tracker.E.get(eid, {})
        label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
        LOG(f"  [{label:7s}] 0x{eid:08X} pos=({xB},{yB}) dir={dB} slot={data[5]:02X}")
        return

    # Fallback Layout A: coordinate at data[3:6]
    xA, yA, dA = dec3(data[3:6])
    if 0 < xA < 1024 and 0 < yA < 1024:
        tracker.update(eid, x=xA, y=yA)
        e     = tracker.E.get(eid, {})
        label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
        LOG(f"  [{label:7s}] 0x{eid:08X} pos=({xA},{yA}) dir={dA} [layout_A]")
        return

    LOGR(f"  [COORD ] 0x{eid:08X} bad decode B=({xB},{yB}) A=({xA},{yA}) raw={data[2:6].hex()}")

def handle_actor_moved(data):
    if len(data) < 16: return
    r = up('<I6sI', data, 2)
    if not r: return
    eid, coords, _ = r
    fx, fy, tx, ty = dec6(coords)
    tracker.update(eid, x=tx, y=ty)
    e     = tracker.E.get(eid, {})
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
                    if 0 < x < 512 and 0 < y < 512:
                        tracker.update(eid, x=x, y=y, type=jtype)
                        label = "MONSTER" if jtype >= MONSTER_TYPE_MIN else "player"
                        LOG(f"  [{label:7s}] 0x{eid:08X} type={jtype} ({x},{y}) {tracker.N.get(eid,'')}"); break
        else:
            if len(data) < 12: return
            eid = struct.unpack_from('<I', data, 4)[0]
            for type_off in [14, 16, 18]:
                t = up('<H', data, type_off)
                if t and t[0] > 0:
                    for co in [54, 58, 50, 46]:
                        if co + 3 <= len(data):
                            x, y, _ = dec3(data[co:co+3])
                            if 0 < x < 512 and 0 < y < 512:
                                tracker.update(eid, x=x, y=y, type=t[0])
                                label = "MONSTER" if t[0] >= MONSTER_TYPE_MIN else "player"
                                LOG(f"  [{label:7s}] 0x{eid:08X} type={t[0]} ({x},{y})"); break
                    break
    except Exception: pass

def handle_actor_removed(data):
    if len(data) < 7: return
    r = up('<IB', data, 2)
    if not r: return
    eid, _ = r
    e = tracker.E.get(eid, {})
    label = "MONSTER" if e.get('type',0) >= MONSTER_TYPE_MIN else "entity"
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

def handle_init_encrypt(data, port=0):
    """Standard Gepard key exchange (0x02AE / 0x083E).
    [FIX v6] Removed k3 odd-bit check."""
    for offset in (2, 4, 6, 8):
        r = up('<III', data, offset)
        if not r: continue
        k1, k2, k3 = r
        # [FIX v6] Only check non-zero — remove k3 & 1 requirement
        if k2 == 0 or k3 == 0: continue
        crypt.set_keys(k1, k2, k3, source=f"0x{struct.unpack_from('<H',data,0)[0]:04X}:port{port}")
        LOGK(f"INIT_ENCRYPT port={port} offset={offset} hex={data[:24].hex(' ')}")
        return
    LOG(f"  [CRYPT ] init_encrypt [{len(data)}B] — no valid keys, hex={data[:20].hex(' ')}")
    LOGK(f"INIT_ENCRYPT_FAIL port={port} len={len(data)} hex={data[:32].hex(' ')}")

def handle_gepard_auth(data, port=0):
    """0x0AC4 — BamBoo-specific Gepard auth packet.
    Appears every session right after 0x4753 on the first connected port.
    Contains session-varying fields at offset 4 and 12 (account_id constant at 8).
    Uses try_packet_force() so it can OVERRIDE speculative keys from 0x4753."""
    LOGK(f"GEPARD_AUTH port={port} len={len(data)} hex={data[:32].hex(' ')}")
    LOG(f"  [GEPARD] 0x0AC4 gepard_auth [{len(data)}B] port={port} — scanning for keys")
    if len(data) >= 16:
        fA = struct.unpack_from('<I', data, 4)[0]
        fB = struct.unpack_from('<I', data, 8)[0]
        fC = struct.unpack_from('<I', data, 12)[0]
        LOGK(f"GEPARD_AUTH_FIELDS fA=0x{fA:08X} fB=0x{fB:08X}(acct?) fC=0x{fC:08X}")
    # Force-scan even if speculative keys already set — 0x0AC4 is authoritative
    key_extractor.try_packet_force(data, source=f"0x0AC4:port{port}")
    # Log body text (session token / server name embedded here)
    if len(data) > 16:
        body = data[16:]
        try:   text = body.decode('utf-8', errors='replace').rstrip('\x00')
        except: text = body.hex()
        LOG(f"  [BROAD ] {text[:120]}")
    if len(data) < 4: return
    body = data[4:]
    try:   text = body.decode('utf-8', errors='replace').rstrip('\x00')
    except: text = body.hex()
    LOG(f"  [BROAD ] {text[:120]}")

def handle_server_broadcast(data):
    """0x0283 — server-wide broadcast message."""
    if len(data) < 4: return
    body = data[4:]
    try:   text = body.decode('utf-8', errors='replace').rstrip('\x00')
    except: text = body.hex()
    LOG(f"  [BROAD ] {text[:120]}")

def handle_map_char_info(data):
    if len(data) < 30: return
    try:
        name_raw = data[26:]
        null_pos = name_raw.find(b'\x00')
        map_name = name_raw[:null_pos].decode('ascii', errors='replace') if null_pos > 0 else ''
    except: map_name = ''
    r = up('<II', data, 4)
    acc_id = r[0] if r else 0; chr_id = r[1] if r else 0
    LOG(f"  [MAPINF] map='{map_name}' acc={acc_id} chr={chr_id}")

def handle_login_success(data):
    """0x0069 — extract char server addresses (first char server entry)."""
    if len(data) < 47: return
    # Standard eA format: offset 47+ = server list entries
    # Each entry: ip(4) + port(2) + name(20) + ...
    LOGK(f"LOGIN_SUCCESS len={len(data)} hex={data[:32].hex(' ')}")
    LOG(f"  [LOGIN ] Login success [{len(data)}B] — scan for char server port")

def handle_char_server(data):
    """0x0071 — char server hands off to map server. May contain session keys."""
    LOGK(f"CHAR_SERVER len={len(data)} hex={data[:32].hex(' ')}")
    LOG(f"  [CHAR  ] Char→Map handoff [{len(data)}B]")
    # Try key extraction here too — some servers embed keys in this packet
    key_extractor.try_packet(data, source="0x0071")

# ── Unknown tracker ───────────────────────────────────────────────
_seen_unk = {}
_silent   = {'null_packet','signal_01','signal_13a','signal_1901',
             'signal_1a01','signal_fd00','signal_fe00','signal_1430'}

# ── Dispatcher ───────────────────────────────────────────────────
def dispatch(data, direction, port=0):
    if len(data) < 2: return

    raw_sw = struct.unpack_from('<H', data, 0)[0]
    sw     = raw_sw
    dec    = False
    ver    = False

    if direction == "→":
        if crypt.on:
            # Keys available: decrypt switch
            sw, dec, ver = crypt.decrypt(raw_sw)
            if dec and not ver and raw_sw not in PACKETS:
                LOGD(f"SKIP unverified dec raw=0x{raw_sw:04X}→0x{sw:04X}")
                _seen_unk[raw_sw] = _seen_unk.get(raw_sw, 0) + 1
                return
        else:
            # No keys yet: buffer for key finder
            if raw_sw not in PACKETS:
                enc_buf.push(raw_sw)

    enc_tag = f" [→0x{sw:04X}]" if dec else ""
    LOGR(f"p{port} {direction} 0x{sw:04X} [{len(data)}B]{enc_tag} {data[:32].hex(' ')}")

    info = PACKETS.get(sw)
    if info is None:
        _seen_unk[sw] = _seen_unk.get(sw, 0) + 1
        if _seen_unk[sw] <= 2:
            LOG(f"  [?????] {direction} 0x{sw:04X} [{len(data)}B]{enc_tag}")
            LOGU(f"p{port} {direction} 0x{sw:04X} [{len(data)}B] {data[:32].hex(' ')}")
        collector.record(sw, '???', data, direction)
        # [NEW v7] Scan unknown server packets ≥32B for Gepard keys
        if direction == "←" and len(data) >= 32 and not crypt.on:
            key_extractor.try_packet(data, source=f"0x{sw:04X}:unk:port{port}")
        return

    name, _ = info
    collector.record(sw, name, data, direction)

    if name not in _silent:
        LOG(f"\np{port} {direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_tag}")

    d = data

    if sw in (0x02AE, 0x083E):
        handle_init_encrypt(d, port)
    elif sw == 0x0AC4:
        handle_gepard_auth(d, port)
    elif sw == 0x0069:
        handle_login_success(d)
    elif sw == 0x0071:
        handle_char_server(d)
    elif sw == 0x4753:
        LOG(f"  [MAP   ] map_login_ack [{len(d)}B]")
        # Attempt key extraction — in previous sessions 0x4753 did NOT carry keys,
        # but log everything for analysis.
        LOGK(f"MAP_LOGIN_ACK len={len(d)} hex={d[:36].hex(' ')}")
        if not crypt.on:
            key_extractor.try_packet(d, source="0x4753")
    elif sw == 0x0086:
        handle_actor_moved(d)
    elif sw == 0x00B6:
        handle_actor_coords(d)
    elif sw in (0x022C,0x09FD,0x09FF,0x0856,0x02EE,0x0078,0x007B,0x007C):
        handle_actor_display(d, sw)
    elif sw == 0x0080:
        handle_actor_removed(d)
    elif sw in (0x0095, 0x0195):
        handle_actor_name(d)
    elif sw == 0x00B0:
        handle_stat_info(d)
    elif sw == 0x0141:
        handle_stat_info2(d)
    elif sw == 0x0283:
        handle_server_broadcast(d)
    elif sw == 0x2E19:
        handle_map_char_info(d)
    elif sw == 0x0073:
        crypt.reset()
        snap = mem_snapshot()
        LOG(f"  [MAP   ] Entered game | memory: {snap}")
    elif sw == 0x0B1D:
        if len(d) > 4:
            n = walk_inner(d[4:], direction, allowed={0x00B6})
            if n == 0: walk_inner(d[4:], direction, allowed=_ACTOR_INNER)
    elif sw == 0x79E8:
        if len(d) > 4: walk_inner(d[4:], direction, allowed=_ACTOR_INNER)
    elif sw == 0x0000:
        inner = d[4:] if len(d) > 4 else b''
        i = 0
        while i + 2 <= len(inner):
            isw = struct.unpack_from('<H', inner, i)[0]
            if   isw == 0x0073 and i+11  <= len(inner): dispatch(inner[i:i+11],  direction, port); i += 11
            elif isw == 0x00B0 and i+8   <= len(inner): dispatch(inner[i:i+8],   direction, port); i += 8
            elif isw == 0x0141 and i+14  <= len(inner): dispatch(inner[i:i+14],  direction, port); i += 14
            elif isw == 0x0086 and i+16  <= len(inner): dispatch(inner[i:i+16],  direction, port); i += 16
            elif isw == 0x00B6 and i+6   <= len(inner): dispatch(inner[i:i+6],   direction, port); i += 6
            elif isw == 0x0080 and i+7   <= len(inner): dispatch(inner[i:i+7],   direction, port); i += 7
            else: i += 1

# ── StreamBuf (per-connection stream reassembler) ─────────────────
class StreamBuf:
    def __init__(self, direction, port=0):
        self.buf    = b''
        self.dir    = direction
        self.port   = port
        self.synced = False

    def feed(self, data):
        self.buf += data
        if not self.synced: self._sync()
        self._process()

    def _is_good_anchor(self, sw, i):
        info = PACKETS.get(sw)
        if not info: return False
        _, plen = info
        if plen >= 4: return True
        if plen == -1:
            if i + 4 <= len(self.buf):
                vlen = struct.unpack_from('<H', self.buf, i+2)[0]
                return 4 <= vlen <= 32768
        return plen == 2

    def _sync(self):
        if self.synced: return
        lim = min(len(self.buf)-1, 256)

        # [FIX v9] Before searching for a sync point, record every 2-byte
        # chunk of the pre-sync client stream into enc_buf — these bytes
        # contain the Gepard handshake that was previously dropped silently.
        if self.dir == "→" and not crypt.on:
            for i in range(0, min(lim, len(self.buf)-1), 2):
                sw2 = struct.unpack_from('<H', self.buf, i)[0]
                enc_buf.push(sw2)
                LOGR(f"p{self.port} → [PRE-SYNC] 0x{sw2:04X} {self.buf[i:i+2].hex()}")
                # Also try to confirm pending keys on each new value
                if key_extractor.pending_keys:
                    key_extractor.activate_pending(sw2)
                    if crypt.on:
                        break

        for i in range(lim):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS:
                _, plen = PACKETS[sw]
                if plen >= 4 or (plen == -1 and self._is_good_anchor(sw, i)):
                    if i > 0: LOG(f"  [SYNC  ] p{self.port} {self.dir} skipped {i}B → 0x{sw:04X}")
                    self.buf = self.buf[i:]; self.synced = True; return
        for i in range(lim):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS and PACKETS[sw][1] == 2 and sw != 0x0000:
                if i > 0: LOG(f"  [SYNC  ] p{self.port} {self.dir} skipped {i}B → 0x{sw:04X} (weak)")
                self.buf = self.buf[i:]; self.synced = True; return
        if len(self.buf) > 128:
            self.buf = self.buf[-32:]; self.synced = False

    def _process(self):
        while len(self.buf) >= 2:
            sw   = struct.unpack_from('<H', self.buf, 0)[0]
            info = PACKETS.get(sw)
            plen = info[1] if info else 0

            if plen == -1:
                if len(self.buf) < 4: break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 32768:
                    self.buf = self.buf[1:]; self.synced = False; self._sync(); continue

            elif plen == 0:
                if self.dir == "→":
                    # [FIX v6] When crypt.on: dispatch the 2-byte encrypted switch
                    # directly so decrypt() is called.  When crypt off: buffer it.
                    if len(self.buf) < 4: break
                    maybe = struct.unpack_from('<H', self.buf, 2)[0]
                    if 4 <= maybe <= 32768:
                        plen = maybe   # larger packet with encrypted switch
                    elif crypt.on:
                        # [FIX v6] 2-byte encrypted signal — dispatch for decryption
                        dispatch(self.buf[:2], self.dir, self.port)
                        self.buf = self.buf[2:]; continue
                    # No keys yet — buffer for key finder
                    # If we have pending keys, try to confirm them now
                    if key_extractor.pending_keys:
                        confirmed = key_extractor.activate_pending(sw)
                        if confirmed:
                            # Re-process this packet now that keys are active
                            sw2, dec2, ver2 = crypt.decrypt(sw)
                            LOGR(f"p{self.port} → [CONFIRMED+DEC] 0x{sw:04X}→0x{sw2:04X}")
                    else:
                        enc_buf.push(sw)
                    LOGR(f"p{self.port} → [ENC?] 0x{sw:04X} {self.buf[:2].hex()}")
                    self.buf = self.buf[2:]; continue
                else:
                    if len(self.buf) >= 4:
                        maybe = struct.unpack_from('<H', self.buf, 2)[0]
                        if 4 <= maybe <= 32768:
                            plen = maybe
                        else:
                            dispatch(self.buf[:2], self.dir, self.port)
                            self.buf = self.buf[2:]; continue
                    else: break

            if len(self.buf) < plen: break
            dispatch(self.buf[:plen], self.dir, self.port)
            self.buf = self.buf[plen:]

# ── Multi-port connection manager ────────────────────────────────
#
#  [NEW v6] Each distinct port gets its own pair of StreamBuf objects.
#  This allows us to capture login (6900), char (6121), and map (24656)
#  server traffic in a single session, which is necessary to intercept
#  the Gepard key exchange that happens before the map server connection.
#
#  The WinDivert filter is now ALL TCP to SERVER_IP (no port restriction).

class MultiPortManager:
    def __init__(self):
        self.conns = {}   # port → {'sv': StreamBuf, 'cl': StreamBuf, 'type': str}

    def _conn_type(self, port):
        # Heuristic label for common RO server ports
        if port == 6900:             return "LOGIN"
        if port in (6121, 6122):     return "CHAR"
        if port == MAP_PORT:         return "MAP"
        return f"PORT{port}"

    def get(self, port):
        if port not in self.conns:
            ctype = self._conn_type(port)
            self.conns[port] = {
                'sv': StreamBuf("←", port),
                'cl': StreamBuf("→", port),
                'type': ctype,
            }
            LOG(f"  [CONN  ] New connection on port {port} [{ctype}]")
        return self.conns[port]

    def feed_server(self, port, data):
        self.get(port)['sv'].feed(data)

    def feed_client(self, port, data):
        self.get(port)['cl'].feed(data)

    def active_ports(self):
        return list(self.conns.keys())

mgr = MultiPortManager()

# ── Summary ──────────────────────────────────────────────────────
def summary():
    tracker.cleanup()
    snap  = mem_snapshot()
    lines = [f"\n{'═'*60}", f"  SUMMARY  {datetime.now().strftime('%H:%M:%S')}", f"{'─'*60}"]
    if snap:
        lines.append(f"  Memory  : pos=({snap['x']},{snap['y']}) "
                     f"HP={snap['hp']}/{snap['hpmax']} SP={snap['sp']}/{snap['spmax']}")
    lines.append(f"  Gepard  : accuracy={crypt.accuracy:.0f}% "
                 f"hits={crypt.hits} miss={crypt.miss} "
                 f"ENC_buf={len(enc_buf.buf)}/{enc_buf.total}")
    lines.append(f"  Keys    : on={crypt.on} src='{crypt.source}'")
    lines.append(f"  Ports   : {mgr.active_ports()}")
    m = sorted(tracker.monsters(), key=lambda e: e.get('x',0))
    p = sorted(tracker.players(),  key=lambda e: e.get('x',0))
    lines += [f"\n  Monsters ({len(m)}):"]
    for e in m:
        lines.append(f"    0x{e['id']:08X}  ({e['x']},{e['y']})  {e.get('name','type='+str(e['type']))}")
    lines += [f"\n  Players ({len(p)}):"]
    for e in p:
        lines.append(f"    0x{e['id']:08X}  ({e['x']},{e['y']})  {e.get('name','')}")
    lines.append(f"{'═'*60}")
    txt = '\n'.join(lines)
    LOG(txt); log_sum.info(txt)

# ── MAIN ─────────────────────────────────────────────────────────
def main():
    LOG("=" * 60)
    LOG("  RO Packet Parser v7")
    LOG(f"  Server : {SERVER_IP} (ALL ports)")
    LOG(f"  Logs   : {os.path.abspath(LOG_DIR)}/ro_*_{_ts}.log")
    LOG("=" * 60)
    LOG("  [IMPORTANT] Filter now captures ALL TCP ports on server IP.")
    LOG("  This includes login (6900), char (~6121), and map server.")
    LOG("  Gepard key exchange 0x02AE/0x083E/0x0AC4 will be captured from")
    LOG("  whichever server phase it occurs in.")
    LOG("=" * 60)

    # [FIX v7] Import pydivert INSIDE main() so log files are always created
    # even if WinDivert is not installed or script is not run as Administrator.
    # If import fails, the error is written to the session log before crashing.
    try:
        import pydivert as _pydivert
    except ImportError as e:
        LOG(f"  [ERROR ] ไม่พบ pydivert: {e}")
        LOG("  แก้ไข: pip install pydivert  (แล้วรันใหม่เป็น Administrator)")
        return
    except Exception as e:
        LOG(f"  [ERROR ] pydivert โหลดไม่ได้: {e}")
        LOG("  ตรวจสอบ: ต้องรันโปรแกรมเป็น Administrator!")
        return

    init_memory(TARGET_PID)
    snap = mem_snapshot()
    if snap and snap['x']:
        LOGV(f"[VERIFY] Init memory: pos=({snap['x']},{snap['y']}) "
             f"HP={snap['hp']}/{snap['hpmax']} SP={snap['sp']}/{snap['spmax']}")

    LOG("\nรัน BamBoo_Client แล้ว login ตั้งแต่ต้น (ต้องเริ่มจาก login screen!)")
    LOG("กด Ctrl+C หยุด + export OpenKore table\n")

    # [KEY CHANGE v6] Capture ALL TCP traffic to server IP — no port restriction
    flt = f"tcp and (ip.DstAddr=={SERVER_IP} or ip.SrcAddr=={SERVER_IP})"

    last_sum = time.time()

    try:
        with _pydivert.WinDivert(flt) as w:
            for pkt in w:
                w.send(pkt)
                if not pkt.tcp or not pkt.payload: continue
                payload = bytes(pkt.payload)
                if len(payload) < 2: continue

                # Determine port and direction
                if pkt.dst_addr == SERVER_IP:
                    port = pkt.dst_port
                    mgr.feed_client(port, payload)
                else:
                    port = pkt.src_port
                    mgr.feed_server(port, payload)

                if time.time() - last_sum > 15:
                    summary(); last_sum = time.time()

    except KeyboardInterrupt:
        LOG("\nหยุด")
        summary()

        prefix = f"{OPENKORE_DIR}/ro_{_ts}"
        r, s   = collector.export_openkore(prefix)
        LOG(f"\n  → recvpackets : {r}")
        LOG(f"  → packets stub: {s}")

        LOG(f"\nUnknown switches: {len(_seen_unk)}")
        for sw, cnt in sorted(_seen_unk.items(), key=lambda x: -x[1])[:20]:
            LOG(f"  0x{sw:04X}  x{cnt}")

        LOG(f"\nGepard : accuracy={crypt.accuracy:.1f}% "
            f"hits={crypt.hits} miss={crypt.miss} src={crypt.source}")
        LOG(f"ENC_buf: {len(enc_buf.buf)} current / {enc_buf.total} total")
        LOG(f"Ports  : {mgr.active_ports()}")

    except Exception as e:
        LOG(f"Error: {e}")
        LOG("ต้องรันใฐานะ Administrator")

if __name__ == '__main__':
    main()
