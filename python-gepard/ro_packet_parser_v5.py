# ro_packet_parser_v5.py
# ================================================================
#  Changes from v4:
#  [FIX]  0x4753 (map_login_ack): extract Gepard LCG keys from payload offset 4
#  [FIX]  0x0000 inner walker: detect 0x0073 → call crypt.reset()
#  [NEW]  EncBuffer: circular buffer of ENC? switches for retroactive verify
#  [NEW]  GepardKeyFinder: score-based candidate scan against ENC? history
#  [NEW]  walk_inner(): generalized sub-packet scanner (replaces copy-paste)
#  [NEW]  0x79E8 (batch_actor2): bulk actor spawn, walks inner sub-packets
#  [NEW]  0x2E19 (map_char_info): map + character info, extracts map name
#  [NEW]  0x1430, 0xE94A added to PACKETS table
#  [FIX]  0xE94A: large encrypted client packet now length-resolved correctly
# ================================================================
# Requirements: pip install pydivert
# Must run as Administrator
# ================================================================

import pydivert
import struct, time, os, ctypes, ctypes.wintypes as wt
import logging, json
from datetime import datetime
from collections import defaultdict, deque

# ── Config ──────────────────────────────────────────────────────
SERVER_IP    = "136.110.172.32"
SERVER_PORT  = 24656
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

sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(message)s'))
log_main.addHandler(sh)

def LOG(msg):  log_main.info(msg)
def LOGR(msg): log_raw.debug(msg)
def LOGU(msg): log_unk.debug(msg)
def LOGV(msg): log_ver.info(msg); log_main.info(msg)
def LOGD(msg): log_dec.info(msg)

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
            ("dwSize",              wt.DWORD), ("cntUsage",            wt.DWORD),
            ("th32ProcessID",       wt.DWORD), ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        wt.DWORD), ("cntThreads",          wt.DWORD),
            ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             wt.DWORD), ("szExeFile",           ctypes.c_char * 260),
        ]
    k32  = ctypes.WinDLL('kernel32', use_last_error=True)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return 0
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = 0
    if k32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode('utf-8', errors='replace')
            if name.lower() == exe_name.lower():
                pid = entry.th32ProcessID; break
            if not k32.Process32Next(snap, ctypes.byref(entry)):
                break
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
    return {
        'x': read_u32(PLAYER_X_ADDR), 'y': read_u32(PLAYER_Y_ADDR),
        'hp': read_u32(HP_ADDR), 'hpmax': read_u32(HPMAX_ADDR),
        'sp': read_u32(SP_ADDR), 'spmax': read_u32(SPMAX_ADDR),
    }

# ── Known packet table ───────────────────────────────────────────
PACKETS = {
    # Server → Client (confirmed)
    0x0073: ("map_loaded",         11),
    0x0078: ("actor_exists",       -1),
    0x007B: ("actor_exists2",      -1),
    0x007C: ("map_actor",          -1),
    0x0080: ("actor_removed",       7),
    0x0086: ("actor_moved",        16),
    0x0087: ("actor_moved2",       -1),
    0x0088: ("damage",             29),
    0x4753: ("map_login_ack",      -1),  # [KEY SOURCE] contains LCG keys @ offset 4
    0x0B1D: ("batch_packet",       -1),
    0x008D: ("public_chat",        -1),
    0x0095: ("actor_name",         30),
    0x009A: ("system_chat",        -1),
    0x00A0: ("item_appeared",      -1),
    0x00AC: ("item_list",          -1),
    0x00B0: ("stat_info",           8),
    0x00B6: ("actor_coords",        6),
    0x00BD: ("stats_info",         -1),
    0x00BE: ("stat_info_single",   -1),
    0x0069: ("login_success",      -1),
    0x006A: ("login_error",         3),
    0x0071: ("char_server",        -1),
    0x0141: ("stat_info2",         14),
    0x0195: ("actor_name2",        30),
    0x01D7: ("actor_display5",     -1),
    0x01DA: ("login_pin",          -1),
    0x0283: ("server_broadcast",   -1),
    0x022C: ("actor_spawned",      -1),
    0x02AE: ("init_encrypt",       -1),  # standard Gepard key exchange
    0x02EE: ("actor_display",      -1),
    0x083E: ("init_encrypt2",      -1),  # standard Gepard key exchange (alt)
    0x0856: ("actor_display4",     -1),
    0x09FD: ("actor_display2",     -1),
    0x09FF: ("actor_display3",     -1),
    0x0BD3: ("actor_display6",     -1),
    # [NEW v5] BamBoo-confirmed opcodes from session 20260318_143602
    0x79E8: ("batch_actor2",       -1),  # bulk actor spawn (1858B+), contains 0x00B6 inside
    0x2E19: ("map_char_info",      -1),  # map/char info, map name @ offset 26
    0x1430: ("signal_1430",         2),  # 2-byte heartbeat signal
    # Bamboo signals (short fixed-length)
    0x0000: ("null_packet",        -1),
    0x0001: ("signal_01",           2),
    0x013A: ("signal_13a",          2),
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
    0x0072: ("map_login",          -1),
    0x0436: ("map_login2",         -1),
    0x007D: ("map_loaded_ack",      2),
    0x0085: ("walk",               -1),
    0x0089: ("action",             -1),
    0x009F: ("item_take",          -1),
    0x00A7: ("item_use",           -1),
    0x00F5: ("item_drop",          -1),
    0x0113: ("skill_use_pos",      -1),
    0x0116: ("skill_use",          -1),
    # [NEW v5] large encrypted client packets — switch is encrypted, body is not
    0xE94A: ("batch_action",       -1),  # 865B client batch (encrypted switch)
}

# ── EncBuffer ─────────────────────────────────────────────────────
#
#  Stores the last N encrypted switch values received from client→server.
#  Purpose: when keys are found AFTER packets have already passed, we can
#  replay the buffer to retroactively decrypt and score candidate keys.
#
#  Each entry = (enc_sw, timestamp) so we can report timing in the log.

class EncBuffer:
    def __init__(self, maxlen=256):
        self.buf    = deque(maxlen=maxlen)   # (enc_sw, ts)
        self.maxlen = maxlen
        self.total  = 0   # total ENC? seen (including evicted)

    def push(self, enc_sw):
        self.buf.append((enc_sw, time.time()))
        self.total += 1

    def switches(self, n=None):
        """Return list of just enc_sw values, newest-first excluded by n limit."""
        items = list(self.buf)
        if n:
            items = items[:n]
        return [sw for sw, _ in items]

    def replay(self, k1, k2, k3, log_results=True):
        """Replay buffered ENC? values through the given key set.
        Returns (hits, total) where hits = switches that decrypted to known opcode."""
        hits = 0
        cur  = k1
        for enc_sw, ts in self.buf:
            cur     = (cur * k3 + k2) & 0xFFFFFFFF
            xk      = (cur >> 16) & 0x7FFF
            real_sw = (enc_sw ^ xk) & 0xFFFF
            known   = real_sw in PACKETS
            if known:
                hits += 1
            if log_results:
                name = PACKETS[real_sw][0] if known else '???'
                LOGD(f"REPLAY enc=0x{enc_sw:04X} → 0x{real_sw:04X} ({name}) "
                     f"{'✓' if known else '✗'}")
        return hits, len(self.buf)

enc_buf = EncBuffer()

# ── GepardKeyFinder ───────────────────────────────────────────────
#
#  Scans any large server→client packet for potential (k1, k2, k3) triples
#  and scores each against the current EncBuffer.
#
#  Scoring: for each candidate triple, simulate the LCG from k1 and check
#  how many buffered ENC? values decrypt to opcodes in PACKETS.
#  Accept if score / checked >= ACCEPT_RATIO and score >= MIN_HITS.
#
#  We try every byte offset, not just aligned ones, because different
#  server builds may pad headers differently.

class GepardKeyFinder:
    MIN_HITS     = 3      # minimum absolute hits to accept
    ACCEPT_RATIO = 0.5    # minimum hits/checked ratio to accept

    def __init__(self, enc_buffer):
        self.enc_buf = enc_buffer
        self.attempts = 0
        self.found    = False

    def _score(self, k1, k2, k3, check_n=10):
        """Simulate LCG from k1, return number of hits in first check_n ENC? values."""
        items = self.enc_buf.switches(check_n)
        if not items:
            return 0
        cur  = k1
        hits = 0
        for enc_sw in items:
            cur     = (cur * k3 + k2) & 0xFFFFFFFF
            xk      = (cur >> 16) & 0x7FFF
            real_sw = (enc_sw ^ xk) & 0xFFFF
            if real_sw in PACKETS:
                hits += 1
        return hits

    def try_packet(self, data, context="packet"):
        """Scan data for best (k1,k2,k3) triple. Sets crypt keys if found.
        Returns True if keys found and set."""
        if self.found:
            return True   # already have keys

        if len(self.enc_buf.buf) < self.MIN_HITS:
            LOGD(f"KEYFND {context}: need {self.MIN_HITS} ENC? in buffer "
                 f"(have {len(self.enc_buf.buf)}), deferring")
            return False

        best_score  = self.MIN_HITS - 1
        best_triple = None
        best_offset = -1

        # Try all byte offsets from 2 (skip switch bytes) to end-12
        for offset in range(2, len(data) - 11):
            try:
                k1, k2, k3 = struct.unpack_from('<III', data, offset)
            except struct.error:
                break

            # Quick sanity: k3 must be ODD for full-period LCG
            # k2 and k3 must be non-zero
            if k3 == 0 or k2 == 0 or not (k3 & 1):
                continue

            self.attempts += 1
            score = self._score(k1, k2, k3)

            if score > best_score:
                best_score  = score
                best_triple = (k1, k2, k3)
                best_offset = offset

        if best_triple:
            k1, k2, k3 = best_triple
            checked = min(10, len(self.enc_buf.buf))
            ratio   = best_score / checked if checked else 0
            LOG(f"  [KEYFND] {context} offset={best_offset} "
                f"score={best_score}/{checked} ({ratio*100:.0f}%) "
                f"k1=0x{k1:08X} k2=0x{k2:08X} k3=0x{k3:08X}")
            if ratio >= self.ACCEPT_RATIO:
                crypt.set_keys(k1, k2, k3)
                hits, total = self.enc_buf.replay(k1, k2, k3)
                LOG(f"  [KEYFND] Retroactive replay: {hits}/{total} hits")
                self.found = True
                return True
            else:
                LOGD(f"KEYFND {context} score too low ({ratio*100:.0f}% < "
                     f"{self.ACCEPT_RATIO*100:.0f}%), skipping")
        return False

key_finder = None  # initialized after crypt

# ── Gepard LCG Decryptor ─────────────────────────────────────────
class GepardDecryptor:
    def __init__(self):
        self.k1 = self.k2 = self.k3 = self.cur = 0
        self.on   = False
        self.hits = 0
        self.miss = 0

    def set_keys(self, k1, k2, k3):
        self.k1  = k1; self.k2 = k2; self.k3 = k3
        self.cur = k1; self.on  = True
        self.hits = self.miss = 0
        LOG(f"  [CRYPT ] Keys SET k1=0x{k1:08X} k2=0x{k2:08X} k3=0x{k3:08X}")
        LOGD(f"KEYS k1={k1:#010x} k2={k2:#010x} k3={k3:#010x}")
        LOGV("[VERIFY] Gepard encryption keys captured — decryption active")

    def decrypt(self, enc_sw):
        """Returns (real_switch, was_decrypted, verified).
           was_decrypted: keys were applied.
           verified: decrypted switch is a known opcode."""
        if not self.on or self.cur == 0:
            return enc_sw, False, False
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk       = (self.cur >> 16) & 0x7FFF
        real_sw  = (enc_sw ^ xk) & 0xFFFF
        verified = real_sw in PACKETS
        if verified: self.hits += 1
        else:
            self.miss += 1
            LOGD(f"DECRYPT MISS enc=0x{enc_sw:04X} xk=0x{xk:04X} → "
                 f"0x{real_sw:04X} cur=0x{self.cur:08X}")
        return real_sw, True, verified

    def reset(self):
        """Reset LCG state to k1 on every map_loaded (0x0073)."""
        self.cur  = self.k1
        self.hits = self.miss = 0
        LOG("  [CRYPT ] LCG reset (map_loaded)")

    @property
    def accuracy(self):
        total = self.hits + self.miss
        return 100 * self.hits / total if total else 0

crypt      = GepardDecryptor()
key_finder = GepardKeyFinder(enc_buf)

# ── OpenKore Packet Collector ────────────────────────────────────
class PacketCollector:
    def __init__(self):
        self.seen = defaultdict(lambda: {
            'name': '???', 'lengths': defaultdict(int),
            'min_len': 9999, 'max_len': 0,
            'samples': [], 'count': 0, 'direction': '?',
        })

    def record(self, sw, name, data, direction):
        e           = self.seen[sw]
        e['name']   = name; e['count'] += 1; e['direction'] = direction
        ln = len(data)
        e['lengths'][ln] += 1
        e['min_len'] = min(e['min_len'], ln)
        e['max_len'] = max(e['max_len'], ln)
        if len(e['samples']) < 4:
            e['samples'].append(data[:64])

    def _guess_openkore_length(self, sw):
        info = PACKETS.get(sw)
        if info:
            _, declared = info
            if declared > 0:  return 'fixed',    declared
            if declared == -1: return 'variable', -1
        e     = self.seen.get(sw, {})
        sizes = e.get('lengths', {})
        if not sizes:                return 'unknown',  0
        if len(sizes) == 1:          return 'fixed',    list(sizes.keys())[0]
        return 'variable', -1

    def _guess_fields(self, sw):
        e       = self.seen.get(sw, {})
        samples = e.get('samples', [])
        if len(samples) < 2: return "# not enough samples"
        min_len = min(len(s) for s in samples)
        if min_len < 3:      return "# too short"
        hints = []
        i = 2
        while i < min_len:
            if i + 4 <= min_len:
                bv = [s[i:i+4] for s in samples if len(s) >= i+4]
                if len(set(bv)) == 1:
                    val = struct.unpack_from('<I', bv[0])[0]
                    hints.append(f"off+{i}: const u32=0x{val:08X}"); i += 4; continue
                if len(set(bv)) > 1:
                    hints.append(f"off+{i}: vary u32 (ID/coord?)"); i += 4; continue
            if i + 2 <= min_len:
                b2 = [s[i:i+2] for s in samples if len(s) >= i+2]
                val = struct.unpack_from('<H', b2[0])[0]
                hints.append(f"off+{i}: {'const' if len(set(b2))==1 else 'vary'} u16"
                             + (f"=0x{val:04X}" if len(set(b2))==1 else ""))
                i += 2; continue
            i += 1
        return ("# fields: " + ", ".join(hints[:6])) if hints else "# (no pattern)"

    def export_openkore(self, path_prefix):
        recv_path = f"{path_prefix}_recvpackets.txt"
        stub_path = f"{path_prefix}_packets_stub.pm"
        recv_lines = [
            "# OpenKore recvpackets — auto-generated by ro_packet_parser_v5",
            f"# Session : {_ts}",
            f"# Server  : {SERVER_IP}:{SERVER_PORT}",
            f"# Gepard accuracy: {crypt.accuracy:.1f}% (hits={crypt.hits} miss={crypt.miss})",
            "# DO NOT use blindly — verify each entry against actual server behaviour", "",
        ]
        stub_lines = [
            "# OpenKore Packet stub — insert into server's packets.pm",
            f"# Generated: {_ts}", "", "%packets = (",
        ]
        for sw in sorted(self.seen.keys()):
            e              = self.seen[sw]
            lt, lv         = self._guess_openkore_length(sw)
            ok_len         = lv if lt in ('fixed','variable') else 0
            recv_lines.append(f"{sw:04X} {ok_len:5d}   # {e['name']} ({e['direction']}) seen={e['count']}x")
            stub_lines.append(f"    '{sw:04X}' => ['{e['name']}', '', [], {max(ok_len,0)}],  {self._guess_fields(sw)}")
        stub_lines.append(");")
        with open(recv_path, 'w', encoding='utf-8') as f: f.write('\n'.join(recv_lines))
        with open(stub_path, 'w', encoding='utf-8') as f: f.write('\n'.join(stub_lines))
        LOG(f"  [EXPORT] recvpackets → {recv_path}")
        LOG(f"  [EXPORT] packets stub → {stub_path}")
        return recv_path, stub_path

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
        for k in [k for k,v in self.E.items() if now - v['last'] > 30]:
            del self.E[k]

    def monsters(self): return [e for e in self.E.values() if e['type'] >= MONSTER_TYPE_MIN]
    def players(self):  return [e for e in self.E.values() if 0 < e['type'] < MONSTER_TYPE_MIN]

tracker = Tracker()

# ── Coord helpers ────────────────────────────────────────────────
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

# ── Generic inner sub-packet walker ─────────────────────────────
#
#  Scans a raw byte buffer for known switches (from PACKETS table),
#  validates the length, and dispatches each sub-packet found.
#
#  This replaces the copy-paste walking code in 0x0B1D, 0x79E8, and 0x0000.
#  Specifically handles:
#    - Fixed-length packets (plen > 0): direct dispatch
#    - Variable-length packets (plen == -1): read bytes 2-3 as length
#    - Unknown switches: skip 1 byte and continue scanning
#
#  Important: For packets like 0x0073 that trigger side-effects (crypt.reset),
#  dispatching them through dispatch() will correctly fire those effects.

def walk_inner(data, direction, allowed=None):
    """Walk inner byte stream dispatching sub-packets.
    allowed: set of allowed switch values (None = all PACKETS).
    Returns number of sub-packets dispatched."""
    dispatched = 0
    i = 0
    while i + 2 <= len(data):
        sw   = struct.unpack_from('<H', data, i)[0]
        info = PACKETS.get(sw)

        if info is None:
            i += 1
            continue

        # Optional whitelist
        if allowed and sw not in allowed:
            i += 1
            continue

        name, plen = info

        if plen > 0:                            # fixed-length
            if i + plen <= len(data):
                dispatch(data[i:i+plen], direction)
                dispatched += 1
                i += plen
            else:
                i += 1

        elif plen == -1:                         # variable-length
            if i + 4 > len(data):
                break
            vlen = struct.unpack_from('<H', data, i + 2)[0]
            if 4 <= vlen <= len(data) - i:
                dispatch(data[i:i+vlen], direction)
                dispatched += 1
                i += vlen
            else:
                i += 1

        else:
            i += 1

    return dispatched

# ── Packet Handlers ───────────────────────────────────────────────

def verify_with_memory(stat_name, packet_val):
    addr_map = {'HP': HP_ADDR, 'HPMAX': HPMAX_ADDR, 'SP': SP_ADDR, 'SPMAX': SPMAX_ADDR}
    addr = addr_map.get(stat_name)
    if not addr: return
    mem_val = read_u32(addr)
    if mem_val is None: return
    match = "✅ MATCH" if packet_val == mem_val else f"❌ DIFF mem={mem_val}"
    LOGV(f"  [VERIFY] {stat_name}: pkt={packet_val} mem@0x{addr:08X}={mem_val} {match}")

def handle_stat_info(data):
    r = up('<HI', data, 2)
    if not r: return
    t, v = r
    names = {
        1:'BaseEXP', 2:'JobEXP', 5:'HP', 6:'HPMAX', 7:'SP', 8:'SPMAX',
        9:'StatusPts', 11:'BaseLv', 12:'SkillPts', 22:'BaseEXPMax',
        23:'JobEXPMax', 24:'Weight', 25:'MaxWeight',
        41:'Attack', 43:'ItemDef', 44:'PlusDef', 45:'MDef', 46:'PlusMDef',
        48:'Hit', 49:'Flee', 50:'PlusFlee', 51:'Critical', 52:'PlusCrit', 53:'ASPD',
    }
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT  ] {n} = {v}")
    verify_with_memory(n, v)

def handle_stat_info2(data):
    r = up('<III', data, 2)
    if not r: return
    t, base, plus = r
    names = {13:'STR', 14:'AGI', 15:'VIT', 16:'INT', 17:'DEX', 18:'LUK'}
    LOG(f"  [STAT2 ] {names.get(t, f'type={t}')} base={base} bonus={plus} total={base+plus}")

def handle_actor_coords(data):
    """0x00B6: 6-byte actor coords — [BUG FIX v4] condition was >= 7, now >= 6."""
    if len(data) < 6: return
    r = up('<I', data, 2)
    if not r: return
    eid = r[0]
    coord_data = data[3:6]
    if len(coord_data) == 3:
        x, y, d = dec3(coord_data)
        if 0 <= x < 1024 and 0 <= y < 1024:
            tracker.update(eid, x=x, y=y)
            e     = tracker.E.get(eid, {})
            label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
            LOG(f"  [{label:7s}] 0x{eid:08X} pos=({x},{y}) dir={d}")
        else:
            LOGR(f"  [COORD ] 0x{eid:08X} bad coords x={x} y={y} raw={coord_data.hex()}")

def handle_actor_moved(data):
    if len(data) < 16: return
    r = up('<I6sI', data, 2)
    if not r: return
    eid, coords, tick = r
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
                        LOG(f"  [{label:7s}] 0x{eid:08X} type={jtype} ({x},{y}) {tracker.N.get(eid,'')}")
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
                            if 0 < x < 512 and 0 < y < 512:
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
    """Standard Gepard key exchange (0x02AE / 0x083E).
    Try offset 2, 4, 6 with LCG validity check."""
    for offset in (2, 4, 6):
        r = up('<III', data, offset)
        if not r: continue
        k1, k2, k3 = r
        if k3 == 0 or k2 == 0 or not (k3 & 1): continue
        crypt.set_keys(k1, k2, k3)
        LOGD(f"init_encrypt [{len(data)}B] offset={offset} hex={data[:20].hex(' ')}")
        if key_finder: key_finder.found = True
        return
    LOG(f"  [CRYPT ] init_encrypt [{len(data)}B] — no valid keys hex={data[:20].hex(' ')}")

# ── [NEW v5] map_login_ack key extraction ────────────────────────
#
#  On BamBoo server, 0x4753 is the first packet from the map server.
#  Analysis of session 20260318_143602 shows:
#    hex @ offset 4: 68 1d 65 27 b3 bb 89 64 79 b7 9b a6
#    k1=0x27651D68, k2=0x6489BBB3, k3=0xA69BB779
#    k3 is ODD (bit0=1) → valid full-period LCG ✓
#
#  Strategy:
#  1. Try offset 4 first (primary hypothesis from log analysis).
#  2. If ENC? buffer is already populated, use KeyFinder to score-verify.
#  3. If ENC? buffer is empty (keys arrive before any ENC?), just store
#     the keys speculatively — they'll be confirmed as soon as ENC? arrives.

def handle_map_login_ack(data):
    """0x4753 — extract Gepard LCG keys from payload.
    Keys are at offset 4 based on session analysis."""
    LOG(f"  [MAP   ] map_login_ack [{len(data)}B]")

    if len(data) < 16:
        return  # too short to contain keys

    # If we already have ENC? buffered, use score-based verification
    if enc_buf.buf and not crypt.on:
        found = key_finder.try_packet(data, "0x4753")
        if found:
            return

    # Even without ENC? to score against, try offset 4 speculatively:
    # the pattern k3=odd, k1/k2 non-zero is a necessary (not sufficient)
    # condition. We'll see quickly if it's right when ENC? starts arriving.
    for offset in (4, 8, 6):
        r = up('<III', data, offset)
        if not r: continue
        k1, k2, k3 = r
        if k3 == 0 or k2 == 0 or not (k3 & 1): continue
        crypt.set_keys(k1, k2, k3)
        LOG(f"  [CRYPT ] 0x4753 speculative keys @ offset {offset} "
            f"(score-verify pending first ENC?)")
        if key_finder: key_finder.found = True
        return

    LOG(f"  [CRYPT ] 0x4753 [{len(data)}B] — no valid key triple found")
    LOGD(f"0x4753 hex: {data[:36].hex(' ')}")

# ── [NEW v5] batch_actor2 handler ────────────────────────────────
#
#  0x79E8 is a large bulk actor update packet specific to BamBoo.
#  It contains multiple sub-packets including 0x00B6 (actor_coords).
#
#  From session log analysis: 0x00B6 found at data offsets 11 and 29.
#  The inner format matches standard sub-packet framing — we use walk_inner()
#  to scan the entire body.
#
#  Allowed inner switches: anything in PACKETS related to actor data.

_ACTOR_INNER = {
    0x00B6, 0x0078, 0x007B, 0x007C, 0x0080, 0x0086, 0x0087,
    0x0088, 0x0095, 0x0195, 0x022C, 0x02EE, 0x0856, 0x09FD,
    0x09FF, 0x0BD3,
}

def handle_batch_actor2(data):
    """0x79E8 — bulk actor spawn (BamBoo custom format).
    Inner sub-packets start at offset 4 (after switch + length field)."""
    if len(data) < 5: return

    # Try to score-verify keys now if we haven't yet
    if enc_buf.buf and not crypt.on and key_finder:
        key_finder.try_packet(data, "0x79E8")

    inner = data[4:]
    n = walk_inner(inner, "←", allowed=_ACTOR_INNER)
    if n > 0:
        LOG(f"  [BATCH ] 0x79E8 [{len(data)}B] dispatched {n} inner sub-packets")
    else:
        # No standard sub-packets found — log raw for manual analysis
        LOGR(f"  [BATCH ] 0x79E8 [{len(data)}B] no inner packets, raw={data[:32].hex(' ')}")

# ── [NEW v5] map_char_info handler ───────────────────────────────
#
#  0x2E19 is a character/map info packet sent after login.
#  From session analysis (256B): map name found at offset 26 as ASCII string.
#
#  Byte layout (from session 20260318_143602):
#    offset 0-1 : switch 0x2E19
#    offset 2-3 : length 256 (0x0100)
#    offset 4-7 : value=1 (account ID?)
#    offset 8-11: value=1 (char ID?)
#    offset 24-25: 0x0091 (map ID?)
#    offset 26+  : map name (null-terminated ASCII)

def handle_map_char_info(data):
    """0x2E19 — map/character info packet, extracts map name."""
    if len(data) < 30: return

    # Try to extract map name from offset 26
    try:
        name_raw = data[26:]
        null_pos = name_raw.find(b'\x00')
        map_name = name_raw[:null_pos].decode('ascii', errors='replace') if null_pos > 0 else ''
    except Exception:
        map_name = ''

    # Read what might be account/char IDs
    r = up('<II', data, 4)
    acc_id = r[0] if r else 0
    chr_id = r[1] if r else 0

    LOG(f"  [MAPINF] 0x2E19 map='{map_name}' acc={acc_id} chr={chr_id} [{len(data)}B]")

def handle_server_broadcast(data):
    """0x0283 — server-wide broadcast message."""
    if len(data) < 4: return
    body = data[4:]
    try:   text = body.decode('utf-8', errors='replace').rstrip('\x00')
    except: text = body.hex()
    LOG(f"  [BROAD ] {text[:120]}")

# ── Unknown packet tracker ───────────────────────────────────────
_seen_unk = {}
_silent   = {'null_packet', 'signal_01', 'signal_13a', 'signal_1901',
             'signal_1a01', 'signal_fd00', 'signal_fe00', 'signal_1430'}

# ── Dispatcher ───────────────────────────────────────────────────
def dispatch(data, direction):
    if len(data) < 2: return

    raw_sw = struct.unpack_from('<H', data, 0)[0]
    sw     = raw_sw
    dec    = False
    ver    = False

    # Decrypt client→server switch if Gepard keys are loaded
    if direction == "→" and crypt.on:
        sw, dec, ver = crypt.decrypt(raw_sw)
        if dec and not ver and raw_sw not in PACKETS:
            LOGD(f"SKIP unverified decrypt raw=0x{raw_sw:04X} → 0x{sw:04X}")
            _seen_unk[raw_sw] = _seen_unk.get(raw_sw, 0) + 1
            return
    elif direction == "→" and not crypt.on:
        # Buffer ENC? (2-byte unknown client→server) for key finder
        if raw_sw not in PACKETS:
            enc_buf.push(raw_sw)
            # Try to use buffered keys once we have enough samples
            if not crypt.on and len(enc_buf.buf) == 5 and key_finder:
                LOGD(f"ENC? buffer now has {len(enc_buf.buf)} entries, key-find triggered")

    enc_tag = f" [enc→0x{sw:04X}]" if dec else ""
    LOGR(f"{direction} 0x{sw:04X} [{len(data)}B]{enc_tag} {data[:32].hex(' ')}")

    info = PACKETS.get(sw)

    if info is None:
        _seen_unk[sw] = _seen_unk.get(sw, 0) + 1
        if _seen_unk[sw] <= 2:
            LOG(f"  [?????] {direction} 0x{sw:04X} [{len(data)}B]{enc_tag}")
            LOGU(f"{direction} 0x{sw:04X} [{len(data)}B] {data[:32].hex(' ')}")
        collector.record(sw, '???', data, direction)
        return

    name, _ = info
    collector.record(sw, name, data, direction)

    if name not in _silent:
        LOG(f"\n{direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_tag}")

    d = data

    # ── Route to handlers ────────────────────────────────────────
    if sw == 0x4753:
        handle_map_login_ack(d)          # [NEW v5] key extraction

    elif sw in (0x02AE, 0x083E):
        handle_init_encrypt(d)           # standard Gepard key exchange

    elif sw == 0x79E8:
        handle_batch_actor2(d)           # [NEW v5] bulk actor spawn

    elif sw == 0x2E19:
        handle_map_char_info(d)          # [NEW v5] map/char info

    elif sw == 0x0086:
        handle_actor_moved(d)

    elif sw == 0x00B6:
        handle_actor_coords(d)

    elif sw in (0x022C, 0x09FD, 0x09FF, 0x0856,
                0x02EE, 0x0078, 0x007B, 0x007C):
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

    elif sw == 0x0073:
        # map_loaded: reset LCG state — must happen after keys are set
        crypt.reset()
        snap = mem_snapshot()
        LOG(f"  [MAP   ] Entered game | memory: {snap}")

    elif sw == 0x0B1D:
        # Standard batch packet: walk inner for 0x00B6
        if len(d) > 4:
            n = walk_inner(d[4:], direction, allowed={0x00B6})
            if n == 0:
                # Fallback: brute-scan for any known actor packet
                walk_inner(d[4:], direction, allowed=_ACTOR_INNER)

    elif sw == 0x0000:
        # Variable null packet — contains stats AND possibly map_loaded (0x0073).
        # [FIX v5] Now walks ALL relevant inner types including 0x0073.
        inner = d[4:] if len(d) > 4 else b''
        i = 0
        while i + 2 <= len(inner):
            isw = struct.unpack_from('<H', inner, i)[0]
            if   isw == 0x0073 and i + 11  <= len(inner):
                dispatch(inner[i:i+11],  direction); i += 11
            elif isw == 0x00B0 and i + 8   <= len(inner):
                dispatch(inner[i:i+8],   direction); i += 8
            elif isw == 0x0141 and i + 14  <= len(inner):
                dispatch(inner[i:i+14],  direction); i += 14
            elif isw == 0x0086 and i + 16  <= len(inner):
                dispatch(inner[i:i+16],  direction); i += 16
            elif isw == 0x00B6 and i + 6   <= len(inner):
                dispatch(inner[i:i+6],   direction); i += 6
            elif isw == 0x0080 and i + 7   <= len(inner):
                dispatch(inner[i:i+7],   direction); i += 7
            else:
                i += 1

# ── Stream buffer with improved sync ────────────────────────────
class StreamBuf:
    def __init__(self, direction):
        self.buf    = b''
        self.dir    = direction
        self.synced = False

    def feed(self, data):
        self.buf += data
        if not self.synced:
            self._sync()
        self._process()

    def _is_good_anchor(self, sw, buf_offset):
        info = PACKETS.get(sw)
        if info is None: return False
        _, plen = info
        if plen >= 4: return True
        if plen == -1:
            if buf_offset + 4 <= len(self.buf):
                vlen = struct.unpack_from('<H', self.buf, buf_offset + 2)[0]
                return 4 <= vlen <= 32768
            return False
        return plen == 2

    def _sync(self):
        if self.synced: return
        scan_limit = min(len(self.buf) - 1, 256)

        for i in range(scan_limit):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS:
                _, plen = PACKETS[sw]
                if plen >= 4 or (plen == -1 and self._is_good_anchor(sw, i)):
                    if i > 0:
                        LOG(f"  [SYNC  ] {self.dir} skipped {i}B → 0x{sw:04X} (strong anchor)")
                    self.buf = self.buf[i:]; self.synced = True; return

        for i in range(scan_limit):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS and PACKETS[sw][1] == 2 and sw != 0x0000:
                if i > 0:
                    LOG(f"  [SYNC  ] {self.dir} skipped {i}B → 0x{sw:04X} (weak anchor)")
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
                    # [v5] Encrypted client packet: try decrypt first,
                    # then use the length field at bytes 2-3 (length NOT encrypted).
                    if len(self.buf) == 2: break
                    if len(self.buf) >= 4:
                        maybe = struct.unpack_from('<H', self.buf, 2)[0]
                        if 4 <= maybe <= 32768:
                            # Treat as variable-length encrypted packet
                            plen = maybe
                        else:
                            # Pure 2-byte encrypted switch
                            enc_buf.push(sw)
                            LOGR(f"→ [ENC?] 0x{sw:04X} {self.buf[:2].hex()}")
                            self.buf = self.buf[2:]; continue
                    else:
                        break
                else:
                    if len(self.buf) >= 4:
                        maybe = struct.unpack_from('<H', self.buf, 2)[0]
                        if 4 <= maybe <= 32768:
                            plen = maybe
                        else:
                            dispatch(self.buf[:2], self.dir)
                            self.buf = self.buf[2:]; continue
                    else:
                        break

            if len(self.buf) < plen: break
            dispatch(self.buf[:plen], self.dir)
            self.buf = self.buf[plen:]

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
                 f"ENC?buf={len(enc_buf.buf)}/{enc_buf.total}")
    if key_finder:
        lines.append(f"  KeyFnd  : attempts={key_finder.attempts} found={key_finder.found}")

    m = sorted(tracker.monsters(), key=lambda e: e.get('x', 0))
    p = sorted(tracker.players(),  key=lambda e: e.get('x', 0))
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
    LOG("  RO Packet Parser v5")
    LOG(f"  Server : {SERVER_IP}:{SERVER_PORT}")
    LOG(f"  Logs   : {os.path.abspath(LOG_DIR)}/ro_*_{_ts}.log")
    LOG("=" * 60)

    init_memory(TARGET_PID)
    snap = mem_snapshot()
    if snap and snap['x']:
        LOGV(f"[VERIFY] Initial memory: pos=({snap['x']},{snap['y']}) "
             f"HP={snap['hp']}/{snap['hpmax']} SP={snap['sp']}/{snap['spmax']}")

    LOG("\nรัน BamBoo_Client แล้ว login ได้เลย (ควรเริ่มก่อน login map)")
    LOG("กด Ctrl+C หยุด + export OpenKore table\n")

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
                if not pkt.tcp or not pkt.payload: continue
                payload = bytes(pkt.payload)
                if len(payload) < 2: continue
                if pkt.dst_addr == SERVER_IP:
                    buf_cl.feed(payload)
                else:
                    buf_sv.feed(payload)
                if time.time() - last_sum > 15:
                    summary(); last_sum = time.time()

    except KeyboardInterrupt:
        LOG("\nหยุด")
        summary()

        prefix = f"{OPENKORE_DIR}/ro_{_ts}"
        r, s   = collector.export_openkore(prefix)
        LOG(f"\n  → recvpackets : {r}")
        LOG(f"  → packets stub: {s}")

        LOG(f"\nUnknown switches: {len(_seen_unk)} ค่า")
        for sw, cnt in sorted(_seen_unk.items(), key=lambda x: -x[1])[:20]:
            LOG(f"  0x{sw:04X}  x{cnt}")

        LOG(f"\nGepard accuracy : {crypt.accuracy:.1f}% "
            f"(hits={crypt.hits} miss={crypt.miss})")
        LOG(f"ENC? buffer     : {len(enc_buf.buf)} current / {enc_buf.total} total seen")
        if key_finder:
            LOG(f"KeyFinder       : {key_finder.attempts} candidates tried, found={key_finder.found}")

    except Exception as e:
        LOG(f"Error: {e}")
        LOG("ต้องรันใฐานะ Administrator")

if __name__ == '__main__':
    main()
