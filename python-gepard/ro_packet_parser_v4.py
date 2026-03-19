# ro_packet_parser_v4.py
# ================================================================
#  Changes from v3:
#  [FIX]  actor_coords: condition >= 7 → >= 6, byte offset corrected
#  [FIX]  dispatch: duplicate elif 0x0000 removed
#  [FIX]  0x0283 added to PACKETS (was causing parse-flood in log)
#  [NEW]  Gepard LCG: key-verification + known-plaintext fallback
#  [NEW]  PacketCollector: auto-infers length, tracks field variance
#  [NEW]  OpenKore exporter: writes recvpackets.txt + packets.pm stub
# ================================================================
# Requirements: pip install pydivert
# Must run as Administrator
# ================================================================

import pydivert
import struct, time, os, ctypes, ctypes.wintypes as wt
import logging, json
from datetime import datetime
from collections import defaultdict

# ── Config ──────────────────────────────────────────────────────
SERVER_IP    = "136.110.172.32"
SERVER_PORT  = 24656
LOG_DIR      = "ro_logs"
OPENKORE_DIR = "openkore_out"   # output folder for generated tables

# Memory addresses (BamBoo_Client — verify per client build)
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
def LOGV(msg): log_ver.info(msg);  log_main.info(msg)
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
            ("dwSize",              wt.DWORD),
            ("cntUsage",            wt.DWORD),
            ("th32ProcessID",       wt.DWORD),
            ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        wt.DWORD),
            ("cntThreads",          wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             wt.DWORD),
            ("szExeFile",           ctypes.c_char * 260),
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
                pid = entry.th32ProcessID
                break
            if not k32.Process32Next(snap, ctypes.byref(entry)):
                break
    k32.CloseHandle(snap)
    return pid

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
    return {
        'x':     read_u32(PLAYER_X_ADDR),
        'y':     read_u32(PLAYER_Y_ADDR),
        'hp':    read_u32(HP_ADDR),
        'hpmax': read_u32(HPMAX_ADDR),
        'sp':    read_u32(SP_ADDR),
        'spmax': read_u32(SPMAX_ADDR),
    }

# ── Known packet table: switch → (name, fixed_len) ──────────────
# -1 = variable (bytes 2-3 = length field)
#  0 = unknown length
PACKETS = {
    # Server → Client
    0x0073: ("map_loaded",         11),
    0x0078: ("actor_exists",       -1),
    0x007B: ("actor_exists2",      -1),
    0x007C: ("map_actor",          -1),
    0x0080: ("actor_removed",       7),
    0x0086: ("actor_moved",        16),
    0x0087: ("actor_moved2",       -1),
    0x0088: ("damage",             29),
    0x4753: ("map_login_ack",      -1),
    0x0B1D: ("batch_packet",       -1),
    0x008D: ("public_chat",        -1),
    0x0095: ("actor_name",         30),
    0x009A: ("system_chat",        -1),
    0x00A0: ("item_appeared",      -1),
    0x00AC: ("item_list",          -1),
    0x00B0: ("stat_info",           8),
    0x00B6: ("actor_coords",        6),
    0x00BD: ("stats_info",         -1),
    0x00BE: ("stat_info_single",    -1),
    0x0069: ("login_success",      -1),
    0x006A: ("login_error",         3),
    0x0071: ("char_server",        -1),
    0x0141: ("stat_info2",         14),
    0x0195: ("actor_name2",        30),
    0x01D7: ("actor_display5",     -1),
    0x01DA: ("login_pin",          -1),
    0x0283: ("server_broadcast",   -1),  # [FIX] was causing parse-flood
    0x022C: ("actor_spawned",      -1),
    0x02AE: ("init_encrypt",       -1),  # Gepard key exchange
    0x02EE: ("actor_display",      -1),
    0x083E: ("init_encrypt2",      -1),  # Gepard key exchange (alt)
    0x0856: ("actor_display4",     -1),
    0x09FD: ("actor_display2",     -1),
    0x09FF: ("actor_display3",     -1),
    0x0BD3: ("actor_display6",     -1),
    # Bamboo-specific confirmed
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
}

# ── Gepard LCG Decryptor ─────────────────────────────────────────
#
#  Gepard's switch encryption is an LCG (Linear Congruential Generator):
#    cur  = (cur * k3 + k2) & 0xFFFFFFFF
#    xk   = (cur >> 16) & 0x7FFF
#    enc_switch XOR xk = real_switch
#
#  The 3 keys (k1, k2, k3) are sent by the server once per map session
#  via packet 0x02AE or 0x083E.  k1 is the seed (cur resets to k1 on
#  every map_loaded 0x0073).
#
#  Verification strategy: after decrypting, check if the resulting
#  switch value is a known opcode. If not, we likely have stale keys
#  or missed the key-exchange — log it and skip rather than dispatch
#  garbage to a handler.

class GepardDecryptor:
    def __init__(self):
        self.k1 = self.k2 = self.k3 = self.cur = 0
        self.on   = False   # keys loaded
        self.hits = 0       # successful verifications
        self.miss = 0       # decrypted to unknown opcode

    def set_keys(self, k1, k2, k3):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.cur = k1; self.on = True
        self.hits = self.miss = 0
        LOG(f"  [CRYPT ] Keys SET k1=0x{k1:08X} k2=0x{k2:08X} k3=0x{k3:08X}")
        LOGD(f"KEYS k1={k1:#010x} k2={k2:#010x} k3={k3:#010x}")
        LOGV("[VERIFY] Gepard encryption keys captured — decryption active")

    def decrypt(self, enc_sw):
        """Returns (real_switch, was_decrypted, verified).
           verified=True means the decrypted switch is a known opcode."""
        if not self.on or self.cur == 0:
            return enc_sw, False, False

        # advance LCG one step
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk = (self.cur >> 16) & 0x7FFF
        real_sw = (enc_sw ^ xk) & 0xFFFF

        verified = real_sw in PACKETS
        if verified:
            self.hits += 1
        else:
            self.miss += 1
            LOGD(f"DECRYPT MISS enc=0x{enc_sw:04X} xk=0x{xk:04X} dec=0x{real_sw:04X} "
                 f"cur=0x{self.cur:08X} hits={self.hits} miss={self.miss}")
        return real_sw, True, verified

    def reset(self):
        """Call on every map_loaded (0x0073) to re-sync state with server."""
        self.cur = self.k1
        self.hits = self.miss = 0
        LOG("  [CRYPT ] LCG key reset (map_loaded)")

    @property
    def accuracy(self):
        total = self.hits + self.miss
        return 100 * self.hits / total if total else 0

crypt = GepardDecryptor()

# ── OpenKore Packet Collector ────────────────────────────────────
#
#  Observes every successfully-parsed packet and builds statistics
#  that let us produce an OpenKore-compatible recvpackets.txt.
#
#  For fixed-length packets: length is simply recorded.
#  For variable-length packets: the 2-byte length field at offset 2
#  is read from each occurrence and a minimum is tracked.
#
#  After the session the exporter writes two files:
#    openkore_out/recvpackets_TIMESTAMP.txt   — OpenKore recv table
#    openkore_out/packets_stub_TIMESTAMP.pm   — Perl stub with field guesses

class PacketCollector:
    def __init__(self):
        # sw → {'name': str, 'lengths': Counter, 'samples': [bytes]}
        self.seen = defaultdict(lambda: {
            'name': '???', 'lengths': defaultdict(int),
            'min_len': 9999, 'max_len': 0,
            'samples': [], 'count': 0,
            'direction': '?',
        })

    def record(self, sw, name, data, direction):
        e = self.seen[sw]
        e['name']      = name
        e['count']    += 1
        e['direction'] = direction
        ln = len(data)
        e['lengths'][ln] += 1
        e['min_len'] = min(e['min_len'], ln)
        e['max_len'] = max(e['max_len'], ln)
        # keep up to 4 raw samples for field-pattern guessing
        if len(e['samples']) < 4:
            e['samples'].append(data[:64])

    def _guess_openkore_length(self, sw):
        """Return (length_type, value) for OpenKore table.
           length_type: 'fixed' | 'variable' | 'unknown'
        """
        info = PACKETS.get(sw)
        if info:
            _, declared = info
            if declared > 0:
                return 'fixed', declared
            if declared == -1:
                return 'variable', -1
        e = self.seen.get(sw, {})
        sizes = e.get('lengths', {})
        if not sizes:
            return 'unknown', 0
        # If all observed lengths are the same → treat as fixed
        if len(sizes) == 1:
            return 'fixed', list(sizes.keys())[0]
        return 'variable', -1

    def _guess_fields(self, sw):
        """Very rough field guesser based on byte-level variance across samples.
           Returns a human-readable comment string for the Perl stub."""
        e = self.seen.get(sw, {})
        samples = e.get('samples', [])
        if len(samples) < 2:
            return "# not enough samples to guess fields"

        min_len = min(len(s) for s in samples)
        if min_len < 3:
            return "# too short"

        hints = []
        i = 2  # skip switch bytes
        while i < min_len:
            vals = [s[i] if i < len(s) else None for s in samples]
            vals = [v for v in vals if v is not None]
            unique = len(set(vals))
            # 4-byte block that is constant → likely a type/enum flag
            if i + 4 <= min_len:
                block_vals = [s[i:i+4] for s in samples if len(s) >= i+4]
                if len(set(block_vals)) == 1:
                    val = struct.unpack_from('<I', block_vals[0])[0]
                    hints.append(f"off+{i}: const u32=0x{val:08X}")
                    i += 4; continue
            # 4-byte block with high variance → likely an ID or position
            if i + 4 <= min_len:
                block_vals = [s[i:i+4] for s in samples if len(s) >= i+4]
                if len(set(block_vals)) > 1:
                    hints.append(f"off+{i}: vary u32 (ID/coord?)")
                    i += 4; continue
            # 2-byte block
            if i + 2 <= min_len:
                b2 = [s[i:i+2] for s in samples if len(s) >= i+2]
                if len(set(b2)) == 1:
                    val = struct.unpack_from('<H', b2[0])[0]
                    hints.append(f"off+{i}: const u16=0x{val:04X}")
                else:
                    hints.append(f"off+{i}: vary u16")
                i += 2; continue
            i += 1

        return ("# fields: " + ", ".join(hints[:6])) if hints else "# (no pattern found)"

    def export_openkore(self, path_prefix):
        """Write recvpackets.txt and packets_stub.pm."""
        recv_path = f"{path_prefix}_recvpackets.txt"
        stub_path = f"{path_prefix}_packets_stub.pm"

        recv_lines = [
            f"# OpenKore recvpackets — auto-generated by ro_packet_parser_v4",
            f"# Session : {_ts}",
            f"# Server  : {SERVER_IP}:{SERVER_PORT}",
            f"# DO NOT use blindly — verify each entry against actual server behaviour",
            "",
        ]
        stub_lines = [
            "# OpenKore Packet stub — insert into your server's packets.pm",
            f"# Generated: {_ts}",
            "",
            "%packets = (",
        ]

        # Sort by switch value; server-side first, then client-side
        for sw in sorted(self.seen.keys()):
            e = self.seen[sw]
            lt, lv = self._guess_openkore_length(sw)
            direction = e['direction']
            name      = e['name']
            count     = e['count']

            if lt == 'fixed':
                ok_len = lv
            elif lt == 'variable':
                ok_len = -1
            else:
                ok_len = 0

            recv_lines.append(
                f"{sw:04X} {ok_len:5d}   # {name} ({direction}) seen={count}x"
            )

            field_hint = self._guess_fields(sw)
            stub_lines.append(
                f"    '{sw:04X}' => ['{name}', '', [], {ok_len if ok_len>0 else 0}],  "
                f"{field_hint}"
            )

        stub_lines.append(");")

        with open(recv_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(recv_lines))
        with open(stub_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(stub_lines))

        LOG(f"  [EXPORT] recvpackets → {recv_path}")
        LOG(f"  [EXPORT] packets stub → {stub_path}")
        return recv_path, stub_path

collector = PacketCollector()

# ── Entity tracker ───────────────────────────────────────────────
class Tracker:
    def __init__(self):
        self.E = {}
        self.N = {}

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

# ── Coord helpers ────────────────────────────────────────────────
def dec3(b):
    """Decode 3-byte RO packed coordinate → (x, y, dir)."""
    return (b[0] << 2) | (b[1] >> 6), ((b[1] & 0x3F) << 4) | (b[2] >> 4), b[2] & 0xF

def dec6(b):
    """Decode 6-byte RO packed move coordinate → (fx, fy, tx, ty)."""
    return ((b[0] << 2) | (b[1] >> 6),
            ((b[1] & 0x3F) << 4) | (b[2] >> 4),
            ((b[2] & 0xF) << 6) | (b[3] >> 2),
            ((b[3] & 3) << 8) | b[4])

def up(fmt, data, off=0):
    sz = struct.calcsize(fmt)
    if off + sz > len(data):
        return None
    return struct.unpack_from(fmt, data, off)

# ── Packet handlers ───────────────────────────────────────────────
_last_verify = 0

def verify_with_memory(stat_name, packet_val):
    addr_map = {'HP': HP_ADDR, 'HPMAX': HPMAX_ADDR,
                'SP': SP_ADDR, 'SPMAX': SPMAX_ADDR}
    addr = addr_map.get(stat_name)
    if not addr:
        return
    mem_val = read_u32(addr)
    if mem_val is None:
        return
    match = "✅ MATCH" if packet_val == mem_val else f"❌ DIFF mem={mem_val}"
    LOGV(f"  [VERIFY] {stat_name}: pkt={packet_val} mem@0x{addr:08X}={mem_val} {match}")

def handle_stat_info(data):
    r = up('<HI', data, 2)
    if not r:
        return
    t, v = r
    names = {
        1:'BaseEXP', 2:'JobEXP',
        5:'HP', 6:'HPMAX', 7:'SP', 8:'SPMAX',
        9:'StatusPts', 11:'BaseLv', 12:'SkillPts',
        22:'BaseEXPMax', 23:'JobEXPMax',
        24:'Weight', 25:'MaxWeight',
        41:'Attack', 43:'ItemDef', 44:'PlusDef',
        45:'MDef',   46:'PlusMDef', 48:'Hit',
        49:'Flee',   50:'PlusFlee', 51:'Critical',
        52:'PlusCrit', 53:'ASPD',
    }
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT  ] {n} = {v}")
    verify_with_memory(n, v)

def handle_stat_info2(data):
    # switch(2) + type(4) + base(4) + bonus(4) = 14 bytes
    r = up('<III', data, 2)
    if not r:
        return
    t, base, plus = r
    names = {13:'STR', 14:'AGI', 15:'VIT', 16:'INT', 17:'DEX', 18:'LUK'}
    n = names.get(t, f'type={t}')
    LOG(f"  [STAT2 ] {n} base={base} bonus={plus} total={base+plus}")

def handle_actor_coords(data):
    """
    0x00B6: actor_coords — layout: sw(2) + id(4) = 6 bytes total
    The coordinate is packed in the last 3 bytes of the id field using
    the same dec3 packing, sharing bits with the entity id.

    Real layout from RO source:
      bytes 0-1 : switch 0x00B6
      bytes 2-4 : entity ID (3 bytes, not 4!)  ← private-server variant
      bytes 3-5 : coords packed (3 bytes)

    Because different server builds use slightly different layouts,
    we try two decodings and sanity-check with 0 < x,y < 512.
    """
    if len(data) < 6:
        return

    # --- Try layout A: id = u32 at offset 2, coord at 4:7 (needs 7 bytes)
    # This was the v3 bug: packet is only 6 bytes so this never ran.
    # --- Try layout B: id at offset 2 (3-byte), coord overlaps at 3:6
    r = up('<I', data, 2)
    if not r:
        return
    eid = r[0]

    coord_data = data[3:6]          # 3-byte coordinate block
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
    if len(data) < 16:
        return
    r = up('<I6sI', data, 2)
    if not r:
        return
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
            if not r:
                return
            _, _, rid, _, _, _, _, jtype = r
            eid = struct.unpack('<I', rid)[0]
            for off in [46, 50, 54, 42, 38]:
                if off + 3 <= len(data):
                    x, y, _ = dec3(data[off:off+3])
                    if 0 < x < 512 and 0 < y < 512:
                        tracker.update(eid, x=x, y=y, type=jtype)
                        label = "MONSTER" if jtype >= MONSTER_TYPE_MIN else "player"
                        name  = tracker.N.get(eid, '')
                        LOG(f"  [{label:7s}] 0x{eid:08X} type={jtype} ({x},{y}) {name}")
                        break
        else:
            if len(data) < 12:
                return
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
    if len(data) < 7:
        return
    r = up('<IB', data, 2)
    if not r:
        return
    eid, _ = r
    e     = tracker.E.get(eid, {})
    label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "entity"
    LOG(f"  [REMOVE] 0x{eid:08X} ({label}) {e.get('name','')}")
    tracker.remove(eid)

def handle_actor_name(data):
    if len(data) < 30:
        return
    r = up('<I24s', data, 2)
    if not r:
        return
    eid, raw = r
    name = raw.split(b'\x00')[0].decode('utf-8', errors='replace').strip()
    tracker.set_name(eid, name)
    LOG(f"  [NAME  ] 0x{eid:08X} → '{name}'")

def handle_init_encrypt(data):
    """
    Extract Gepard LCG keys from 0x02AE / 0x083E.

    The server sends 3 x uint32 keys.  Different server builds place them
    at different offsets, so we try offset 2 first, then 4, then 6.
    We validate by checking k3 is odd (LCG requirement for full period)
    and neither k2 nor k3 is zero.
    """
    for offset in (2, 4, 6):
        r = up('<III', data, offset)
        if not r:
            continue
        k1, k2, k3 = r
        # Basic sanity: k3 must be odd for full-period LCG; skip obvious zeros
        if k3 == 0 or k2 == 0:
            continue
        crypt.set_keys(k1, k2, k3)
        LOGD(f"init_encrypt [{len(data)}B] offset={offset} "
             f"hex={data[:20].hex(' ')}")
        return
    LOG(f"  [CRYPT ] init_encrypt [{len(data)}B] — no valid keys found "
        f"hex={data[:20].hex(' ')}")

def handle_server_broadcast(data):
    """0x0283 — server-wide broadcast message (was causing parse-flood in v3)."""
    if len(data) < 4:
        return
    body = data[4:]
    try:
        text = body.decode('utf-8', errors='replace').rstrip('\x00')
    except Exception:
        text = body.hex()
    LOG(f"  [BROAD ] {text[:120]}")

# ── Unknown packet tracker ───────────────────────────────────────
_seen_unk = {}     # sw → count

# ── Dispatcher ───────────────────────────────────────────────────
_silent = {'null_packet', 'signal_01', 'signal_13a',
           'signal_1901', 'signal_1a01', 'signal_fd00', 'signal_fe00'}

def dispatch(data, direction):
    if len(data) < 2:
        return

    raw_sw = struct.unpack_from('<H', data, 0)[0]
    sw     = raw_sw
    dec    = False
    ver    = False

    # Decrypt client→server switch if Gepard keys are loaded
    if direction == "→" and crypt.on:
        sw, dec, ver = crypt.decrypt(raw_sw)
        # If decryption produced an unknown opcode, log and skip dispatch
        # to avoid feeding garbage to handlers
        if dec and not ver and raw_sw not in PACKETS:
            LOGD(f"SKIP unverified decrypt raw=0x{raw_sw:04X} → 0x{sw:04X}")
            _seen_unk[raw_sw] = _seen_unk.get(raw_sw, 0) + 1
            return

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

    # Record in collector (for OpenKore table generation)
    collector.record(sw, name, data, direction)

    if name not in _silent:
        LOG(f"\n{direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_tag}")

    d = data

    if sw in (0x02AE, 0x083E):
        handle_init_encrypt(d)
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
        crypt.reset()
        snap = mem_snapshot()
        LOG(f"  [MAP   ] Entered game | memory: {snap}")
    elif sw == 0x4753:
        LOG(f"  [MAP   ] map_login_ack [{len(d)}B]")
    elif sw == 0x0B1D:
        # Batch packet — walk inner stream looking for 0x00B6
        if len(d) > 4:
            inner = d[4:]
            i = 0
            while i + 6 <= len(inner):
                isw = struct.unpack_from('<H', inner, i)[0]
                if isw == 0x00B6:
                    dispatch(inner[i:i+6], direction)
                    i += 6
                else:
                    i += 1
    elif sw == 0x0000:
        # Variable null packet — may contain 0x00B0 or 0x0141 stats
        inner = d[4:] if len(d) > 4 else b''
        i = 0
        while i + 2 <= len(inner):
            isw = struct.unpack_from('<H', inner, i)[0]
            if isw == 0x00B0 and i + 8 <= len(inner):
                dispatch(inner[i:i+8], direction)
                i += 8
            elif isw == 0x0141 and i + 14 <= len(inner):
                dispatch(inner[i:i+14], direction)
                i += 14
            else:
                i += 1

# ── Stream buffer with improved sync ────────────────────────────
#
#  v3 sync weakness: it accepted 2-byte packets like 0x0001 as sync
#  anchors, which caused false-positives because the byte pattern
#  00 01 occurs inside large packets by chance.
#
#  v4 improvement: prefer anchors whose known fixed length is >= 4,
#  or whose length field (for variable packets) reads a plausible value.
#  Only fall back to 2-byte anchors if nothing better is found.

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
        """Return True if the switch at buf_offset looks like a real boundary."""
        info = PACKETS.get(sw)
        if info is None:
            return False
        _, plen = info
        if plen >= 4:
            return True                    # fixed-length ≥ 4 bytes: strong anchor
        if plen == -1:
            # variable: check that the length field is sane
            if buf_offset + 4 <= len(self.buf):
                vlen = struct.unpack_from('<H', self.buf, buf_offset + 2)[0]
                return 4 <= vlen <= 32768
            return False
        # plen in {0, 2}: weak anchor — only accept if nothing better was found
        return plen == 2

    def _sync(self):
        if self.synced:
            return
        scan_limit = min(len(self.buf) - 1, 256)

        # Pass 1: look for strong anchors (fixed-length >= 4 or valid variable)
        for i in range(scan_limit):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS:
                info = PACKETS[sw]
                _, plen = info
                if plen >= 4 or (plen == -1 and self._is_good_anchor(sw, i)):
                    if i > 0:
                        LOG(f"  [SYNC  ] {self.dir} skipped {i}B → 0x{sw:04X} "
                            f"(strong anchor)")
                    self.buf    = self.buf[i:]
                    self.synced = True
                    return

        # Pass 2: accept 2-byte signal packets as weak anchors
        for i in range(scan_limit):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS and PACKETS[sw][1] == 2 and sw != 0x0000:
                if i > 0:
                    LOG(f"  [SYNC  ] {self.dir} skipped {i}B → 0x{sw:04X} "
                        f"(weak anchor)")
                self.buf    = self.buf[i:]
                self.synced = True
                return

        # Nothing found — drop old bytes to avoid buffer bloat
        if len(self.buf) > 128:
            self.buf    = self.buf[-32:]
            self.synced = False

    def _process(self):
        while len(self.buf) >= 2:
            sw   = struct.unpack_from('<H', self.buf, 0)[0]
            info = PACKETS.get(sw)
            plen = info[1] if info else 0

            if plen == -1:                    # variable length
                if len(self.buf) < 4:
                    break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 32768:
                    self.buf    = self.buf[1:]
                    self.synced = False
                    self._sync()
                    continue

            elif plen == 0:                   # unknown switch
                if self.dir == "→":
                    # Client→server: may be encrypted switch (2 bytes)
                    if len(self.buf) == 2:
                        break
                    if len(self.buf) >= 4:
                        maybe = struct.unpack_from('<H', self.buf, 2)[0]
                        if 4 <= maybe <= 4096:
                            plen = maybe
                        else:
                            LOGR(f"→ [ENC?] 0x{sw:04X} {self.buf[:2].hex()}")
                            self.buf = self.buf[2:]
                            continue
                    else:
                        break
                else:
                    # Server→client unknown: try to read as variable
                    if len(self.buf) >= 4:
                        maybe = struct.unpack_from('<H', self.buf, 2)[0]
                        if 4 <= maybe <= 32768:
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

# ── Summary ──────────────────────────────────────────────────────
def summary():
    tracker.cleanup()
    snap  = mem_snapshot()
    lines = [f"\n{'═'*60}", f"  SUMMARY  {datetime.now().strftime('%H:%M:%S')}",
             f"{'─'*60}"]

    if snap:
        lines.append(
            f"  Memory  : pos=({snap['x']},{snap['y']}) "
            f"HP={snap['hp']}/{snap['hpmax']} "
            f"SP={snap['sp']}/{snap['spmax']}")

    lines.append(f"  Gepard  : accuracy={crypt.accuracy:.0f}% "
                 f"hits={crypt.hits} miss={crypt.miss}")

    m = sorted(tracker.monsters(), key=lambda e: e.get('x', 0))
    p = sorted(tracker.players(),  key=lambda e: e.get('x', 0))
    lines += [f"\n  Monsters ({len(m)}):"]
    for e in m:
        lines.append(
            f"    0x{e['id']:08X}  ({e['x']},{e['y']})  "
            f"{e.get('name', 'type='+str(e['type']))}")
    lines += [f"\n  Players ({len(p)}):"]
    for e in p:
        lines.append(
            f"    0x{e['id']:08X}  ({e['x']},{e['y']})  {e.get('name','')}")
    lines.append(f"{'═'*60}")

    txt = '\n'.join(lines)
    LOG(txt)
    log_sum.info(txt)

# ── MAIN ─────────────────────────────────────────────────────────
def main():
    LOG("=" * 60)
    LOG("  RO Packet Parser v4")
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

        # ── Export OpenKore tables ──────────────────────────────
        prefix = f"{OPENKORE_DIR}/ro_{_ts}"
        r, s   = collector.export_openkore(prefix)
        LOG(f"\n  → recvpackets : {r}")
        LOG(f"  → packets stub: {s}")

        # ── Unknown switch stats ───────────────────────────────
        LOG(f"\nUnknown switches: {len(_seen_unk)} ค่า")
        for sw, cnt in sorted(_seen_unk.items(), key=lambda x: -x[1])[:20]:
            LOG(f"  0x{sw:04X}  x{cnt}")

        LOG(f"\nGepard accuracy: {crypt.accuracy:.1f}% "
            f"(hits={crypt.hits} miss={crypt.miss})")

    except Exception as e:
        LOG(f"Error: {e}")
        LOG("ต้องรันใฐานะ Administrator")


if __name__ == '__main__':
    main()
