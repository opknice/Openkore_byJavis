# ro_packet_parser_direct_openkore.py
# Pure Direct OpenKore + Custom Decrypt/Encrypt + Translator
# ไม่ต้องรัน BamBoo_Client.exe เลย — Gepard ไม่ทำงาน

import struct, time, os, socket, threading
from datetime import datetime
import logging

# ── Config ──────────────────────────────────────────────
REAL_SERVER_IP    = "136.110.172.32"
REAL_SERVER_PORT  = 24656
OPENKORE_PORT     = 24657
LOG_DIR           = "ro_logs"

# ── Logger (เหมือนเดิม) ─────────────────────────────────────
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

log_main = make_logger("main", f"{LOG_DIR}/ro_session_{_ts}.log")
log_raw  = make_logger("raw",  f"{LOG_DIR}/ro_raw_{_ts}.log")

sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(message)s'))
log_main.addHandler(sh)

def LOG(msg): log_main.info(msg)
def LOGR(msg): log_raw.debug(msg)

# ── PACKETS, CUSTOM_TO_STANDARD, translate_to_* ─────────────────
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
    0x008D: ("public_chat",        -1),
    0x0095: ("actor_name",         30),
    0x009A: ("system_chat",        -1),
    0x00B0: ("stat_info",           8),
    0x00B6: ("actor_coords",        6),
    0x00BD: ("stats_info",         -1),
    0x0141: ("stat_info2",         14),
    0x0195: ("actor_name2",        30),
    0x022C: ("actor_spawned",      -1),
    0x02AE: ("init_encrypt",       -1),
    0x02EE: ("actor_display",      -1),
    0x083E: ("init_encrypt2",      -1),
    0x0856: ("actor_display4",     -1),
    0x09FD: ("actor_display2",     -1),
    0x09FF: ("actor_display3",     -1),
    # Bamboo-specific
    0x0000: ("null_packet",        -1),
    0x0001: ("signal_01",           2),
    0x013A: ("signal_13a",          2),
    0x1901: ("signal_1901",         2),
    0x1A01: ("signal_1a01",         2),
    0xFD00: ("signal_fd00",         8),
    0xFE00: ("signal_fe00",         8),
    # Client → Server
    0x0072: ("map_login",          -1),
    0x0436: ("map_login2",         -1),
    0x007D: ("map_loaded_ack",      2),
    0x0085: ("walk",               -1),
    0x0089: ("action",             -1),
    0x009F: ("item_take",          -1),
}

# Packet Translation Map (Custom BamBoo <--> Standard RO)
CUSTOM_TO_STANDARD = {
    0x0073: 0x0073, 0x0078: 0x0078, 0x007B: 0x007B, 0x007C: 0x007C,
    0x0080: 0x0080, 0x0086: 0x0086, 0x0087: 0x0087, 0x0088: 0x0088,
    0x008D: 0x008D, 0x0095: 0x0095, 0x009A: 0x009A, 0x00B0: 0x00B0,
    0x00B6: 0x00B6, 0x00BD: 0x00BD, 0x0141: 0x0141, 0x0195: 0x0195,
    0x022C: 0x022C, 0x02AE: 0x02AE, 0x02EE: 0x02EE, 0x083E: 0x083E,
    0x0856: 0x0856, 0x09FD: 0x09FD, 0x09FF: 0x09FF,
    0x0000: 0x0000, 0x0001: 0x0001, 0x013A: 0x013A,
    0x1901: 0x1901, 0x1A01: 0x1A01, 0xFD00: 0xFD00, 0xFE00: 0xFE00,
    0x0072: 0x0072, 0x0436: 0x0436, 0x007D: 0x007D,
    0x0085: 0x0085, 0x0089: 0x0089, 0x009F: 0x009F,
}
STANDARD_TO_CUSTOM = {v: k for k, v in CUSTOM_TO_STANDARD.items()}

def translate_to_standard(data):
    if len(data) < 2: return data
    sw = struct.unpack_from('<H', data, 0)[0]
    new_sw = CUSTOM_TO_STANDARD.get(sw, sw)
    return struct.pack('<H', new_sw) + data[2:]

def translate_to_custom(data):
    if len(data) < 2: return data
    sw = struct.unpack_from('<H', data, 0)[0]
    new_sw = STANDARD_TO_CUSTOM.get(sw, sw)
    return struct.pack('<H', new_sw) + data[2:]

# ── Decryptor (มี encrypt ด้วย) ─────────────────────────────
class Decryptor:
    def __init__(self):
        self.k1 = self.k2 = self.k3 = self.cur = 0
        self.on = False

    def set_keys(self, k1, k2, k3):
        self.k1 = k1; self.k2 = k2; self.k3 = k3
        self.cur = k1; self.on = True
        LOG(f"  [CRYPT ] KEYS SET k1=0x{k1:08X}")

    def decrypt(self, enc_sw):
        if not self.on or self.cur == 0:
            return enc_sw, False
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk = (self.cur >> 16) & 0x7FFF
        return (enc_sw ^ xk) & 0xFFFF, True

    def encrypt(self, sw):
        if not self.on or self.cur == 0:
            return sw
        self.cur = (self.cur * self.k3 + self.k2) & 0xFFFFFFFF
        xk = (self.cur >> 16) & 0x7FFF
        return (sw ^ xk) & 0xFFFF

    def reset(self):
        self.cur = self.k1

crypt = Decryptor()

# ── StreamBuf + Dispatcher ───────────────────────────────────────
# (คัดลอกจาก ro_packet_parser_v3_proxy_mitm.py)

# ── Coord helpers ───────────────────────────────────────────────
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

# ── Packet handlers ──────────────────────────────────────────────
def handle_init_encrypt(data):
    """0x02AE / 0x083E — server ส่ง encryption keys"""
    r = up('<III', data, 2)
    if r:
        crypt.set_keys(*r)
        return
    r = up('<III', data, 4)
    if r:
        crypt.set_keys(*r)
        return
    LOG(f"  [CRYPT ] init_encrypt received [{len(data)}B] hex={data[:16].hex()}")

# ── Dispatcher ──────────────────────────────────────────────────
_seen_unk = {}

def dispatch(data, direction):
    if len(data) < 2:
        return

    raw_sw = struct.unpack_from('<H', data, 0)[0]
    sw     = raw_sw
    dec    = False

    if direction == "→" and crypt.on:
        sw, dec = crypt.decrypt(raw_sw)

    enc_tag = f" [enc→0x{sw:04X}]" if dec else ""
    LOGR(f"{direction} 0x{sw:04X} [{len(data)}B]{enc_tag} {data[:32].hex(' ')}")

    info = PACKETS.get(sw)

    if info is None:
        if sw not in _seen_unk:
            _seen_unk[sw] = 0
        _seen_unk[sw] += 1
        if _seen_unk[sw] <= 2:
            LOG(f"  [?????] {direction} 0x{sw:04X} [{len(data)}B]{enc_tag}")
        return

    name, _ = info
    _silent = {'null_packet', 'signal_01', 'signal_13a',
               'signal_1901', 'signal_1a01', 'signal_fd00', 'signal_fe00'}
    if name not in _silent:
        LOG(f"\n{direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_tag}")

    d = data if not dec else struct.pack('<H', sw) + data[2:]

    # เรียก handler
    if sw in (0x02AE, 0x083E): 
        handle_init_encrypt(d)
    elif sw == 0x0073:
        crypt.reset()
        LOG(f"  [MAP   ] Entered game")
    elif sw in (0x0001, 0x013A, 0x1901, 0x1A01, 0xFD00, 0xFE00, 0x0000):
        pass

# ── StreamBuf ───────────────────────────────────────────────────
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
        if self.synced:
            return
        for i in range(min(len(self.buf) - 1, 64)):
            sw = struct.unpack_from('<H', self.buf, i)[0]
            if sw in PACKETS:
                if i > 0:
                    LOG(f"  [SYNC  ] {self.dir} skipped {i} bytes to sync at 0x{sw:04X}")
                self.buf    = self.buf[i:]
                self.synced = True
                return
        if len(self.buf) > 32:
            self.buf    = self.buf[-8:]
            self.synced = False

    def _process(self):
        while len(self.buf) >= 2:
            sw   = struct.unpack_from('<H', self.buf, 0)[0]
            info = PACKETS.get(sw)
            plen = info[1] if info else 0

            if plen == -1:
                if len(self.buf) < 4: break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 32768:
                    self.buf    = self.buf[1:]
                    self.synced = False
                    self._sync()
                    continue
            elif plen == 0:
                if self.dir == "→" and len(self.buf) == 2:
                    break
                if self.dir == "→" and len(self.buf) >= 4:
                    maybe = struct.unpack_from('<H', self.buf, 2)[0]
                    if 4 <= maybe <= 4096:
                        plen = maybe
                    else:
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

# ── Relay Threads ───────────────────────────────────────────
server_sock = None
openkore_sock = None

def relay_server_to_openkore():
    buf = StreamBuf("←")
    while True:
        try:
            data = server_sock.recv(4096)
            if not data: break
            buf.feed(data)
            if openkore_sock:
                try:
                    openkore_sock.sendall(translate_to_standard(data))
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    break
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            break
        except Exception as e:
            LOG(f"[relay_server_to_openkore] Error: {e}")
            break

def relay_openkore_to_server():
    buf = StreamBuf("→")
    while True:
        try:
            data = openkore_sock.recv(4096)
            if not data: break
            custom = translate_to_custom(data)
            if crypt.on:
                sw = struct.unpack_from('<H', custom, 0)[0]
                enc_sw = crypt.encrypt(sw)
                custom = struct.pack('<H', enc_sw) + custom[2:]
            if server_sock:
                try:
                    server_sock.sendall(custom)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    break
            buf.feed(custom)  # ให้ dispatch parse
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            break
        except Exception as e:
            LOG(f"[relay_openkore_to_server] Error: {e}")
            break

# ── MAIN ────────────────────────────────────────────────────
def main():
    LOG("=" * 70)
    LOG("  RO Direct OpenKore Proxy (No Client - Gepard Safe)")
    LOG(f"  OpenKore connect → 127.0.0.1:{OPENKORE_PORT}")
    LOG("=" * 70)

    global server_sock
    server_sock = socket.socket()
    server_sock.connect((REAL_SERVER_IP, REAL_SERVER_PORT))
    LOG("[PROXY] เชื่อมต่อ Real Server สำเร็จ")

    # รอ OpenKore
    listener = socket.socket()
    listener.bind(('127.0.0.1', OPENKORE_PORT))
    listener.listen(1)
    LOG(f"[PROXY] รอ OpenKore ที่ 127.0.0.1:{OPENKORE_PORT} ...")
    global openkore_sock
    openkore_sock, addr = listener.accept()
    LOG(f"[PROXY] OpenKore เชื่อมต่อจาก {addr}")

    threading.Thread(target=relay_server_to_openkore, daemon=True).start()
    threading.Thread(target=relay_openkore_to_server, daemon=True).start()

    LOG("\n=== พร้อม! OpenKore สั่งการได้เลย (Gepard ไม่เตะ) ===")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOG("หยุด")

if __name__ == '__main__':
    main()