# ro_packet_parser_v2.py
# Parse RO packets — with Encryption Detection, Decryption, and Log File
# ต้องรันใฐานะ Administrator
# pip install pydivert

import pydivert
import struct
import time
import os
import logging
from datetime import datetime
from collections import defaultdict

# ── Config ──────────────────────────────────────────────
SERVER_IP        = "136.110.172.32"
SERVER_PORT      = 24656
LOG_DIR          = "ro_logs"
LOG_RAW_HEX      = True    # เก็บ raw hex ของทุก packet
LOG_UNKNOWN_SW   = True    # log switch ที่ยังไม่รู้จัก
MONSTER_TYPE_MIN = 1000
PLAYER_TYPE_MAX  = 999
# ────────────────────────────────────────────────────────

# ── Logger setup ─────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)
_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

# Custom formatter ที่รองรับ milliseconds (แก้ปัญหา %f ใน strftime)
class MsFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created)
        return ct.strftime('%H:%M:%S') + f'.{ct.microsecond // 1000:03d}'

def make_handler(path):
    h = logging.FileHandler(path, encoding='utf-8')
    h.setFormatter(MsFormatter('%(asctime)s %(message)s'))
    return h

# Main log (human-readable)
log_main = logging.getLogger("ro_main")
log_main.setLevel(logging.DEBUG)
log_main.addHandler(make_handler(f"{LOG_DIR}/ro_session_{_ts}.log"))
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(message)s'))
log_main.addHandler(sh)

# Raw hex log
log_raw = logging.getLogger("ro_raw")
log_raw.setLevel(logging.DEBUG)
log_raw.addHandler(make_handler(f"{LOG_DIR}/ro_raw_{_ts}.log"))

# Unknown switch log
log_unk = logging.getLogger("ro_unknown")
log_unk.setLevel(logging.DEBUG)
log_unk.addHandler(make_handler(f"{LOG_DIR}/ro_unknown_switches_{_ts}.log"))

# Summary log
log_sum = logging.getLogger("ro_summary")
log_sum.setLevel(logging.DEBUG)
log_sum.addHandler(make_handler(f"{LOG_DIR}/ro_summary_{_ts}.log"))

def LOG(msg):
    log_main.info(msg)

def LOG_RAW(direction, switch, data):
    if not LOG_RAW_HEX:
        return
    hex_str = data[:64].hex(' ')
    truncated = '...' if len(data) > 64 else ''
    log_raw.debug(f"{direction} 0x{switch:04X} [{len(data)}B] {hex_str}{truncated}")

def LOG_UNK(direction, switch, data):
    if not LOG_UNKNOWN_SW:
        return
    hex_str = data[:32].hex(' ')
    log_unk.debug(f"{direction} 0x{switch:04X} [{len(data)}B] {hex_str}")

# ── Known switches ────────────────────────────────────────
SW = {
    # Server → Client
    0x0073: ("map_loaded",            11),
    0x007C: ("map_actor",             -1),
    0x0078: ("actor_exists",          -1),
    0x007B: ("actor_exists2",         -1),
    0x0086: ("actor_moved",           16),
    0x0080: ("actor_removed",          7),
    0x022C: ("actor_spawned",         -1),
    0x02EE: ("actor_display",         -1),
    0x09FD: ("actor_display2",        -1),
    0x09FF: ("actor_display3",        -1),
    0x0856: ("actor_display4",        -1),
    0x0095: ("actor_name",            30),
    0x0195: ("actor_name2",           30),
    0x00B0: ("stat_info",              8),
    0x0141: ("stat_info2",            14),
    0x00BD: ("stats_info",            -1),
    0x02AE: ("init_encrypt",          -1),  # ← Encryption key exchange!
    0x083E: ("init_encrypt2",         -1),
    0x0AC4: ("account_server_info",   -1),
    0x0069: ("login_ok",              -1),
    0x006B: ("char_list",             -1),
    0x00B4: ("npc_talk",              -1),
    0x009A: ("system_chat",           -1),
    0x008D: ("public_chat",           -1),
    # Client → Server
    0x0072: ("map_login",             -1),
    0x0436: ("map_login2",            -1),
    0x007D: ("map_loaded_ack",         2),
    0x035F: ("walk",                  -1),
    0x0089: ("action",                -1),
    0x009F: ("item_take",             -1),
}

# ──────────────────────────────────────────────────────────
# ENCRYPTION SYSTEM
# จาก OpenKore/Send.pm:
#   enc_val1 = (enc_val1 * 0x343FD + enc_val2) & 0xFFFFFFFF
#   messageID ^= (enc_val1 >> 16) & 0x7FFF
# ──────────────────────────────────────────────────────────
class RODecryptor:
    def __init__(self):
        self.key1      = 0      # crypt_key_1
        self.key2      = 0      # crypt_key_2
        self.key3      = 0      # crypt_key_3 (multiplier)
        self.cur_key   = 0      # rolling key
        self.enabled   = False
        self.MUL       = 0x000343FD

    def set_keys(self, key1, key2, key3):
        self.key1    = key1
        self.key2    = key2
        self.key3    = key3
        self.cur_key = key1
        self.enabled = True
        LOG(f"  [CRYPT ] Keys set: k1=0x{key1:08X} k2=0x{key2:08X} k3=0x{key3:08X}")

    def decrypt_switch(self, encrypted_switch):
        """
        Decrypt packet switch (2 bytes) ด้วย rolling XOR
        """
        if not self.enabled or self.cur_key == 0:
            return encrypted_switch, False

        # คำนวณ rolling key
        self.cur_key = (self.cur_key * self.key3 + self.key2) & 0xFFFFFFFF
        xor_key      = (self.cur_key >> 16) & 0x7FFF

        decrypted = (encrypted_switch ^ xor_key) & 0xFFFF
        return decrypted, True

    def reset(self):
        """Reset เมื่อ map change"""
        self.cur_key = self.key1
        LOG("  [CRYPT ] Key reset (map change)")

    def is_encrypted_heuristic(self, data):
        """
        ตรวจว่า packet น่าจะ encrypted ไหม
        โดยดูว่า switch ที่อ่านมาตรงกับ known switches หรือเปล่า
        ถ้าไม่ตรงเลย = น่าจะ encrypted
        """
        if len(data) < 2:
            return False
        sw = struct.unpack_from('<H', data, 0)[0]
        return sw not in SW

# ── Entity tracker ────────────────────────────────────────
class EntityTracker:
    def __init__(self):
        self.entities = {}
        self.names    = {}
        self.stats    = {}  # stat snapshots

    def update(self, eid, **kw):
        if eid not in self.entities:
            self.entities[eid] = {
                'id': eid, 'x': 0, 'y': 0,
                'type': 0, 'name': '', 'hp': 0,
                'first_seen': datetime.now().isoformat(),
                'last_seen': time.time()
            }
        self.entities[eid].update(kw)
        self.entities[eid]['last_seen'] = time.time()
        if eid in self.names:
            self.entities[eid]['name'] = self.names[eid]

    def set_name(self, eid, name):
        self.names[eid] = name
        if eid in self.entities:
            self.entities[eid]['name'] = name

    def remove(self, eid):
        self.entities.pop(eid, None)

    def cleanup(self, max_age=30.0):
        now = time.time()
        stale = [k for k, v in self.entities.items()
                 if now - v['last_seen'] > max_age]
        for k in stale:
            del self.entities[k]

    def get_monsters(self):
        return [e for e in self.entities.values()
                if e['type'] >= MONSTER_TYPE_MIN]

    def get_players(self):
        return [e for e in self.entities.values()
                if 0 < e['type'] <= PLAYER_TYPE_MAX]

# ── Coord helpers ─────────────────────────────────────────
def decode_3b(data):
    b = data
    x   = (b[0] << 2) | (b[1] >> 6)
    y   = ((b[1] & 0x3F) << 4) | (b[2] >> 4)
    d   = b[2] & 0x0F
    return x, y, d

def decode_6b(data):
    b = data
    fx = (b[0] << 2) | (b[1] >> 6)
    fy = ((b[1] & 0x3F) << 4) | (b[2] >> 4)
    tx = ((b[2] & 0x0F) << 6) | (b[3] >> 2)
    ty = ((b[3] & 0x03) << 8) | b[4]
    return fx, fy, tx, ty

def safe_unpack(fmt, data, off=0):
    sz = struct.calcsize(fmt)
    if off + sz > len(data):
        return None
    return struct.unpack_from(fmt, data, off)

# ── Packet parsers ────────────────────────────────────────
tracker  = EntityTracker()
crypt    = RODecryptor()

# track unknown switches ที่เจอแล้ว (ไม่ log ซ้ำ)
seen_unknown = defaultdict(int)

def parse_init_encrypt(data):
    """
    0x02AE / 0x083E — initialize_message_id_encryption
    Server ส่ง encryption keys มาให้ client
    Format: sw(2) + key1(4) + key2(4) + key3(4)  [12+ bytes]
    """
    r = safe_unpack('<III', data, 2)
    if not r:
        # ลอง format อื่น
        r = safe_unpack('<III', data, 4)
    if r:
        k1, k2, k3 = r
        crypt.set_keys(k1, k2, k3)
        LOG(f"  [CRYPT ] Encryption initialized!")
        LOG(f"           key1=0x{k1:08X} key2=0x{k2:08X} key3=0x{k3:08X}")
    else:
        LOG(f"  [CRYPT ] init_encrypt packet (unknown format) [{len(data)}B]")
        LOG(f"           hex: {data.hex(' ')}")

def parse_actor_display(data):
    try:
        sw = struct.unpack_from('<H', data, 0)[0]

        if sw == 0x022C:
            r = safe_unpack('<HH4sHHHIH', data, 0)
            if not r:
                return
            _, _, rid, spd, opt1, opt2, option, jtype = r
            eid = struct.unpack('<I', rid)[0]

            for off in [46, 50, 54, 42, 38]:
                if off + 3 <= len(data):
                    x, y, _ = decode_3b(data[off:off+3])
                    if 0 < x < 2000 and 0 < y < 2000:
                        tracker.update(eid, x=x, y=y, type=jtype)
                        label = "MONSTER" if jtype >= MONSTER_TYPE_MIN else "player"
                        name  = tracker.names.get(eid, '')
                        LOG(f"  [{label:7s}] id=0x{eid:08X} type={jtype:4d} "
                            f"pos=({x},{y}) {name}")
                        break

        elif sw in (0x09FD, 0x09FF, 0x0856, 0x02EE, 0x0078, 0x007B, 0x007C):
            if len(data) < 12:
                return
            eid = struct.unpack_from('<I', data, 4)[0]

            for type_off in [14, 16, 18, 20]:
                t = safe_unpack('<H', data, type_off)
                if t and t[0] > 0:
                    for coord_off in [54, 58, 50, 46, 42]:
                        if coord_off + 3 <= len(data):
                            x, y, _ = decode_3b(data[coord_off:coord_off+3])
                            if 0 < x < 2000 and 0 < y < 2000:
                                tracker.update(eid, x=x, y=y, type=t[0])
                                label = ("MONSTER" if t[0] >= MONSTER_TYPE_MIN
                                         else "player")
                                name  = tracker.names.get(eid, '')
                                LOG(f"  [{label:7s}] id=0x{eid:08X} "
                                    f"type={t[0]:4d} pos=({x},{y}) {name}")
                                break
                    break
    except Exception:
        pass

def parse_actor_moved(data):
    if len(data) < 16:
        return
    r = safe_unpack('<4s6sI', data, 2)
    if not r:
        return
    raw_id, raw_coords, tick = r
    eid = struct.unpack('<I', raw_id)[0]
    fx, fy, tx, ty = decode_6b(raw_coords)
    tracker.update(eid, x=tx, y=ty)
    e     = tracker.entities.get(eid, {})
    label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "player"
    name  = e.get('name', '')
    LOG(f"  [{label:7s}] id=0x{eid:08X} ({fx},{fy})→({tx},{ty})  {name}")

def parse_actor_removed(data):
    if len(data) < 7:
        return
    r = safe_unpack('<4sB', data, 2)
    if not r:
        return
    raw_id, rem_type = r
    eid   = struct.unpack('<I', raw_id)[0]
    e     = tracker.entities.get(eid, {})
    label = "MONSTER" if e.get('type', 0) >= MONSTER_TYPE_MIN else "player"
    name  = e.get('name', '')
    LOG(f"  [REMOVED] id=0x{eid:08X} ({label}) {name}")
    tracker.remove(eid)

def parse_actor_name(data):
    if len(data) < 30:
        return
    r = safe_unpack('<4s24s', data, 2)
    if not r:
        return
    raw_id, raw_name = r
    eid  = struct.unpack('<I', raw_id)[0]
    name = raw_name.split(b'\x00')[0].decode('utf-8', errors='replace').strip()
    tracker.set_name(eid, name)
    LOG(f"  [NAME   ] id=0x{eid:08X} → '{name}'")

def parse_stat_info(data):
    r = safe_unpack('<HI', data, 2)
    if not r:
        return
    stat_type, val = r
    stat_names = {
        1:'BaseEXP', 2:'JobEXP', 5:'HP', 6:'HPMAX',
        7:'SP', 8:'SPMAX', 11:'BaseLv', 12:'SkillPts',
        22:'BaseEXPMax', 23:'JobEXPMax', 24:'Weight',
        25:'MaxWeight',
    }
    sname = stat_names.get(stat_type, f'type={stat_type}')
    LOG(f"  [STAT   ] {sname} = {val}")

def parse_chat(data, kind="PUBLIC"):
    try:
        # sw(2) + len(2) + id(4) + message(variable)
        msg_raw = data[8:]
        if b':' in msg_raw:
            parts = msg_raw.split(b':', 1)
            name  = parts[0].decode('utf-8', errors='replace').strip('\x00 ')
            msg   = parts[1].decode('utf-8', errors='replace').strip('\x00 ')
            LOG(f"  [{kind:6s}] {name}: {msg}")
    except Exception:
        pass

# ── Main dispatch ─────────────────────────────────────────
def dispatch(data, direction="←"):
    if len(data) < 2:
        return

    raw_sw = struct.unpack_from('<H', data, 0)[0]

    # ── Encryption detection & decryption ──────────────────
    is_encrypted = False
    sw           = raw_sw
    decrypted_data = data

    if crypt.enabled and direction == "→":
        # Client → Server packets ที่ส่งออกจะถูก encrypt packet ID
        dec_sw, was_decrypted = crypt.decrypt_switch(raw_sw)
        if was_decrypted and dec_sw in SW:
            sw             = dec_sw
            decrypted_data = struct.pack('<H', dec_sw) + data[2:]
            is_encrypted   = True

    enc_mark = " [ENC→DEC]" if is_encrypted else ""
    sw_info  = SW.get(sw)

    # ── Log raw hex ────────────────────────────────────────
    LOG_RAW(direction, sw, data)

    # ── Unknown switch ─────────────────────────────────────
    if sw_info is None:
        seen_unknown[sw] += 1
        if seen_unknown[sw] <= 3:  # log แค่ 3 ครั้งแรก
            LOG_UNK(direction, sw, data)
            if seen_unknown[sw] == 1:
                LOG(f"  [?????  ] {direction} 0x{sw:04X} [{len(data)}B]{enc_mark} "
                    f"(unknown — logged to ro_unknown_switches)")
        return

    name, _ = sw_info
    LOG(f"\n{direction} 0x{sw:04X} ({name}) [{len(data)}B]{enc_mark}")

    # ── Dispatch ───────────────────────────────────────────
    d = decrypted_data

    if sw in (0x02AE, 0x083E):
        parse_init_encrypt(d)
    elif sw == 0x0086:
        parse_actor_moved(d)
    elif sw in (0x022C, 0x09FD, 0x09FF, 0x0856, 0x02EE,
                0x0078, 0x007B, 0x007C):
        parse_actor_display(d)
    elif sw == 0x0080:
        parse_actor_removed(d)
    elif sw in (0x0095, 0x0195):
        parse_actor_name(d)
    elif sw == 0x00B0:
        parse_stat_info(d)
    elif sw == 0x0141:
        r = safe_unpack('<HII', d, 2)
        if r:
            stype, base, plus = r
            LOG(f"  [STAT2  ] type={stype} base={base} plus={plus}")
    elif sw == 0x0073:
        crypt.reset()  # reset encryption key เมื่อเข้า map ใหม่
        LOG(f"  [MAP    ] Entered game — encryption key reset")
    elif sw in (0x008D, 0x009A):
        parse_chat(d, "CHAT")
    elif sw == 0x00B4:
        try:
            npc_id = struct.unpack_from('<I', d, 2)[0]
            msg    = d[6:].split(b'\x00')[0].decode('utf-8', errors='replace')
            LOG(f"  [NPC    ] id=0x{npc_id:08X} '{msg}'")
        except Exception:
            pass

# ── TCP stream ────────────────────────────────────────────
class StreamBuffer:
    def __init__(self, direction):
        self.buf       = b''
        self.direction = direction

    def feed(self, data):
        self.buf += data
        self._process()

    def _process(self):
        while len(self.buf) >= 2:
            sw   = struct.unpack_from('<H', self.buf, 0)[0]
            info = SW.get(sw)
            plen = info[1] if info else 0

            if plen == -1:
                if len(self.buf) < 4:
                    break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 65535:
                    self.buf = self.buf[2:]
                    continue

            elif plen == 0:
                # Unknown switch — ลอง dispatch แบบ best-effort
                # หา length จาก bytes 2-3 ดูว่าสมเหตุสมผลไหม
                if len(self.buf) >= 4:
                    maybe_len = struct.unpack_from('<H', self.buf, 2)[0]
                    if 4 <= maybe_len <= 4096:
                        plen = maybe_len
                    else:
                        dispatch(self.buf[:2], self.direction)
                        self.buf = self.buf[2:]
                        continue
                else:
                    break

            if len(self.buf) < plen:
                break

            dispatch(self.buf[:plen], self.direction)
            self.buf = self.buf[plen:]

# ── Summary ───────────────────────────────────────────────
def print_summary():
    tracker.cleanup()
    monsters = sorted(tracker.get_monsters(), key=lambda e: e.get('x', 0))
    players  = sorted(tracker.get_players(),  key=lambda e: e.get('x', 0))

    lines = [
        f"\n{'═'*60}",
        f"  SUMMARY  {datetime.now().strftime('%H:%M:%S')}",
        f"{'─'*60}",
        f"  Monsters ({len(monsters)}):",
    ]
    for m in monsters:
        name = m.get('name') or f"type={m['type']}"
        lines.append(
            f"    0x{m['id']:08X}  ({m['x']:3d},{m['y']:3d})  {name}")

    lines += [f"\n  Players ({len(players)}):"]
    for p in players:
        name = p.get('name') or f"type={p['type']}"
        lines += [f"    0x{p['id']:08X}  ({p['x']:3d},{p['y']:3d})  {name}"]
    lines += [f"{'═'*60}"]

    text = '\n'.join(lines)
    LOG(text)
    log_sum.info(text)

# ── MAIN ─────────────────────────────────────────────────
def main():
    buf_sv = StreamBuffer("←")  # server → client
    buf_cl = StreamBuffer("→")  # client → server

    filter_str = (
        f"tcp and "
        f"(ip.DstAddr == {SERVER_IP} or ip.SrcAddr == {SERVER_IP}) and "
        f"(tcp.DstPort == {SERVER_PORT} or tcp.SrcPort == {SERVER_PORT})"
    )

    LOG("=" * 60)
    LOG("  RO Packet Parser v2")
    LOG(f"  Server  : {SERVER_IP}:{SERVER_PORT}")
    LOG(f"  Log dir : {os.path.abspath(LOG_DIR)}")
    LOG(f"  Files   : ro_session_{_ts}.log")
    LOG(f"            ro_raw_{_ts}.log")
    LOG(f"            ro_unknown_switches_{_ts}.log")
    LOG(f"            ro_summary_{_ts}.log")
    LOG("=" * 60)
    LOG("Encryption: จะ detect อัตโนมัติเมื่อรับ 0x02AE packet")
    LOG("กด Ctrl+C หยุด\n")

    last_summary = time.time()

    try:
        with pydivert.WinDivert(filter_str) as w:
            for pkt in w:
                w.send(pkt)  # ส่งต่อ ไม่ block

                if not pkt.tcp or not pkt.payload:
                    continue

                payload = bytes(pkt.payload)
                if len(payload) < 2:
                    continue

                if pkt.dst_addr == SERVER_IP:
                    buf_cl.feed(payload)
                else:
                    buf_sv.feed(payload)

                # auto summary ทุก 15 วิ
                if time.time() - last_summary > 15:
                    print_summary()
                    last_summary = time.time()

    except KeyboardInterrupt:
        LOG("\nหยุด — สรุปสุดท้าย:")
        print_summary()
        LOG(f"\nUnknown switches พบทั้งหมด {len(seen_unknown)} ค่า:")
        for sw, cnt in sorted(seen_unknown.items(), key=lambda x: -x[1]):
            LOG(f"  0x{sw:04X}  x{cnt}")

    except Exception as e:
        LOG(f"\nError: {e}")
        LOG("Troubleshooting:")
        LOG("  1. ต้องรันใฐานะ Administrator")
        LOG("  2. pip install pydivert")

if __name__ == '__main__':
    main()