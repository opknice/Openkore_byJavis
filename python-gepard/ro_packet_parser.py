# ro_packet_parser.py
# Parse RO packets จาก BamBoo client โดยตรง (ไม่ต้อง Wireshark)
# ต้องรันใฐานะ Administrator
# pip install pydivert

import pydivert
import struct
import time
from collections import defaultdict

# ── Config ──────────────────────────────────────────────
SERVER_IP   = "136.110.172.32"
SERVER_PORT = 24656

# Monster type IDs จาก OpenKore jobs_lut (type >= 1000 = monster)
MONSTER_TYPE_MIN = 1000
PLAYER_TYPE_MAX  = 999

# ── Packet switches ที่สนใจ ──────────────────────────────
SW = {
    0x0086: "actor_moved",
    0x0078: "actor_exists",
    0x007B: "actor_exists2",
    0x022C: "actor_spawned",
    0x02EE: "actor_display",
    0x09FD: "actor_display2",
    0x09FF: "actor_display3",
    0x0856: "actor_display4",
    0x0080: "actor_removed",
    0x0095: "actor_name",
    0x0195: "actor_name2",
    0x0073: "map_loaded",
    0x007C: "map_actor",
    0x00B0: "stat_info",
}

# ── Coord decoders ────────────────────────────────────────
def decode_coords_3b(data):
    """3 bytes → (x, y, dir)"""
    if len(data) < 3:
        return 0, 0, 0
    b = data
    x   = (b[0] << 2) | (b[1] >> 6)
    y   = ((b[1] & 0x3F) << 4) | (b[2] >> 4)
    dir = b[2] & 0x0F
    return x, y, dir

def decode_coords_6b(data):
    """6 bytes → (from_x, from_y, to_x, to_y)"""
    if len(data) < 6:
        return 0, 0, 0, 0
    b = data
    fx = (b[0] << 2) | (b[1] >> 6)
    fy = ((b[1] & 0x3F) << 4) | (b[2] >> 4)
    tx = ((b[2] & 0x0F) << 6) | (b[3] >> 2)
    ty = ((b[3] & 0x03) << 8) | b[4]
    return fx, fy, tx, ty

def unpack_safe(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)

# ── Entity tracker ────────────────────────────────────────
class EntityTracker:
    def __init__(self):
        self.entities = {}   # id → {x, y, type, name, hp, last_seen}
        self.names    = {}   # id → name (from actor_name packet)

    def update(self, entity_id, **kwargs):
        if entity_id not in self.entities:
            self.entities[entity_id] = {
                'id': entity_id, 'x': 0, 'y': 0,
                'type': 0, 'name': '', 'hp': 0,
                'last_seen': time.time()
            }
        self.entities[entity_id].update(kwargs)
        self.entities[entity_id]['last_seen'] = time.time()

        # ใส่ชื่อถ้ามีใน cache
        if entity_id in self.names:
            self.entities[entity_id]['name'] = self.names[entity_id]

    def set_name(self, entity_id, name):
        self.names[entity_id] = name
        if entity_id in self.entities:
            self.entities[entity_id]['name'] = name

    def remove(self, entity_id):
        self.entities.pop(entity_id, None)

    def cleanup(self, max_age=10.0):
        now = time.time()
        old = [k for k, v in self.entities.items()
               if now - v['last_seen'] > max_age]
        for k in old:
            del self.entities[k]

    def get_monsters(self):
        return [e for e in self.entities.values()
                if e['type'] >= MONSTER_TYPE_MIN]

    def get_players(self):
        return [e for e in self.entities.values()
                if 0 < e['type'] <= PLAYER_TYPE_MAX]

# ── Packet parser ─────────────────────────────────────────
tracker = EntityTracker()

def parse_actor_display(data):
    """Parse actor_display packets (0x022C, 0x09FD, etc.)"""
    if len(data) < 20:
        return

    try:
        # Common fields: switch(2) + len(2) + ID(4) + ...
        # Format depends on switch — ลองทั้งสองแบบ
        result = unpack_safe('<v v a4', data, 0)
        if not result:
            return
        switch, plen, raw_id = result
        entity_id = struct.unpack('<I', raw_id)[0]

        if switch == 0x022C:
            # 022C format: sw(2)+len(2)+ID(4)+spd(2)+opt1(2)+opt2(2)+
            #              option(4)+type(2)+...+coords(3 or 6)+...
            r = unpack_safe('<HH4sHHHIH', data, 0)
            if not r:
                return
            sw, ln, rid, spd, opt1, opt2, option, jtype = r
            eid = struct.unpack('<I', rid)[0]

            # หา coords — offset ขึ้นกับ version
            # ลอง offset 46 (common สำหรับ 022C)
            for off in [46, 50, 54, 42]:
                if off + 3 <= len(data):
                    x, y, _ = decode_coords_3b(data[off:off+3])
                    if 0 < x < 1000 and 0 < y < 1000:
                        tracker.update(eid, x=x, y=y, type=jtype)

                        label = "MONSTER" if jtype >= MONSTER_TYPE_MIN else "player"
                        print(f"  [{label:7s}] id=0x{eid:08X} type={jtype:4d} "
                              f"pos=({x:3d},{y:3d})")
                        break

        elif switch in (0x09FD, 0x09FF, 0x0856):
            # Newer format — ID ที่ offset 4
            r = unpack_safe('<4s', data, 4)
            if r:
                eid = struct.unpack('<I', r[0])[0]
                # type ที่ offset ต่างๆ
                for type_off in [14, 16, 18]:
                    t = unpack_safe('<H', data, type_off)
                    if t and t[0] > 0:
                        # หา coords
                        for coord_off in [54, 58, 50, 46]:
                            if coord_off + 3 <= len(data):
                                x, y, _ = decode_coords_3b(
                                    data[coord_off:coord_off+3])
                                if 0 < x < 1000 and 0 < y < 1000:
                                    tracker.update(eid, x=x, y=y, type=t[0])
                                    label = ("MONSTER" if t[0] >= MONSTER_TYPE_MIN
                                             else "player")
                                    print(f"  [{label:7s}] id=0x{eid:08X} "
                                          f"type={t[0]:4d} pos=({x:3d},{y:3d})")
                                    break
                        break

    except Exception as e:
        pass  # skip malformed packets

def parse_actor_moved(data):
    """0x0086: actor_moved — ID(4) + coords(6) + tick(4)"""
    if len(data) < 16:
        return
    r = unpack_safe('<4s6sI', data, 2)
    if not r:
        return
    raw_id, raw_coords, tick = r
    eid = struct.unpack('<I', raw_id)[0]
    fx, fy, tx, ty = decode_coords_6b(raw_coords)

    if eid in tracker.entities:
        e = tracker.entities[eid]
        tracker.update(eid, x=tx, y=ty)
        label = "MONSTER" if e['type'] >= MONSTER_TYPE_MIN else "player"
        name  = e.get('name', '')
        print(f"  [{label:7s}] id=0x{eid:08X} "
              f"({fx},{fy})→({tx},{ty})  {name}")

def parse_actor_removed(data):
    """0x0080: actor_removed — ID(4) + type(1)"""
    if len(data) < 7:
        return
    r = unpack_safe('<4sB', data, 2)
    if not r:
        return
    raw_id, rem_type = r
    eid = struct.unpack('<I', raw_id)[0]
    if eid in tracker.entities:
        e = tracker.entities[eid]
        label = "MONSTER" if e['type'] >= MONSTER_TYPE_MIN else "player"
        print(f"  [REMOVED ] id=0x{eid:08X} ({label})")
    tracker.remove(eid)

def parse_actor_name(data):
    """0x0095/0x0195: actor_name — ID(4) + name(24)"""
    if len(data) < 30:
        return
    r = unpack_safe('<4s24s', data, 2)
    if not r:
        return
    raw_id, raw_name = r
    eid  = struct.unpack('<I', raw_id)[0]
    name = raw_name.split(b'\x00')[0].decode('utf-8', errors='replace')
    tracker.set_name(eid, name)
    print(f"  [NAME    ] id=0x{eid:08X} name='{name}'")

def parse_packet(data, direction="←"):
    """Main packet dispatcher"""
    if len(data) < 2:
        return

    switch = struct.unpack_from('<H', data, 0)[0]
    name   = SW.get(switch, None)

    if name is None:
        return  # ไม่สนใจ packet นี้

    print(f"\n{direction} 0x{switch:04X} ({name}) [{len(data)} bytes]")

    if switch == 0x0086:
        parse_actor_moved(data)
    elif switch in (0x022C, 0x09FD, 0x09FF, 0x0856, 0x0078, 0x007B, 0x007C):
        parse_actor_display(data)
    elif switch == 0x0080:
        parse_actor_removed(data)
    elif switch in (0x0095, 0x0195):
        parse_actor_name(data)
    elif switch == 0x0073:
        print(f"  [MAP LOAD] You are now in game")
    elif switch == 0x00B0:
        r = unpack_safe('<HI', data, 2)
        if r:
            stat_type, val = r
            stat_names = {
                5: 'HP', 6: 'HPMAX', 7: 'SP', 8: 'SPMAX',
                1: 'BaseEXP', 22: 'BaseEXPMax',
            }
            sname = stat_names.get(stat_type, f'type={stat_type}')
            print(f"  [STAT    ] {sname} = {val}")

# ── TCP stream reassembler (simple) ──────────────────────
class StreamBuffer:
    def __init__(self):
        self.buf = b''

    def feed(self, data):
        self.buf += data
        self._process()

    def _process(self):
        while len(self.buf) >= 2:
            switch = struct.unpack_from('<H', self.buf, 0)[0]

            # หา packet length จาก switch
            plen = self._get_length(switch)

            if plen == -1:
                # Variable length — อ่านจาก bytes 2-3
                if len(self.buf) < 4:
                    break
                plen = struct.unpack_from('<H', self.buf, 2)[0]
                if plen < 4 or plen > 65535:
                    self.buf = self.buf[2:]
                    continue

            if plen == 0:
                # Unknown packet — skip 2 bytes
                self.buf = self.buf[2:]
                continue

            if len(self.buf) < plen:
                break  # รอ data เพิ่ม

            parse_packet(self.buf[:plen])
            self.buf = self.buf[plen:]

    def _get_length(self, switch):
        """Length table สำหรับ packets ที่สนใจ"""
        lengths = {
            0x0086: 16,
            0x0080: 7,
            0x0095: 30,
            0x0195: 30,
            0x0073: 11,
            0x00B0: 8,
            # Variable length:
            0x022C: -1,
            0x09FD: -1,
            0x09FF: -1,
            0x0856: -1,
            0x0078: -1,
            0x007B: -1,
            0x007C: -1,
        }
        return lengths.get(switch, 0)

# ── Summary display ───────────────────────────────────────
def print_summary():
    tracker.cleanup(max_age=30.0)
    monsters = tracker.get_monsters()
    players  = tracker.get_players()

    print(f"\n{'═'*55}")
    print(f"  Monsters on map: {len(monsters)}")
    for m in sorted(monsters, key=lambda e: e['x']):
        name = m.get('name', f"type={m['type']}")
        print(f"    0x{m['id']:08X}  pos=({m['x']:3d},{m['y']:3d})  {name}")

    print(f"\n  Players on map: {len(players)}")
    for p in sorted(players, key=lambda e: e['x']):
        name = p.get('name', f"type={p['type']}")
        print(f"    0x{p['id']:08X}  pos=({p['x']:3d},{p['y']:3d})  {name}")
    print(f"{'═'*55}\n")

# ── MAIN ─────────────────────────────────────────────────
def main():
    buf_from_server = StreamBuffer()
    buf_from_client = StreamBuffer()

    filter_str = (f"tcp and "
                  f"(ip.DstAddr == {SERVER_IP} or ip.SrcAddr == {SERVER_IP}) and "
                  f"(tcp.DstPort == {SERVER_PORT} or tcp.SrcPort == {SERVER_PORT})")

    print("=" * 55)
    print("  RO Packet Parser")
    print(f"  Server: {SERVER_IP}:{SERVER_PORT}")
    print("=" * 55)
    print("รัน BamBoo_Client แล้ว login เข้า map ได้เลยค่ะ")
    print("กด Ctrl+S เพื่อดู monster summary")
    print("กด Ctrl+C หยุด\n")

    last_summary = time.time()

    try:
        with pydivert.WinDivert(filter_str) as w:
            for packet in w:
                w.send(packet)  # ส่ง packet ต่อไปตามปกติ ไม่ block

                if not packet.tcp or not packet.payload:
                    continue

                payload = bytes(packet.payload)
                if len(payload) < 2:
                    continue

                if packet.dst_addr == SERVER_IP:
                    buf_from_client.feed(payload)
                else:
                    buf_from_server.feed(payload)

                # auto summary ทุก 10 วิ
                if time.time() - last_summary > 10:
                    print_summary()
                    last_summary = time.time()

    except KeyboardInterrupt:
        print("\n\nหยุด — สรุปสุดท้าย:")
        print_summary()

    except Exception as e:
        print(f"\nError: {e}")
        print("\nTroubleshooting:")
        print("  1. ต้องรันใฐานะ Administrator")
        print("  2. pip install pydivert")
        print("  3. WinDivert driver ต้องถูก install")

if __name__ == '__main__':
    main()
