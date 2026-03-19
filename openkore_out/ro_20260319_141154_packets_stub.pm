# OpenKore packets.pm stub
# 20260319_141154

%packets = (
    '0000' => ['null_packet', '', [], 0],  # need more samples
    '0086' => ['actor_moved', '', [], 16],  # need more samples
    '00B0' => ['stat_info', '', [], 8],  # off+2: vary u32, off+6: const u16=0x0000
    '00B6' => ['actor_coords', '', [], 6],  # off+2: vary u32
    '0141' => ['stat_info2', '', [], 14],  # off+2: vary u32, off+6: vary u32, off+10: vary u32
    '0283' => ['server_broadcast', '', [], 0],  # need more samples
    '0436' => ['map_login2', '', [], 0],  # need more samples
    '0AC4' => ['gepard_auth', '', [], 0],  # need more samples
    '4753' => ['map_login_ack', '', [], 0],  # off+2: vary u32, off+6: vary u32, off+10: vary u32, off+14: vary u32, off+18: vary u32, off+22: vary u32
    '6072' => ['???', '', [], 4632],  # need more samples
);