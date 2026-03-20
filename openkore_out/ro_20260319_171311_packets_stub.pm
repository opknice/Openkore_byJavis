# OpenKore packets.pm stub
# 20260319_171311

%packets = (
    '0000' => ['null_packet', '', [], 0],  # off+2: vary u32, off+6: vary u32, off+10: vary u32, off+14: vary u32, off+18: vary u32, off+22: vary u32
    '0001' => ['signal_01', '', [], 2],  # need more samples
    '007D' => ['map_loaded_ack', '', [], 2],  # too short
    '0080' => ['actor_removed', '', [], 7],  # need more samples
    '0086' => ['actor_moved', '', [], 16],  # off+2: vary u32, off+6: vary u32, off+10: vary u32, off+14: const u16=0x9357
    '0088' => ['damage', '', [], 29],  # need more samples
    '0090' => ['???', '', [], 256],  # need more samples
    '00B0' => ['stat_info', '', [], 8],  # off+2: vary u32, off+6: const u16=0x0000
    '00B6' => ['actor_coords', '', [], 6],  # off+2: vary u32
    '0141' => ['stat_info2', '', [], 14],  # off+2: vary u32, off+6: vary u32, off+10: vary u32
    '0283' => ['server_broadcast', '', [], 0],  # need more samples
    '0436' => ['map_login2', '', [], 0],  # need more samples
    '0694' => ['???', '', [], 2],  # need more samples
    '0700' => ['???', '', [], 2],  # need more samples
    '09FD' => ['actor_display2', '', [], 0],  # need more samples
    '4194' => ['???', '', [], 2],  # need more samples
    '4753' => ['map_login_ack', '', [], 0],  # off+2: vary u32, off+6: vary u32, off+10: vary u32, off+14: vary u32, off+18: vary u32, off+22: vary u32
    '696C' => ['???', '', [], 31092],  # need more samples
    '6C42' => ['???', '', [], 29541],  # need more samples
    '7329' => ['???', '', [], 20889],  # need more samples
    '9357' => ['???', '', [], 182],  # need more samples
    '9499' => ['???', '', [], 6],  # need more samples
    '95AF' => ['???', '', [], 19545],  # need more samples
    '99A3' => ['???', '', [], 1684],  # need more samples
    'A126' => ['???', '', [], 2],  # need more samples
    'A143' => ['???', '', [], 16492],  # need more samples
    'B4A0' => ['???', '', [], 2],  # need more samples
    'B600' => ['???', '', [], 18176],  # need more samples
    'C392' => ['gepard_handshake', '', [], 44],  # off+2: vary u32, off+6: vary u32, off+10: vary u32, off+14: vary u32, off+18: vary u32, off+22: vary u32
    'D228' => ['???', '', [], 10341],  # need more samples
    'D749' => ['???', '', [], 2],  # need more samples
);