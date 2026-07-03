"""Shared protocol constants for Deck-Upad."""

import struct

# Network
HOST_IP = "192.168.50.1"
DECK_IP = "192.168.50.2"
INPUT_PORT = 5555      # Deck → Host: controller input
HAPTIC_PORT = 5556     # Host → Deck: haptic feedback
VIDEO_PORT = 5000       # Host → Deck: H.264 video stream
TOUCH_PORT = 5001       # Deck → Host: touch coordinates

# Packet types
PACKET_INPUT = 0x01
PACKET_HAPTIC = 0x02

# Neptune report
NEPTUNE_REPORT_SIZE = 64
NEPTUNE_REPORT_ID = 0x09

# HID report descriptor for virtual Steam Controller
# Defines: 16 buttons, 2 sticks (16-bit each), 2 triggers (8-bit each),
# 2 trackpads (16-bit X/Y + 16-bit force each), IMU (6 × 16-bit)
STEAM_CONTROLLER_VID = 0x28DE  # Valve
STEAM_CONTROLLER_PID = 0x1101  # SC1

# Button bit positions (matches Neptune layout)
BTN_A        = 0x0001
BTN_B        = 0x0002
BTN_X        = 0x0004
BTN_Y        = 0x0008
BTN_L1       = 0x0010
BTN_R1       = 0x0020
BTN_SELECT   = 0x0040
BTN_START    = 0x0080
BTN_MODE     = 0x0100
BTN_L3       = 0x0200
BTN_R3       = 0x0400
BTN_DPAD_UP  = 0x0800
BTN_DPAD_DOWN = 0x1000
BTN_DPAD_LEFT = 0x2000
BTN_DPAD_RIGHT = 0x4000
BTN_BACK     = 0x8000


def pack_input_report(buttons, lx, ly, rx, ry, lt, rt,
                      lpx, lpy, rpx, rpy, lpf, rpf,
                      ax, ay, az, gx, gy, gz):
    """Pack controller input into a UDP packet.

    Returns bytes ready to send.
    """
    return struct.pack('<BHIhhhhHHhhHHhhhh',
        PACKET_INPUT,
        buttons & 0xFFFF,
        lx, ly, rx, ry,
        lt, rt,
        lpx, lpy, rpx, rpy,
        lpf, rpf,
        ax, ay, az, gx, gy, gz
    )


def unpack_input_report(data):
    """Unpack a controller input UDP packet.

    Returns dict with all fields.
    """
    pkt_type, buttons, lx, ly, rx, ry, lt, rt, \
        lpx, lpy, rpx, rpy, lpf, rpf, \
        ax, ay, az, gx, gy, gz = struct.unpack('<BHIhhhhHHhhHHhhhh', data)
    return {
        'type': pkt_type,
        'buttons': buttons,
        'lx': lx, 'ly': ly,
        'rx': rx, 'ry': ry,
        'lt': lt, 'rt': rt,
        'lpad_x': lpx, 'lpad_y': lpy,
        'rpad_x': rpx, 'rpad_y': rpy,
        'lpad_force': lpf, 'rpad_force': rpf,
        'accel_x': ax, 'accel_y': ay, 'accel_z': az,
        'gyro_x': gx, 'gyro_y': gy, 'gyro_z': gz,
    }


def pack_haptic_report(left_motor, right_motor):
    """Pack haptic feedback into a UDP packet."""
    return struct.pack('<BBB', PACKET_HAPTIC, left_motor, right_motor)


def unpack_haptic_report(data):
    """Unpack a haptic feedback UDP packet."""
    pkt_type, left_motor, right_motor = struct.unpack('<BBB', data)
    return {'left_motor': left_motor, 'right_motor': right_motor}
