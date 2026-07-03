"""Neptune controller HID report parser.

Ported from spoofdeck-modified/src/input_handler.py.
Reads 64-byte HID reports from /dev/hidrawN and extracts
buttons, sticks, triggers, trackpads, and IMU data.
"""

import os
import struct
import time


def find_neptune_hidraw():
    """Find the Neptune controller's hidraw device."""
    base = "/sys/class/hidraw"
    if not os.path.isdir(base):
        return None
    for entry in os.listdir(base):
        device_dir = os.path.join(base, entry, "device")
        uevent_path = os.path.join(device_dir, "uevent")
        if not os.path.isfile(uevent_path):
            continue
        try:
            with open(uevent_path, "r") as f:
                content = f.read()
        except OSError:
            continue
        if "28DE" not in content or "1205" not in content:
            continue
        if "input2" not in content:
            continue
        dev_path = os.path.join("/dev", entry)
        if os.path.exists(dev_path):
            return dev_path
    return None


# Lizard-off commands — disable Deck's built-in mouse/keyboard emulation
LIZARD_OFF_CMDS = [
    b'\x81' + b'\x00' * 63,
    b'\x87\x03\x08\x07\x00' + b'\x00' * 59,
    b'\x87\x03\x07\x07\x00' + b'\x00' * 59,
    b'\x87\x03\x18\x00\x00' + b'\x00' * 59,
    b'\x87\x03\x15\x00\x00' + b'\x00' * 59,
]


def send_lizard_off(fd):
    """Disable lizard mode on the Neptune controller."""
    for cmd in LIZARD_OFF_CMDS:
        try:
            os.write(fd, cmd)
        except OSError:
            pass


class NeptuneReport:
    """Parsed Neptune controller state."""

    __slots__ = ('buttons', 'lx', 'ly', 'rx', 'ry',
                 'left_trigger', 'right_trigger',
                 'lpad_x', 'lpad_y', 'rpad_x', 'rpad_y',
                 'lpad_force', 'rpad_force',
                 'accel_x', 'accel_y', 'accel_z',
                 'gyro_x', 'gyro_y', 'gyro_z',
                 'timestamp')

    def __init__(self):
        self.buttons = 0
        self.lx = 0
        self.ly = 0
        self.rx = 0
        self.ry = 0
        self.left_trigger = 0
        self.right_trigger = 0
        self.lpad_x = 0
        self.lpad_y = 0
        self.rpad_x = 0
        self.rpad_y = 0
        self.lpad_force = 0
        self.rpad_force = 0
        self.accel_x = 0
        self.accel_y = 0
        self.accel_z = 0
        self.gyro_x = 0
        self.gyro_y = 0
        self.gyro_z = 0
        self.timestamp = 0


def parse_neptune_report(raw):
    """Parse a 64-byte Neptune HID report.

    Returns a NeptuneReport or None if the report is invalid.
    """
    if len(raw) < 64 or raw[2] != 0x09:
        return None

    rpt = NeptuneReport()
    ts = int(time.monotonic() * 1000000) & 0xFFFFFFFF

    btn8 = raw[8]
    btn9 = raw[9]
    btn10 = raw[10]
    btn11 = raw[11]
    btn13 = raw[13]
    btn14 = raw[14]

    b = 0
    # Byte 8
    if btn8 & 0x80: b |= 0x0001  # A
    if btn8 & 0x20: b |= 0x0002  # B
    if btn8 & 0x40: b |= 0x0004  # X
    if btn8 & 0x10: b |= 0x0008  # Y
    if btn8 & 0x08: b |= 0x0010  # L1
    if btn8 & 0x04: b |= 0x0020  # R1
    # Byte 9
    if btn9 & 0x10: b |= 0x0040  # Select
    if btn9 & 0x40: b |= 0x0080  # Start
    if btn9 & 0x20: b |= 0x0100  # Steam
    # Byte 10
    if btn10 & 0x40: b |= 0x0200  # L3
    # Byte 11
    if btn11 & 0x04: b |= 0x0400  # R3
    # D-pad (Byte 9)
    if btn9 & 0x01: b |= 0x0800  # Up
    if btn9 & 0x08: b |= 0x1000  # Down
    if btn9 & 0x04: b |= 0x2000  # Left
    if btn9 & 0x02: b |= 0x4000  # Right
    # Back grips
    if (btn13 & 0x02) or (btn9 & 0x80) or (btn13 & 0x04) or (btn10 & 0x01):
        b |= 0x8000

    rpt.buttons = b

    # Sticks (signed 16-bit, bytes 48-55)
    rpt.lx = struct.unpack_from('<h', raw, 48)[0]
    rpt.ly = struct.unpack_from('<h', raw, 50)[0]
    rpt.rx = struct.unpack_from('<h', raw, 52)[0]
    rpt.ry = struct.unpack_from('<h', raw, 54)[0]

    # Triggers (unsigned 16-bit, bytes 44-47)
    lt = struct.unpack_from('<H', raw, 44)[0]
    rt = struct.unpack_from('<H', raw, 46)[0]
    rpt.left_trigger = min(255, lt >> 7)
    rpt.right_trigger = min(255, rt >> 7)

    # Trackpads (signed 16-bit, bytes 16-23)
    rpt.lpad_x = struct.unpack_from('<h', raw, 16)[0]
    rpt.lpad_y = struct.unpack_from('<h', raw, 18)[0]
    rpt.rpad_x = struct.unpack_from('<h', raw, 20)[0]
    rpt.rpad_y = struct.unpack_from('<h', raw, 22)[0]

    # Trackpad force (unsigned 16-bit, bytes 56-59)
    rpt.lpad_force = struct.unpack_from('<H', raw, 56)[0]
    rpt.rpad_force = struct.unpack_from('<H', raw, 58)[0]

    # IMU (signed 16-bit, bytes 24-35)
    rpt.accel_x = struct.unpack_from('<h', raw, 24)[0]
    rpt.accel_y = struct.unpack_from('<h', raw, 26)[0]
    rpt.accel_z = struct.unpack_from('<h', raw, 28)[0]
    rpt.gyro_x = struct.unpack_from('<h', raw, 30)[0]
    rpt.gyro_y = struct.unpack_from('<h', raw, 32)[0]
    rpt.gyro_z = struct.unpack_from('<h', raw, 34)[0]

    rpt.timestamp = ts
    return rpt
