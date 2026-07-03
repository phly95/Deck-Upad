#!/usr/bin/env python3
"""Host-side UHID gamepad daemon — fake Steam Controller.

Receives controller input over UDP from the Deck and creates a virtual
Steam Controller via /dev/uhid. Uses the actual SC2 HID descriptor
and VID/PID so Steam recognizes it as a real Steam Controller.

Usage: sudo python3 uhid_gamepad.py [--deck DECK_IP]
"""

import argparse
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.protocol import (
    INPUT_PORT, HAPTIC_PORT, PACKET_INPUT, PACKET_HAPTIC,
    unpack_input_report, pack_haptic_report,
)

# --- UHID constants (from linux/uhid.h) ---
UHID_DESTROY = 1
UHID_CREATE2 = 11
UHID_INPUT2 = 12

BUS_USB = 0x03

# Valve Steam Controller VID/PID
SC_VID = 0x28DE
SC_PID = 0x1303  # BLE SC2

# Full SC2 HID Report Map descriptor (282 bytes)
# From spoofdeck-modified/src/gatt_db.py build_report_map()
SC2_RD = bytes([
    # --- Gamepad (Report ID 1) & Haptic Output (Report ID 2) ---
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x05,        # Usage (Gamepad)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x01,        #   Report ID (1)
    0x05, 0x09,        #   Usage Page (Button)
    0x19, 0x01,        #   Usage Minimum (1)
    0x29, 0x10,        #   Usage Maximum (16)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1)
    0x95, 0x10,        #   Report Count (16)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- 16 button bits
    0x05, 0x01,        #   Usage Page (Generic Desktop)
    0x09, 0x30,        #   Usage (X)
    0x09, 0x31,        #   Usage (Y)
    0x09, 0x33,        #   Usage (Rx)
    0x09, 0x34,        #   Usage (Ry)
    0x16, 0x00, 0x80,  #   Logical Minimum (-32768)
    0x26, 0xFF, 0x7F,  #   Logical Maximum (32767)
    0x75, 0x10,        #   Report Size (16)
    0x95, 0x04,        #   Report Count (4)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- 4 x 16-bit axes
    0x09, 0x32,        #   Usage (Z)
    0x09, 0x35,        #   Usage (Rz)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x02,        #   Report Count (2)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- 2 x 8-bit triggers
    0x85, 0x02,        #   Report ID (2)
    0x09, 0x20,        #   Usage (Survey)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x01,        #   Report Count (1)
    0x91, 0x02,        #   Output (Data,Var,Abs)         -- haptic output
    0xC0,              # End Collection

    # --- Mouse (Report ID 3) ---
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x02,        # Usage (Mouse)
    0xA1, 0x01,        # Collection (Application)
    0x09, 0x01,        #   Usage (Pointer)
    0xA1, 0x00,        #   Collection (Physical)
    0x85, 0x03,        #     Report ID (3)
    0x05, 0x09,        #     Usage Page (Button)
    0x19, 0x01,        #     Usage Minimum (1)
    0x29, 0x05,        #     Usage Maximum (5)
    0x15, 0x00,        #     Logical Minimum (0)
    0x25, 0x01,        #     Logical Maximum (1)
    0x95, 0x05,        #     Report Count (5)
    0x75, 0x01,        #     Report Size (1)
    0x81, 0x02,        #     Input (Data,Var,Abs)
    0x95, 0x01,        #     Report Count (1)
    0x75, 0x03,        #     Report Size (3)
    0x81, 0x01,        #     Input (Cnst,Var,Abs)        -- padding
    0x05, 0x01,        #     Usage Page (Generic Desktop)
    0x09, 0x30,        #     Usage (X)
    0x09, 0x31,        #     Usage (Y)
    0x15, 0x81,        #     Logical Minimum (-127)
    0x25, 0x7F,        #     Logical Maximum (127)
    0x75, 0x08,        #     Report Size (8)
    0x95, 0x02,        #     Report Count (2)
    0x81, 0x06,        #     Input (Data,Var,Rel)
    0x09, 0x38,        #     Usage (Wheel)
    0x15, 0x81,        #     Logical Minimum (-127)
    0x25, 0x7F,        #     Logical Maximum (127)
    0x75, 0x08,        #     Report Size (8)
    0x95, 0x01,        #     Report Count (1)
    0x81, 0x06,        #     Input (Data,Var,Rel)
    0xC0,              #   End Collection
    0xC0,              # End Collection

    # --- Keyboard (Report ID 4) ---
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x06,        # Usage (Keyboard)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x04,        #   Report ID (4)
    0x05, 0x07,        #   Usage Page (Key Codes)
    0x19, 0xE0,        #   Usage Minimum (224)
    0x29, 0xE7,        #   Usage Maximum (231)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1)
    0x95, 0x08,        #   Report Count (8)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- modifier byte
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x08,        #   Report Size (8)
    0x81, 0x01,        #   Input (Cnst,Var,Abs)          -- reserved
    0x19, 0x00,        #   Usage Minimum (0)
    0x29, 0x65,        #   Usage Maximum (101)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x65,        #   Logical Maximum (101)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x06,        #   Report Count (6)
    0x81, 0x00,        #   Input (Data,Ary,Abs)          -- 6 key codes
    0xC0,              # End Collection

    # --- SC2 Custom Input (Report ID 0x45, 45 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x45,        # Usage (0x45)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x45,        #   Report ID (0x45)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x2D,        #   Report Count (45)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- 45 raw bytes
    0xC0,              # End Collection

    # --- SC2 Custom Input (Report ID 0x47, 47 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x47,        # Usage (0x47)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x47,        #   Report ID (0x47)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x2F,        #   Report Count (47)
    0x81, 0x02,        #   Input (Data,Var,Abs)          -- 47 raw bytes
    0xC0,              # End Collection

    # --- SC2 Haptic Rumble Output (Report ID 0x80, 9 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x80,        # Usage (0x80)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x80,        #   Report ID (0x80)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x09,        #   Report Count (9)
    0x91, 0x02,        #   Output (Data,Var,Abs)         -- 9 bytes output
    0xC0,              # End Collection

    # --- Feature Report 0x02 (SC2 Command Channel, 64 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x00,        # Usage (0x00)
    0xA1, 0x02,        # Collection (Logical)
    0x85, 0x02,        #   Report ID (0x02)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0xB1, 0x02,        #   Feature (Data,Var,Abs)
    0xC0,              # End Collection

    # --- Feature Report 0x01 (SC2 Capabilities, 64 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        # Usage (0x01)
    0xA1, 0x02,        # Collection (Logical)
    0x85, 0x01,        #   Report ID (0x01)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0xB1, 0x02,        #   Feature (Data,Var,Abs)
    0xC0,              # End Collection

    # --- Feature Report 0x85 (SC2 Mode Switch, 64 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x85,        # Usage (0x85)
    0xA1, 0x02,        # Collection (Logical)
    0x85, 0x85,        #   Report ID (0x85)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0xB1, 0x02,        #   Feature (Data,Var,Abs)
    0xC0,              # End Collection

    # --- Feature Report 0x8F (SC2 Haptic Command, 64 bytes) ---
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x8F,        # Usage (0x8F)
    0xA1, 0x02,        # Collection (Logical)
    0x85, 0x8F,        #   Report ID (0x8F)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0xB1, 0x02,        #   Feature (Data,Var,Abs)
    0xC0,              # End Collection
])


def uhid_create(fd):
    """Create a virtual Steam Controller via UHID.

    UHID event struct (uhid.h, __attribute__((packed))):
      type:     u32  (4)
      name:     u8[128]
      phys:     u8[64]
      uniq:     u8[64]
      rd_size:  u16
      bus:      u16
      vendor:   u32
      product:  u32
      version:  u32
      country:  u32
      rd_data:  u8[4096]
    Total: 4 + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + 4096 = 4372
    """
    rd = SC2_RD
    buf = bytearray(4372)

    struct.pack_into('<I', buf, 0, UHID_CREATE2)

    name = b"Steam Controller\x00"
    buf[4:4+len(name)] = name

    # offsets: name(128) phys(64) uniq(64) = 260
    struct.pack_into('<H', buf, 260, len(rd))     # rd_size
    struct.pack_into('<H', buf, 262, BUS_USB)     # bus
    struct.pack_into('<I', buf, 264, SC_VID)      # vendor
    struct.pack_into('<I', buf, 268, SC_PID)      # product
    struct.pack_into('<I', buf, 272, 0x0100)      # version
    struct.pack_into('<I', buf, 276, 0)           # country
    buf[280:280+len(rd)] = rd

    os.write(fd, bytes(buf))
    print(f"[uhid] Created virtual Steam Controller (VID={SC_VID:#06x} PID={SC_PID:#06x})")


def uhid_input(fd, report_id, report_data):
    """Send an input report to the kernel via UHID_INPUT2."""
    pkt = bytes([report_id]) + report_data
    size = len(pkt)
    buf = struct.pack('<IH', UHID_INPUT2, size) + pkt
    os.write(fd, buf)


def build_sc2_report_45(rpt):
    """Build a 45-byte SC2 Report 0x45 from parsed Neptune data.

    Layout from spoofdeck-modified docs/sc2-protocol.md:
    [0]      seq_num (1 byte)
    [1-4]    buttons (32-bit Triton bitmask)
    [5-6]    sTriggerLeft (signed 16-bit)
    [7-8]    sTriggerRight (signed 16-bit)
    [9-10]   sLeftStickX (signed 16-bit)
    [11-12]  sLeftStickY (signed 16-bit)
    [13-14]  sRightStickX (signed 16-bit)
    [15-16]  sRightStickY (signed 16-bit)
    [17-18]  sLeftPadX (signed 16-bit)
    [19-20]  sLeftPadY (signed 16-bit)
    [21-22]  unPressureLeft (unsigned 16-bit)
    [23-24]  sRightPadX (signed 16-bit)
    [25-26]  sRightPadY (signed 16-bit)
    [27-28]  unPressureRight (unsigned 16-bit)
    [29-32]  timestamp (uint32_t us)
    [33-34]  accel_x (signed 16-bit)
    [35-36]  accel_y (signed 16-bit)
    [37-38]  accel_z (signed 16-bit)
    [39-40]  gyro_x (signed 16-bit)
    [41-42]  gyro_y (signed 16-bit)
    [43-44]  gyro_z (signed 16-bit)
    """
    report = bytearray(45)

    report[0] = build_sc2_report_45.seq & 0xFF
    build_sc2_report_45.seq = (build_sc2_report_45.seq + 1) & 0xFF

    # 32-bit Triton button bitmask
    b = 0
    buttons = rpt['buttons']
    if buttons & 0x0001: b |= (1 << 0)   # A
    if buttons & 0x0002: b |= (1 << 1)   # B
    if buttons & 0x0004: b |= (1 << 2)   # X
    if buttons & 0x0008: b |= (1 << 3)   # Y
    if buttons & 0x0010: b |= (1 << 19)  # L1
    if buttons & 0x0020: b |= (1 << 9)   # R1
    if buttons & 0x0040: b |= (1 << 6)   # Select
    if buttons & 0x0080: b |= (1 << 14)  # Start
    if buttons & 0x0100: b |= (1 << 16)  # Steam
    if buttons & 0x0200: b |= (1 << 15)  # L3
    if buttons & 0x0400: b |= (1 << 5)   # R3
    if buttons & 0x0800: b |= (1 << 13)  # D-pad Up
    if buttons & 0x1000: b |= (1 << 10)  # D-pad Down
    if buttons & 0x2000: b |= (1 << 12)  # D-pad Left
    if buttons & 0x4000: b |= (1 << 11)  # D-pad Right
    if buttons & 0x8000: b |= (1 << 17)  # Back grips

    struct.pack_into('<I', report, 1, b)
    struct.pack_into('<h', report, 5, min(32767, max(-32768, rpt['lt'] << 7)))
    struct.pack_into('<h', report, 7, min(32767, max(-32768, rpt['rt'] << 7)))
    struct.pack_into('<h', report, 9, rpt['lx'])
    struct.pack_into('<h', report, 11, rpt['ly'])
    struct.pack_into('<h', report, 13, rpt['rx'])
    struct.pack_into('<h', report, 15, rpt['ry'])
    struct.pack_into('<h', report, 17, rpt['lpad_x'])
    struct.pack_into('<h', report, 19, rpt['lpad_y'])
    struct.pack_into('<H', report, 21, rpt['lpad_force'])
    struct.pack_into('<h', report, 23, rpt['rpad_x'])
    struct.pack_into('<h', report, 25, rpt['rpad_y'])
    struct.pack_into('<H', report, 27, rpt['rpad_force'])
    struct.pack_into('<I', report, 29, rpt.get('timestamp', 0))
    struct.pack_into('<h', report, 33, rpt['accel_x'])
    struct.pack_into('<h', report, 35, rpt['accel_y'])
    struct.pack_into('<h', report, 37, rpt['accel_z'])
    struct.pack_into('<h', report, 39, rpt['gyro_x'])
    struct.pack_into('<h', report, 41, rpt['gyro_y'])
    struct.pack_into('<h', report, 43, rpt['gyro_z'])

    return bytes(report)


build_sc2_report_45.seq = 0


def build_sc2_report_01(rpt):
    """Build a 12-byte standard gamepad Report 0x01 from parsed Neptune data."""
    report = bytearray(12)
    struct.pack_into('<H', report, 0, rpt['buttons'] & 0xFFFF)
    struct.pack_into('<h', report, 2, rpt['lx'])
    struct.pack_into('<h', report, 4, rpt['ly'])
    struct.pack_into('<h', report, 6, rpt['rx'])
    struct.pack_into('<h', report, 8, rpt['ry'])
    report[10] = rpt['lt'] & 0xFF
    report[11] = rpt['rt'] & 0xFF
    return bytes(report)


def main():
    parser = argparse.ArgumentParser(description="Deck-Upad fake Steam Controller")
    parser.add_argument("--deck", default="192.168.50.2", help="Deck IP address")
    args = parser.parse_args()

    deck_ip = args.deck

    uhid_fd = os.open("/dev/uhid", os.O_RDWR)
    print("[uhid] Opened /dev/uhid")

    uhid_create(uhid_fd)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", INPUT_PORT))
    sock.setblocking(False)
    print(f"[uhid] Listening for input on :{INPUT_PORT}")

    deck_target = (deck_ip, HAPTIC_PORT)

    report_count = 0
    last_print = time.monotonic()

    try:
        while True:
            rlist, _, _ = select.select([sock], [], [], 1.0)
            if not rlist:
                continue

            try:
                data, addr = sock.recvfrom(512)
            except BlockingIOError:
                continue

            if len(data) < 3 or data[0] != PACKET_INPUT:
                continue

            rpt = unpack_input_report(data)

            # Send standard gamepad report (Report ID 1)
            rpt01 = build_sc2_report_01(rpt)
            uhid_input(uhid_fd, 0x01, rpt01)

            # Send SC2 vendor report (Report ID 0x45)
            rpt45 = build_sc2_report_45(rpt)
            uhid_input(uhid_fd, 0x45, rpt45)

            report_count += 1
            now = time.monotonic()
            if now - last_print >= 5.0:
                print(f"[uhid] Processed {report_count} reports")
                last_print = now

    except KeyboardInterrupt:
        print(f"\n[uhid] Stopped. Processed {report_count} reports.")
    finally:
        destroy_buf = struct.pack('<I', UHID_DESTROY)
        try:
            os.write(uhid_fd, destroy_buf)
        except OSError:
            pass
        os.close(uhid_fd)
        sock.close()


if __name__ == "__main__":
    main()
