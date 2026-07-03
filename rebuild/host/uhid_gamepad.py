#!/usr/bin/env python3
"""Host-side UHID gamepad daemon.

Receives controller input over UDP from the Deck and creates a virtual
Xbox 360 controller via /dev/uhid. Steam/SDL recognize this natively.

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

# Xbox 360 controller HID report descriptor.
# Steam, SDL, and KDE all recognize this natively.
# Layout: ReportID(1) + Buttons(16-bit) + LX(16) + LY(16) + RX(16) + RY(16) + LT(8) + RT(8)
XBOX360_RD = bytes([
    0x05, 0x01,        # USAGE_PAGE (Generic Desktop)
    0x09, 0x05,        # USAGE (Game Pad)
    0xA1, 0x01,        # COLLECTION (Application)
    0x85, 0x01,        #   REPORT_ID (1)

    # 16 buttons
    0x05, 0x09,        #   USAGE_PAGE (Button)
    0x19, 0x01,        #   USAGE_MINIMUM (Button 1)
    0x29, 0x10,        #   USAGE_MAXIMUM (Button 16)
    0x15, 0x00,        #   LOGICAL_MINIMUM (0)
    0x25, 0x01,        #   LOGICAL_MAXIMUM (1)
    0x75, 0x01,        #   REPORT_SIZE (1)
    0x95, 0x10,        #   REPORT_COUNT (16)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # Left stick X/Y (16-bit signed)
    0x05, 0x01,        #   USAGE_PAGE (Generic Desktop)
    0x09, 0x30,        #   USAGE (X)
    0x09, 0x31,        #   USAGE (Y)
    0x16, 0x00, 0x80,  #   LOGICAL_MINIMUM (-32768)
    0x26, 0xFF, 0x7F,  #   LOGICAL_MAXIMUM (32767)
    0x75, 0x10,        #   REPORT_SIZE (16)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # Right stick X/Y (16-bit signed)
    0x09, 0x32,        #   USAGE (Z)
    0x09, 0x35,        #   USAGE (Rz)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # Left/Right trigger (8-bit unsigned)
    0x09, 0x33,        #   USAGE (Rx)
    0x09, 0x34,        #   USAGE (Ry)
    0x15, 0x00,        #   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,  #   LOGICAL_MAXIMUM (255)
    0x75, 0x08,        #   REPORT_SIZE (8)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    0xC0,              # END_COLLECTION
])

# uinput capabilities matching the HID descriptor
try:
    import evdev
    from evdev import UInput, ecodes
except ImportError:
    ecodes = None


def uhid_create(fd):
    """Create a virtual Xbox 360 controller via UHID.

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
    rd = XBOX360_RD
    buf = bytearray(4372)

    struct.pack_into('<I', buf, 0, UHID_CREATE2)

    name = b"Xbox 360 Controller\x00"
    buf[4:4+len(name)] = name

    # offsets: name(128) phys(64) uniq(64) = 260
    struct.pack_into('<H', buf, 260, len(rd))     # rd_size
    struct.pack_into('<H', buf, 262, BUS_USB)     # bus
    struct.pack_into('<I', buf, 264, 0x045E)      # vendor: Microsoft
    struct.pack_into('<I', buf, 268, 0x028E)      # product: Xbox 360 Controller
    struct.pack_into('<I', buf, 272, 0x0100)      # version
    struct.pack_into('<I', buf, 276, 0)           # country
    buf[280:280+len(rd)] = rd

    os.write(fd, bytes(buf))
    print("[uhid] Created virtual Xbox 360 Controller")


def uhid_input(fd, report_data):
    """Send an input report to the kernel via UHID_INPUT2."""
    size = len(report_data)
    buf = struct.pack('<IH', UHID_INPUT2, size) + report_data
    os.write(fd, buf)


def main():
    parser = argparse.ArgumentParser(description="Deck-Upad UHID gamepad")
    parser.add_argument("--deck", default="192.168.50.2", help="Deck IP address")
    args = parser.parse_args()

    deck_ip = args.deck

    uhid_fd = os.open("/dev/uhid", os.O_RDWR)
    print("[uhid] Opened /dev/uhid")

    uhid_create(uhid_fd)

    # UDP socket
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

            # Build HID report matching the descriptor:
            # report_id(1) + buttons(2) + lx(2) + ly(2) + rx(2) + ry(2) + lt(1) + rt(1) = 13 bytes
            hid_report = struct.pack('<BHhhhhBB',
                1,                    # report_id
                rpt['buttons'] & 0xFFFF,
                rpt['lx'], rpt['ly'],
                rpt['rx'], rpt['ry'],
                rpt['lt'], rpt['rt'],
            )

            uhid_input(uhid_fd, hid_report)
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
