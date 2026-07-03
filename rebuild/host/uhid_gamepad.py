#!/usr/bin/env python3
"""Host-side UHID gamepad daemon.

Receives controller input over UDP from the Deck and creates a virtual
Steam Controller via /dev/uhid. Also reads haptic output from the kernel
and sends it back to the Deck.

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
UHID_OUTPUT = 6
UHID_CREATE2 = 11
UHID_INPUT2 = 12

BUS_USB = 0x03

# HID report descriptor for a Steam Controller-like device.
# 16 buttons, 2 sticks (16-bit), 2 triggers (8-bit),
# 2 trackpads (16-bit X/Y + 16-bit force), IMU (6 × 16-bit).
STEAM_CONTROLLER_RD = bytes([
    0x05, 0x01,        # USAGE_PAGE (Generic Desktop)
    0x09, 0x05,        # USAGE (Game Pad)
    0xA1, 0x01,        # COLLECTION (Application)
    0x85, 0x01,        #   REPORT_ID (1)

    # --- Buttons (16 bits) ---
    0x05, 0x09,        #   USAGE_PAGE (Button)
    0x19, 0x01,        #   USAGE_MINIMUM (Button 1)
    0x29, 0x10,        #   USAGE_MAXIMUM (Button 16)
    0x15, 0x00,        #   LOGICAL_MINIMUM (0)
    0x25, 0x01,        #   LOGICAL_MAXIMUM (1)
    0x75, 0x01,        #   REPORT_SIZE (1)
    0x95, 0x10,        #   REPORT_COUNT (16)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Left Stick X/Y (16-bit signed each) ---
    0x05, 0x01,        #   USAGE_PAGE (Generic Desktop)
    0x09, 0x30,        #   USAGE (X)
    0x09, 0x31,        #   USAGE (Y)
    0x16, 0x00, 0x80,  #   LOGICAL_MINIMUM (-32768)
    0x26, 0xFF, 0x7F,  #   LOGICAL_MAXIMUM (32767)
    0x75, 0x10,        #   REPORT_SIZE (16)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Right Stick X/Y (16-bit signed each) ---
    0x09, 0x32,        #   USAGE (Z)
    0x09, 0x35,        #   USAGE (Rz)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Left/Right Triggers (8-bit unsigned each) ---
    0x09, 0x33,        #   USAGE (Rx)
    0x09, 0x34,        #   USAGE (Ry)
    0x15, 0x00,        #   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,  #   LOGICAL_MAXIMUM (255)
    0x75, 0x08,        #   REPORT_SIZE (8)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Left Trackpad X/Y (16-bit signed) ---
    0x09, 0x36,        #   USAGE (Slider)
    0x09, 0x37,        #   USAGE (Dial)
    0x16, 0x00, 0x80,  #   LOGICAL_MINIMUM (-32768)
    0x26, 0xFF, 0x7F,  #   LOGICAL_MAXIMUM (32767)
    0x75, 0x10,        #   REPORT_SIZE (16)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Right Trackpad X/Y (16-bit signed) ---
    0x09, 0x38,        #   USAGE (Wheel)
    0x09, 0x39,        #   USAGE (Hat Switch)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- Trackpad Force (16-bit unsigned each) ---
    0x09, 0x3A,        #   USAGE (Vx)
    0x09, 0x3B,        #   USAGE (Vy)
    0x15, 0x00,        #   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x7F,  #   LOGICAL_MAXIMUM (32767)
    0x75, 0x10,        #   REPORT_SIZE (16)
    0x95, 0x02,        #   REPORT_COUNT (2)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- IMU Accel X/Y/Z (16-bit signed) ---
    0x05, 0x01,        #   USAGE_PAGE (Generic Desktop)
    0x09, 0x40,        #   USAGE (Rx) — repurpose for accel
    0x09, 0x41,        #   USAGE (Ry)
    0x09, 0x42,        #   USAGE (Rz)
    0x16, 0x00, 0x80,  #   LOGICAL_MINIMUM (-32768)
    0x26, 0xFF, 0x7F,  #   LOGICAL_MAXIMUM (32767)
    0x75, 0x10,        #   REPORT_SIZE (16)
    0x95, 0x03,        #   REPORT_COUNT (3)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    # --- IMU Gyro X/Y/Z (16-bit signed) ---
    0x09, 0x43,        #   USAGE (Vx)
    0x09, 0x44,        #   USAGE (Vy)
    0x09, 0x45,        #   USAGE (Vz)
    0x81, 0x02,        #   INPUT (Data,Var,Abs)

    0xC0,              # END_COLLECTION
])


def uhid_create(fd):
    """Create a virtual Steam Controller device via UHID.

    UHID event struct layout (uhid.h):
      type:     u32  (4 bytes)
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
    Total: 4 + 4372 = 4376 bytes
    """
    rd = STEAM_CONTROLLER_RD
    buf = bytearray(4376)

    # Event type (UHID_CREATE2 = 11)
    struct.pack_into('<I', buf, 0, UHID_CREATE2)

    # name (128 bytes, null-terminated) at offset 4
    name = b"Steam Controller\x00"
    buf[4:4+len(name)] = name

    # phys at offset 4+128=132, uniq at offset 4+128+64=196 — leave as zeros
    # rd_size at offset 4 + 128 + 64 + 64 = 260
    struct.pack_into('<H', buf, 260, len(rd))
    # bus at offset 262
    struct.pack_into('<H', buf, 262, BUS_USB)
    # vendor at offset 264 (u32)
    struct.pack_into('<I', buf, 264, 0x28DE)
    # product at offset 268 (u32)
    struct.pack_into('<I', buf, 268, 0x1101)
    # version at offset 272 (u32)
    struct.pack_into('<I', buf, 276, 0x0100)
    # country at offset 276 (u32)
    struct.pack_into('<I', buf, 280, 0)
    # rd_data at offset 280 + 4 = 284
    buf[284:284+len(rd)] = rd

    os.write(fd, bytes(buf))
    print("[uhid] Created virtual Steam Controller")


def uhid_input(fd, report_data):
    """Send an input report to the kernel via UHID.

    UHID_INPUT2 struct:
      type: u32 (4 bytes)
      size: u16 (2 bytes)
      data: u8[4096]
    """
    size = len(report_data)
    # type(4) + size(2) + data
    buf = struct.pack('<IH', UHID_INPUT2, size) + report_data
    os.write(fd, buf)


def main():
    parser = argparse.ArgumentParser(description="Deck-Upad UHID gamepad daemon")
    parser.add_argument("--deck", default="192.168.50.2", help="Deck IP address")
    args = parser.parse_args()

    deck_ip = args.deck

    # Open UHID
    uhid_fd = os.open("/dev/uhid", os.O_RDWR)
    print("[uhid] Opened /dev/uhid")

    uhid_create(uhid_fd)

    # UDP socket for input from Deck
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", INPUT_PORT))
    sock.setblocking(False)
    print(f"[uhid] Listening for input on :{INPUT_PORT}")

    deck_target = (deck_ip, HAPTIC_PORT)

    report_count = 0
    last_report_time = time.monotonic()

    try:
        while True:
            rlist, _, _ = select.select([sock, uhid_fd], [], [], 1.0)

            for fd in rlist:
                if fd == sock:
                    # Input from Deck
                    try:
                        data, addr = sock.recvfrom(512)
                    except BlockingIOError:
                        continue

                    if len(data) < 3 or data[0] != PACKET_INPUT:
                        continue

                    rpt = unpack_input_report(data)

                    # Build HID report: report_id(1) + buttons(2) + lx(2) + ly(2) + rx(2) + ry(2) + lt(1) + rt(1) + lpad_x(2) + lpad_y(2) + rpad_x(2) + rpad_y(2) + lpad_force(2) + rpad_force(2) + accel(6) + gyro(6) = 37 bytes
                    hid_report = struct.pack('<BHhhhhBBhhhhHHhhhh',
                        1,                    # report_id
                        rpt['buttons'] & 0xFFFF,
                        rpt['lx'], rpt['ly'],
                        rpt['rx'], rpt['ry'],
                        rpt['lt'], rpt['rt'],
                        rpt['lpad_x'], rpt['lpad_y'],
                        rpt['rpad_x'], rpt['rpad_y'],
                        rpt['lpad_force'], rpt['rpad_force'],
                        rpt['accel_x'], rpt['accel_y'], rpt['accel_z'],
                        rpt['gyro_x'], rpt['gyro_y'], rpt['gyro_z'],
                    )

                    uhid_input(uhid_fd, hid_report)
                    report_count += 1

                    now = time.monotonic()
                    if now - last_report_time >= 5.0:
                        print(f"[uhid] Processed {report_count} reports")
                        last_report_time = now

                elif fd == uhid_fd:
                    # Output from kernel (haptics)
                    try:
                        data = os.read(uhid_fd, 512)
                    except BlockingIOError:
                        continue

                    if len(data) < 4:
                        continue

                    pkt_type = struct.unpack_from('<I', data, 0)[0]
                    if pkt_type == UHID_OUTPUT:
                        # Output report from kernel — contains haptic data
                        # uhid_event: type(4) + output_req { size(2) + data }
                        if len(data) >= 10:
                            out_size = struct.unpack_from('<H', data, 4)[0]
                            output_data = data[6:6+out_size]
                            if len(output_data) >= 3:
                                left_motor = output_data[1]
                                right_motor = output_data[2]
                                haptic_pkt = pack_haptic_report(left_motor, right_motor)
                                sock.sendto(haptic_pkt, deck_target)

    except KeyboardInterrupt:
        print(f"\n[uhid] Stopped. Processed {report_count} reports.")
    finally:
        # Destroy UHID device
        destroy_buf = struct.pack('<I', UHID_DESTROY)
        try:
            os.write(uhid_fd, destroy_buf)
        except OSError:
            pass
        os.close(uhid_fd)
        sock.close()


if __name__ == "__main__":
    main()
