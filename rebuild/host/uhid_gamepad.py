#!/usr/bin/env python3
"""Host-side UHID fake Steam Controller daemon.

Simulates a USB-connected Steam Controller via /dev/uhid.
Handles the hid-steam driver's initialization handshake (feature report 0x00)
and forwards controller input from the Deck over UDP.

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

# --- UHID constants (from linux/uhid.h enum) ---
UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

BUS_USB = 0x03

# Steam Controller VID/PID — must match hid-steam driver's USB ID table
# hid-steam.c: HID_USB_DEVICE(0x28DE, 0x1205) = Steam Deck
SC_VID = 0x28DE
SC_PID = 0x1205

# hid-steam command IDs (from hid-steam.c:85-138)
ID_CLEAR_DIGITAL_MAPPINGS = 0x81
ID_SET_DEFAULT_DIGITAL_MAPPINGS = 0x85
ID_SET_SETTINGS_VALUES = 0x87
ID_LOAD_DEFAULT_SETTINGS = 0x8E
ID_TRIGGER_HAPTIC_PULSE = 0x8F
ID_GET_DEVICE_INFO = 0xA1
ID_GET_STRING_ATTRIBUTE = 0xAE
ID_TRIGGER_RUMBLE_CMD = 0xEB

# Input report ID — Deck uses 0x09, SC uses 0x01
INPUT_REPORT_ID = 0x09


# --- HID Report Descriptor ---
# Structure:
# 1. Vendor Feature report (NO Report ID → implicit ID 0) — hid-steam command channel
# 2. Gamepad Input report (Report ID 0x09 — Deck input format)
STEAM_CONTROLLER_RD = bytes([
    # Feature report — NO Report ID tag (implicit ID 0)
    # hid-steam looks for report_id_hash[0] — must be >= 64 bytes
    0x06, 0x00, 0xFF,  # Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        # Usage (0x01)
    0xA1, 0x01,        # Collection (Application)
    0x09, 0x20,        #   Usage (0x20)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0xB1, 0x02,        #   Feature (Data,Var,Abs)  -- 64-byte feature (ID 0x00 implicit)
    0xC0,              # End Collection

    # Gamepad Input (Report ID 0x09)
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x05,        # Usage (Gamepad)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x09,        #   Report ID (0x09)
    0x05, 0x09,        #   Usage Page (Button)
    0x19, 0x01,        #   Usage Minimum (1)
    0x29, 0x10,        #   Usage Maximum (16)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1)
    0x95, 0x10,        #   Report Count (16)
    0x81, 0x02,        #   Input (Data,Var,Abs)
    0x05, 0x01,        #   Usage Page (Generic Desktop)
    0x09, 0x30,        #   Usage (X)
    0x09, 0x31,        #   Usage (Y)
    0x09, 0x33,        #   Usage (Rx)
    0x09, 0x34,        #   Usage (Ry)
    0x16, 0x00, 0x80,  #   Logical Minimum (-32768)
    0x26, 0xFF, 0x7F,  #   Logical Maximum (32767)
    0x75, 0x10,        #   Report Size (16)
    0x95, 0x04,        #   Report Count (4)
    0x81, 0x02,        #   Input (Data,Var,Abs)
    0x09, 0x32,        #   Usage (Z)
    0x09, 0x35,        #   Usage (Rz)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x02,        #   Report Count (2)
    0x81, 0x02,        #   Input (Data,Var,Abs)
    0xC0,              # End Collection
])


def uhid_create(fd):
    """Create a virtual Steam Controller via UHID_CREATE2."""
    rd = STEAM_CONTROLLER_RD
    buf = bytearray(4372)

    struct.pack_into('<I', buf, 0, UHID_CREATE2)
    name = b"Steam Controller\x00"
    buf[4:4+len(name)] = name

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


def uhid_get_report_reply(fd, req_id, data):
    """Reply to a UHID_GET_REPORT request."""
    size = len(data)
    # uhid_event: type(u32) + { id(u32) + err(u16) + size(u16) + data }
    buf = struct.pack('<IIHH', UHID_GET_REPORT_REPLY, req_id, 0, size) + data
    os.write(fd, buf)


def uhid_set_report_reply(fd, req_id):
    """Reply to a UHID_SET_REPORT request (success)."""
    # uhid_event: type(u32) + { id(u32) + err(u16) }
    buf = struct.pack('<IIH', UHID_SET_REPORT_REPLY, req_id, 0)
    os.write(fd, buf)


def handle_command(data):
    """Handle a 64-byte command from hid-steam and return a 64-byte response.

    hid-steam sends commands via SET_REPORT with report_id=0x00.
    The first byte of the 64-byte payload is the command ID.
    """
    cmd_id = data[0] if data else 0
    response = bytearray(64)

    if cmd_id == ID_GET_STRING_ATTRIBUTE:
        # GET_SERIAL: [0xAE, 0x15, 0x01, ...] -> serial starting with 'F'
        sub = data[1] if len(data) > 1 else 0
        response[0] = cmd_id
        response[1] = 0x15  # length
        response[2] = 0x01  # success
        serial = b"F123456789ABCDEF0000"
        response[3:3+len(serial)] = serial

    elif cmd_id == ID_GET_DEVICE_INFO:
        # GET_DEVICE_INFO
        response[0] = cmd_id
        response[1] = 0x15  # length
        response[2] = 0x01  # success
        # Device type, capabilities, etc.
        response[3] = 0x01  # SC2 wired

    elif cmd_id == 0x83:
        # GET_ATTRIBUTES
        # 9 attributes: 1-byte tag + 4-byte LE value each
        response[0] = cmd_id
        response[1] = 0x01  # success
        offset = 2
        attrs = [
            (1, SC_PID),          # ATTRIB_PRODUCT_ID
            (2, 0x4169BFFF),      # ATTRIB_CAPABILITIES
            (4, 0x65E4F1AD),      # ATTRIB_FIRMWARE_BUILD_TIME
            (9, 46),              # ATTRIB_BOARD_REVISION
            (10, 0x65E4F1AD),     # ATTRIB_BOOTLOADER_BUILD_TIME
            (11, 4000),           # ATTRIB_CONNECTION_INTERVAL_IN_US
            (12, 0),              # ATTRIB_12
            (13, 0),              # ATTRIB_13
            (14, 0),              # ATTRIB_14
        ]
        for tag, val in attrs:
            response[offset] = tag
            struct.pack_into('<I', response, offset + 1, val)
            offset += 5

    elif cmd_id == ID_SET_DEFAULT_DIGITAL_MAPPINGS:
        # ENABLE_LIZARD_MODE — just ACK
        response[0] = cmd_id
        response[1] = 0x01  # success

    elif cmd_id == ID_CLEAR_DIGITAL_MAPPINGS:
        # DISABLE_LIZARD_MODE — just ACK
        response[0] = cmd_id
        response[1] = 0x01  # success

    elif cmd_id == ID_LOAD_DEFAULT_SETTINGS:
        # LOAD_DEFAULTS — just ACK
        response[0] = cmd_id
        response[1] = 0x01  # success

    elif cmd_id == ID_SET_SETTINGS_VALUES:
        # SET_SETTINGS — just ACK
        response[0] = cmd_id
        response[1] = 0x01  # success

    elif cmd_id == ID_TRIGGER_HAPTIC_PULSE:
        # HAPTIC PULSE — ACK (we'll handle haptics later)
        response[0] = cmd_id
        response[1] = 0x01  # success

    elif cmd_id == ID_TRIGGER_RUMBLE_CMD:
        # RUMBLE CMD — ACK
        response[0] = cmd_id
        response[1] = 0x01  # success

    else:
        # Unknown command — generic ACK
        response[0] = cmd_id
        response[1] = 0x01  # success
        print(f"[uhid] Unknown command: {cmd_id:#04x}")

    return bytes(response)


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

    # Pending response buffer for GET_REPORT after SET_REPORT
    pending_response = bytearray(64)

    report_count = 0
    last_print = time.monotonic()

    try:
        while True:
            rlist, _, _ = select.select([sock, uhid_fd], [], [], 1.0)

            for fd in rlist:
                if fd == sock:
                    # --- Input from Deck (UDP) ---
                    try:
                        data, addr = sock.recvfrom(512)
                    except BlockingIOError:
                        continue

                    if len(data) < 3 or data[0] != PACKET_INPUT:
                        continue

                    rpt = unpack_input_report(data)

                    # Build Deck input report (Report ID 0x09)
                    # UHID_INPUT2: type(u32) + { size(u16) + report_id(u8) + data }
                    hid_report = struct.pack('<BHhhhhBB',
                        INPUT_REPORT_ID,
                        rpt['buttons'] & 0xFFFF,
                        rpt['lx'], rpt['ly'],
                        rpt['rx'], rpt['ry'],
                        rpt['lt'], rpt['rt'],
                    )
                    uhid_input(uhid_fd, INPUT_REPORT_ID, hid_report[1:])

                    report_count += 1
                    now = time.monotonic()
                    if now - last_print >= 5.0:
                        print(f"[uhid] Processed {report_count} reports")
                        last_print = now

                elif fd == uhid_fd:
                    # --- UHID event from kernel ---
                    try:
                        raw = os.read(uhid_fd, 4376)
                    except BlockingIOError:
                        continue

                    if len(raw) < 4:
                        continue

                    evt_type = struct.unpack_from('<I', raw, 0)[0]

                    if evt_type == UHID_GET_REPORT:
                        # Kernel reads a feature report (hid-steam reading response)
                        req_id = struct.unpack_from('<I', raw, 4)[0]
                        rnum = raw[8]
                        rtype = raw[9]
                        uhid_get_report_reply(uhid_fd, req_id, pending_response)

                    elif evt_type == UHID_SET_REPORT:
                        # Kernel writes a feature report (hid-steam sending command)
                        req_id = struct.unpack_from('<I', raw, 4)[0]
                        rnum = raw[8]
                        rtype = raw[9]
                        size = struct.unpack_from('<H', raw, 10)[0]
                        cmd_data = raw[12:12+size]

                        if rtype == 3 and size >= 1:
                            # Feature report — command from hid-steam
                            pending_response = bytearray(handle_command(cmd_data))

                        # ACK the SET_REPORT
                        uhid_set_report_reply(uhid_fd, req_id)

                    elif evt_type == UHID_START:
                        print("[uhid] Device started by kernel")

                    elif evt_type == UHID_STOP:
                        print("[uhid] Device stopped by kernel")

                    elif evt_type == UHID_OPEN:
                        print("[uhid] Device opened")

                    elif evt_type == UHID_CLOSE:
                        print("[uhid] Device closed")

                    elif evt_type == UHID_OUTPUT:
                        # Output from kernel (haptic commands from Steam)
                        if len(raw) >= 12:
                            out_size = struct.unpack_from('<H', raw, 6)[0]
                            out_data = raw[8:8+out_size]
                            if out_size >= 2:
                                left_motor = min(255, out_data[1] if len(out_data) > 1 else 0)
                                right_motor = min(255, out_data[2] if len(out_data) > 2 else 0)
                                haptic_pkt = pack_haptic_report(left_motor, right_motor)
                                sock.sendto(haptic_pkt, deck_target)

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
