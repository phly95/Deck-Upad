#!/usr/bin/env python3
"""Host-side virtual gamepad daemon (evdev/uinput).

Receives controller input over UDP from the Deck and creates a virtual
gamepad via uinput. Simple, proven, works.

Usage: sudo python3 gamepad.py [--deck DECK_IP]
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

try:
    import evdev
    from evdev import UInput, ecodes
except ImportError:
    print("[gamepad] evdev not installed: pip install evdev")
    sys.exit(1)


def create_virtual_gamepad():
    """Create a virtual gamepad via uinput."""
    # Capabilities: buttons + axes
    cap = {
        ecodes.EV_KEY: [
            ecodes.BTN_SOUTH,   # A
            ecodes.BTN_EAST,    # B
            ecodes.BTN_NORTH,   # X
            ecodes.BTN_WEST,    # Y
            ecodes.BTN_TL,      # L1
            ecodes.BTN_TR,      # R1
            ecodes.BTN_SELECT,  # Select/Back
            ecodes.BTN_START,   # Start
            ecodes.BTN_MODE,    # Steam
            ecodes.BTN_THUMBL,  # L3
            ecodes.BTN_THUMBR,  # R3
        ],
        ecodes.EV_ABS: [
            (ecodes.ABS_X,  evdev.AbsInfo(value=0, min=-32768, max=32767, fuzz=0, flat=0, resolution=0)),
            (ecodes.ABS_Y,  evdev.AbsInfo(value=0, min=-32768, max=32767, fuzz=0, flat=0, resolution=0)),
            (ecodes.ABS_Z,  evdev.AbsInfo(value=0, min=0, max=255, fuzz=0, flat=0, resolution=0)),       # L trigger
            (ecodes.ABS_RX, evdev.AbsInfo(value=0, min=-32768, max=32767, fuzz=0, flat=0, resolution=0)), # R stick X
            (ecodes.ABS_RY, evdev.AbsInfo(value=0, min=-32768, max=32767, fuzz=0, flat=0, resolution=0)), # R stick Y
            (ecodes.ABS_RZ, evdev.AbsInfo(value=0, min=0, max=255, fuzz=0, flat=0, resolution=0)),       # R trigger
            (ecodes.ABS_HAT0X, evdev.AbsInfo(value=0, min=-1, max=1, fuzz=0, flat=0, resolution=0)),     # D-pad X
            (ecodes.ABS_HAT0Y, evdev.AbsInfo(value=0, min=-1, max=1, fuzz=0, flat=0, resolution=0)),     # D-pad Y
        ],
    }

    device = UInput(cap, name="Deck-Upad Virtual Gamepad", vendor=0x28DE, product=0x1101)
    print(f"[gamepad] Created virtual gamepad: {device.name}")
    return device


def main():
    parser = argparse.ArgumentParser(description="Deck-Upad virtual gamepad")
    parser.add_argument("--deck", default="192.168.50.2", help="Deck IP address")
    args = parser.parse_args()

    deck_ip = args.deck

    # Create virtual gamepad
    gamepad = create_virtual_gamepad()

    # UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", INPUT_PORT))
    sock.setblocking(False)
    print(f"[gamepad] Listening for input on :{INPUT_PORT}")

    deck_target = (deck_ip, HAPTIC_PORT)

    # Button mapping: Neptune bit → evdev code
    btn_map = [
        (0x0001, ecodes.BTN_SOUTH),   # A
        (0x0002, ecodes.BTN_EAST),    # B
        (0x0004, ecodes.BTN_NORTH),   # X
        (0x0008, ecodes.BTN_WEST),    # Y
        (0x0010, ecodes.BTN_TL),      # L1
        (0x0020, ecodes.BTN_TR),      # R1
        (0x0040, ecodes.BTN_SELECT),  # Select
        (0x0080, ecodes.BTN_START),   # Start
        (0x0100, ecodes.BTN_MODE),    # Steam
        (0x0200, ecodes.BTN_THUMBL),  # L3
        (0x0400, ecodes.BTN_THUMBR),  # R3
    ]

    prev_buttons = 0
    report_count = 0
    last_print = time.monotonic()

    try:
        while True:
            rlist, _, _ = select.select([sock], [], [], 0.1)
            if not rlist:
                continue

            try:
                data, addr = sock.recvfrom(512)
            except BlockingIOError:
                continue

            if len(data) < 3 or data[0] != PACKET_INPUT:
                continue

            rpt = unpack_input_report(data)
            buttons = rpt['buttons']

            # Emit button events
            for mask, code in btn_map:
                pressed = bool(buttons & mask)
                prev_pressed = bool(prev_buttons & mask)
                if pressed != prev_pressed:
                    gamepad.write(ecodes.EV_KEY, code, int(pressed))

            prev_buttons = buttons

            # Emit axis events
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_X, rpt['lx'])
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_Y, rpt['ly'])
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_RX, rpt['rx'])
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_RY, rpt['ry'])
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_Z, rpt['lt'])
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_RZ, rpt['rt'])

            # D-pad
            dpad_x = 0
            dpad_y = 0
            if buttons & 0x2000: dpad_x = -1  # Left
            if buttons & 0x4000: dpad_x = 1   # Right
            if buttons & 0x0800: dpad_y = -1  # Up
            if buttons & 0x1000: dpad_y = 1   # Down
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_HAT0X, dpad_x)
            gamepad.write(ecodes.EV_ABS, ecodes.ABS_HAT0Y, dpad_y)

            # SYN_REPORT
            gamepad.write(ecodes.EV_SYN, ecodes.SYN_REPORT, 0)

            report_count += 1
            now = time.monotonic()
            if now - last_print >= 5.0:
                print(f"[gamepad] Processed {report_count} reports")
                last_print = now

    except KeyboardInterrupt:
        print(f"\n[gamepad] Stopped. Processed {report_count} reports.")
    finally:
        gamepad.close()
        sock.close()


if __name__ == "__main__":
    main()
