#!/usr/bin/env python3
"""Deck-side input sender.

Reads the Neptune controller and sends input reports over UDP to the host.
Also receives haptic feedback from the host and forwards it to the Neptune.

Usage: sudo python3 sender.py [--host HOST_IP]
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
    pack_input_report,
)
from deck.neptune import (
    find_neptune_hidraw, send_lizard_off, parse_neptune_report,
)


def main():
    parser = argparse.ArgumentParser(description="Deck-Upad input sender")
    parser.add_argument("--host", default="192.168.50.1", help="Host IP address")
    args = parser.parse_args()

    host_ip = args.host
    print(f"[sender] Host: {host_ip}")

    # Find Neptune controller
    neptune_path = find_neptune_hidraw()
    if not neptune_path:
        print("[sender] Neptune controller not found")
        sys.exit(1)

    neptune_fd = os.open(neptune_path, os.O_RDWR | os.O_NONBLOCK)
    print(f"[sender] Neptune: {neptune_path}")

    # Disable lizard mode
    send_lizard_off(neptune_fd)
    last_lizard_off = time.monotonic()

    # UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", HAPTIC_PORT))
    sock.setblocking(False)

    target = (host_ip, INPUT_PORT)
    print(f"[sender] Sending to {target}, listening for haptics on :{HAPTIC_PORT}")
    print("[sender] Reading controller input...")

    report_count = 0
    try:
        while True:
            # Periodically re-send lizard off
            now = time.monotonic()
            if now - last_lizard_off >= 2.0:
                send_lizard_off(neptune_fd)
                last_lizard_off = now

            # Read from Neptune (non-blocking)
            rlist, _, _ = select.select([neptune_fd, sock], [], [], 0.1)

            for fd in rlist:
                if fd == neptune_fd:
                    try:
                        raw = os.read(neptune_fd, 64)
                    except BlockingIOError:
                        continue
                    if len(raw) != 64:
                        continue

                    rpt = parse_neptune_report(raw)
                    if rpt is None:
                        continue

                    # Pack and send
                    pkt = pack_input_report(
                        rpt.buttons,
                        rpt.lx, rpt.ly, rpt.rx, rpt.ry,
                        rpt.left_trigger, rpt.right_trigger,
                        rpt.lpad_x, rpt.lpad_y, rpt.rpad_x, rpt.rpad_y,
                        rpt.lpad_force, rpt.rpad_force,
                        rpt.accel_x, rpt.accel_y, rpt.accel_z,
                        rpt.gyro_x, rpt.gyro_y, rpt.gyro_z,
                    )
                    sock.sendto(pkt, target)
                    report_count += 1

                    if report_count % 300 == 0:
                        print(f"[sender] Sent {report_count} reports")

                elif fd == sock:
                    try:
                        data, addr = sock.recvfrom(64)
                    except BlockingIOError:
                        continue
                    if len(data) >= 3 and data[0] == PACKET_HAPTIC:
                        left_motor = data[1]
                        right_motor = data[2]
                        # Forward haptic to Neptune
                        # Neptune haptic report: 0xeb 0x09 + motor data
                        haptic_pkt = struct.pack('<BBBB',
                            0xeb, 0x09, left_motor, right_motor)
                        try:
                            os.write(neptune_fd, haptic_pkt)
                        except OSError:
                            pass

    except KeyboardInterrupt:
        print(f"\n[sender] Stopped. Sent {report_count} reports.")
    finally:
        os.close(neptune_fd)
        sock.close()


if __name__ == "__main__":
    main()
