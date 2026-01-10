#!/usr/bin/env python3
import argparse
import sys
import signal
import os
import subprocess
import time
import shutil
import socket

from services.host_daemon import HostService
from services.client_agent import ClientService

PID_FILE = "/tmp/deck_upad.pid"

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def check_internet():
    """Returns True if we can reach Google DNS."""
    try:
        # Connect to 8.8.8.8 on port 53 (DNS) - fast and reliable
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def wait_for_network_restore(timeout=15):
    """Blocks until internet is restored or timeout expires."""
    print("[Startup] Verifying Internet Connectivity...")
    start = time.time()
    while time.time() - start < timeout:
        if check_internet():
            return True
        time.sleep(1)
    print("[Startup] Warning: Internet not detected. Image builds may fail.")
    return False

def perform_aggressive_cleanup(force=False):
    """
    Cleans up state.
    If 'force' is False, we only cleanup if a stale PID file exists (crash detected).
    """
    # If no PID file and not forced, assume clean exit and skip to save time/net
    if not force and not os.path.exists(PID_FILE):
        return

    print("[Startup] Cleaning up previous session state...")

    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            if old_pid != os.getpid():
                try: os.kill(old_pid, signal.SIGKILL)
                except: pass
        except: pass
        try: os.remove(PID_FILE)
        except: pass

    containers = "wifi-bridge usbip-sidecar stream-receiver"
    run_cmd(f"podman stop -t 0 {containers}")
    run_cmd(f"podman rm -f {containers}")

    run_cmd("nmcli connection down veth-host-conn")
    run_cmd("nmcli connection delete veth-host-conn")
    run_cmd("ip link delete veth-host")

    if shutil.which("firewall-cmd"):
        ports = "2000:65535"
        run_cmd(f"firewall-cmd --remove-port={ports}/udp")
        run_cmd(f"firewall-cmd --remove-port={ports}/tcp")

    # Restore WiFi
    run_cmd("nmcli device set wlan0 managed yes")
    run_cmd("nmcli device connect wlan0")

    # Wait for the OS to grab an IP
    wait_for_network_restore()

def write_pid_file():
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except: pass

def remove_pid_file():
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

def main():
    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    parser.add_argument("--role", choices=["host", "client"], required=True)
    parser.add_argument("--ssid", default="DeckUpad")
    parser.add_argument("--password", default="DeckUpad123")
    parser.add_argument("--channel", default=165, type=int)
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax")
    parser.add_argument("--force-clean", action="store_true", help="Force cleanup even if no crash detected")

    args = parser.parse_args()

    # 1. Intelligent Cleanup
    perform_aggressive_cleanup(force=args.force_clean)

    # 2. Mark run
    write_pid_file()

    service = None

    def signal_handler(sig, frame):
        print("\n[Main] Signal received. Shutting down...")
        if service:
            service.stop()
        remove_pid_file()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.role == "host":
            print("--- LAUNCHING HOST DAEMON ---")
            service = HostService()
            service.start(ssid=args.ssid, password=args.password, channel=args.channel, wifi_mode=args.wifi_mode)
        else:
            print("--- LAUNCHING CLIENT AGENT ---")
            service = ClientService()
            service.start(ssid=args.ssid, password=args.password)
    finally:
        remove_pid_file()

if __name__ == "__main__":
    main()
