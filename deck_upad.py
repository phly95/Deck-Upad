#!/usr/bin/env python3
import argparse
import sys
import signal
import os
import subprocess
import time
import shutil

from services.host_daemon import HostService
from services.client_agent import ClientService

# Path to store the PID of the active instance
PID_FILE = "/tmp/deck_upad.pid"

def run_cmd(cmd):
    """Helper to run shell commands silently"""
    subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def perform_aggressive_cleanup():
    """
    Forcefully cleans up ALL lingering state from previous runs.
    This ensures a clean slate for networking and containers.
    """
    print("[Startup] Scrubbing previous session state...")

    # 1. Kill the specific stale PID if it exists
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())

            # Don't kill ourselves
            if old_pid != os.getpid():
                try:
                    os.kill(old_pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
        except: pass

        try: os.remove(PID_FILE)
        except: pass

    # 2. Stop and Remove ALL Deck-Upad Containers
    # We stop them all at once to free up hardware (WiFi card, USB)
    containers = "wifi-bridge usbip-sidecar stream-receiver"
    run_cmd(f"podman stop -t 0 {containers}")
    run_cmd(f"podman rm -f {containers}")

    # 3. Clean up Network Interfaces and Connections
    # This frees the IP 192.168.50.2 and removes the bridge
    run_cmd("nmcli connection down veth-host-conn")
    run_cmd("nmcli connection delete veth-host-conn")
    run_cmd("ip link delete veth-host")

    # 4. Reset Firewall Rules (Broad sweep)
    if shutil.which("firewall-cmd"):
        ports = "2000:65535" # The range used in wifi_manager
        run_cmd(f"firewall-cmd --remove-port={ports}/udp")
        run_cmd(f"firewall-cmd --remove-port={ports}/tcp")
        run_cmd(f"firewall-cmd --zone=trusted --remove-port={ports}/udp")
        run_cmd(f"firewall-cmd --zone=trusted --remove-port={ports}/tcp")

    # 5. Restore WiFi Interface to Host
    # If the container crashed while holding the card, we nudge NetworkManager to take it back
    run_cmd("nmcli device set wlan0 managed yes")
    run_cmd("nmcli device connect wlan0")

    # 6. Wait for Kernel to cleanup network namespaces
    time.sleep(1)

def write_pid_file():
    """Writes the current PID to the lock file."""
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except IOError:
        pass

def remove_pid_file():
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

def main():
    # 1. Clean the slate (Fixes "Network in wrong state" issues)
    perform_aggressive_cleanup()

    # 2. Mark this run
    write_pid_file()

    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    parser.add_argument("--role", choices=["host", "client"], required=True, help="Run as Host (PC) or Client (Deck)")
    parser.add_argument("--ssid", default="DeckUpad", help="SSID for P2P connection")
    parser.add_argument("--password", default="DeckUpad123", help="Password for P2P connection")
    parser.add_argument("--channel", default=165, type=int, help="WiFi Channel (Default: 165)")
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax",
                        help="WiFi Standard: n (Legacy), ac (WiFi 5), ax (WiFi 6/Default)")

    args = parser.parse_args()

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
