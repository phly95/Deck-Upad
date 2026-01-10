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
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def wait_for_network_restore(timeout=15):
    print("[Startup] Verifying Internet Connectivity...")
    start = time.time()
    while time.time() - start < timeout:
        if check_internet(): return True
        time.sleep(1)
    print("[Startup] Warning: Internet not detected.")
    return False

def perform_aggressive_cleanup(force=False):
    if not force and not os.path.exists(PID_FILE): return

    print("[Startup] Cleaning up previous session state...")
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f: old_pid = int(f.read().strip())
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

    run_cmd("nmcli device set wlan0 managed yes")
    run_cmd("nmcli device connect wlan0")

    # Only wait for net if we actually cleaned up (implies we might have broken it)
    wait_for_network_restore()

def write_pid_file():
    try:
        with open(PID_FILE, 'w') as f: f.write(str(os.getpid()))
    except: pass

def remove_pid_file():
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

def main():
    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    # Role is now optional because cleanup-only doesn't need it
    parser.add_argument("--role", choices=["host", "client"], required=False)
    parser.add_argument("--ssid", default="DeckUpad")
    parser.add_argument("--password", default="DeckUpad123")
    parser.add_argument("--channel", default=165, type=int)
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax")
    parser.add_argument("--country", default="US")
    parser.add_argument("--force-clean", action="store_true")
    # New Flag
    parser.add_argument("--cleanup-only", action="store_true", help="Run cleanup routine and exit")

    args = parser.parse_args()

    # If cleanup-only is requested, force is implied
    should_force = args.force_clean or args.cleanup_only
    perform_aggressive_cleanup(force=should_force)

    if args.cleanup_only:
        print("[Startup] Cleanup Complete. Exiting.")
        sys.exit(0)

    # If not cleaning up, Role is mandatory
    if not args.role:
        parser.error("the following arguments are required: --role")

    write_pid_file()

    service = None

    def signal_handler(sig, frame):
        print("\n[Main] Signal received. Shutting down...")
        if service: service.stop()
        remove_pid_file()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.role == "host":
            print("--- LAUNCHING HOST DAEMON ---")
            service = HostService()
            service.start(ssid=args.ssid, password=args.password,
                          channel=args.channel, wifi_mode=args.wifi_mode,
                          country=args.country)
        else:
            print("--- LAUNCHING CLIENT AGENT ---")
            service = ClientService()
            service.start(ssid=args.ssid, password=args.password, country=args.country)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Script crashed: {e}")
        if service:
            try: service.stop()
            except: pass
        perform_aggressive_cleanup(force=True)
        sys.exit(1)
    finally:
        remove_pid_file()

if __name__ == "__main__":
    main()
