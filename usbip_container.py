#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import re
import argparse
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
CUSTOM_IMAGE = "usbip-ready-v7" # Version 7: Background Daemon
SCAN_SUBNET_PREFIX = "192.168.50."
USBIP_PORT = 3240
SCAN_INTERVAL = 5 # Seconds between scan cycles

# Steam Deck Controller Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

class ContainerUSBIP:
    def __init__(self):
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/bash -c"
        self.running = False # Flag for background thread

    def run_command(self, cmd, shell=False, check=True, input=None, timeout=None):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, input=input, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return None
        except subprocess.CalledProcessError as e:
            if check:
                if "usbip list" not in str(cmd):
                    pass # Suppress noise
                raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def is_container_running(self):
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def stop_container(self):
            print("\nStopping containers...")
            self.running = False # Stop daemon thread
            self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

            # Receiver Cleanup
            try:
                print("      Detaching imported USBIP devices...")
                self.run_command(f"{self.exec_cmd} 'usbip detach -p 00'", check=False)
            except: pass

            # Sender Cleanup
            try:
                print("      Unbinding Valve devices...")
                out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
                if out:
                    matches = re.findall(r"busid\s+([\d\.-]+)\s+\(" + VALVE_VID + r":" + VALVE_PID + r"\)", out)
                    if matches:
                        for bus_id in matches:
                            print(f"      Releasing Bus {bus_id}...")
                            self.run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
                            self.run_command(f"{self.exec_cmd} 'udevadm trigger'", check=False)
            except: pass

            self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
            self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
            self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            print("Cleaned up.")

    def ensure_image_exists(self):
        print("[1/5] Checking for USBIP tools image...")
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)
        if has_image:
            print("      Image found. Skipping build.")
            return

        print("      Image not found. Building...")
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils --exclude=kernel-debug*"

        try:
            self.run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'")
            print(f"      Saving to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")
            self.run_command(f"podman rm -f {BUILDER_NAME}")
        except Exception as e:
            print("\n[ERROR] Build failed. Check internet.")
            self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            sys.exit(1)

    def start_runtime_container(self):
        if self.is_container_running(): return

        print("[3/5] Starting Runtime Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- DAEMON LOGIC ---
    def check_ip(self, ip):
        """Checks if a single IP has port 3240 open (Low Impact)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2) # Very short timeout
        try:
            result = sock.connect_ex((ip, USBIP_PORT))
            sock.close()
            if result == 0: return ip
        except: pass
        return None

    def receiver_daemon(self):
        """Background thread that handles scanning and attaching."""
        print(f"      [Daemon] Background Scanner Started (Interval: {SCAN_INTERVAL}s)")
        print(f"      [Daemon] Target Subnet: {SCAN_SUBNET_PREFIX}x")

        # Load kernel module once
        self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

        # Generate IP list once
        ips_to_scan = [f"{SCAN_SUBNET_PREFIX}{i}" for i in range(1, 255)]
        known_targets = set() # Track devices we've already attached to

        while self.running:
            try:
                # 1. SCAN PHASE (Threaded for speed, but limited workers for gentleness)
                # Using 10 workers ensures we don't spike the network stack
                found_hosts = []
                with ThreadPoolExecutor(max_workers=10) as executor:
                    results = executor.map(self.check_ip, ips_to_scan)
                for ip in results:
                    if ip: found_hosts.append(ip)

                # 2. DISCOVERY PHASE
                for host in found_hosts:
                    # Skip if we think we are already connected (Keepalive phase checks validity)
                    # Actually, check anyway in case user rebooted Deck

                    try:
                        # Query the host with a 2s timeout
                        raw_out = self.run_command(f"{self.exec_cmd} 'usbip list -r {host}'", check=False, timeout=3)

                        if raw_out and "28de:1205" in raw_out:
                            match = re.search(r"([\d\.-]+):.*28de:1205", raw_out)
                            if match:
                                bus = match.group(1)
                                target_id = f"{host}:{bus}"

                                # Check if already attached locally
                                port_info = self.run_command(f"{self.exec_cmd} 'usbip port'", check=False)

                                # If not currently attached, Attach it
                                if host not in str(port_info):
                                    print(f"\n      [Auto-Connect] Found Valve Device at {host} Bus {bus}")
                                    print("      [Safety Delay] Waiting 2s...")
                                    time.sleep(2)
                                    self.run_command(f"{self.exec_cmd} 'usbip attach -r {host} -b {bus}'", check=False)
                                    known_targets.add(target_id)
                    except: pass

                # 3. KEEPALIVE PHASE
                # Check all known targets. If dropped, they will be caught by Discovery phase next loop.
                # Just sleep now.

            except Exception as e:
                print(f"      [Daemon Error] {e}")

            # 4. SLEEP PHASE
            time.sleep(SCAN_INTERVAL)

    def find_deck_controller_on_host(self):
        base_path = "/sys/bus/usb/devices"
        candidates = []
        if not os.path.exists(base_path): return []
        for device_id in os.listdir(base_path):
            if ":" in device_id or device_id.startswith("usb"): continue
            try:
                with open(os.path.join(base_path, device_id, "idVendor"), 'r') as f: vid = f.read().strip()
                with open(os.path.join(base_path, device_id, "idProduct"), 'r') as f: pid = f.read().strip()
                if vid == VALVE_VID and pid == VALVE_PID: candidates.append(device_id)
            except: continue
        return candidates

    def get_active_mode(self):
        ps_out = self.run_command(f"{self.exec_cmd} 'ps aux'", check=False)
        if "usbipd" in ps_out: return "sender"
        # We don't check for keepalive script anymore, just container existence
        return None

    # --- SENDER LOGIC ---
    def setup_sender(self, resume=False, auto_bg=False):
        print("\n--- SENDER MODE (Steam Deck) ---")
        if resume:
            print(">> Resuming existing Sender session.")
        else:
            self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")
            self.run_command(f"{self.exec_cmd} 'usbipd -D'")

            candidates = self.find_deck_controller_on_host()
            target_bus = None
            if len(candidates) == 1:
                target_bus = candidates[0]
                print(f"      Auto-selected Steam Deck Controller: {target_bus}")
            elif len(candidates) > 1:
                print("\nMultiple Valve devices found:")
                for i, c in enumerate(candidates): print(f" {i+1}: {c}")
                target_bus = candidates[int(input("Select #: "))-1]
            else:
                print("No Steam Deck controller found via Host scan.")
                return

            print(f"      Binding {target_bus}...")
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'")

        print("\n" + "="*40)
        print(" SENDER ACTIVE")
        print(" 1. Press ENTER to Stop.")
        print(" 2. Type 'bg' to run in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        else: self.stop_container()

    # --- RECEIVER LOGIC ---
    def setup_receiver(self, resume=False, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")
        if resume:
            print(">> Resuming existing Receiver session.")

        # Start the background daemon
        self.running = True
        t = threading.Thread(target=self.receiver_daemon, daemon=True)
        t.start()

        # Wait a moment to let the first scan start
        time.sleep(1)

        print("\n" + "="*40)
        print(" RECEIVER RUNNING (Background Auto-Scan Active)")
        print(" * Scans 192.168.50.x every 5 seconds")
        print(" * Auto-attaches Valve Controllers")
        print("-" * 40)
        print(" 1. Press ENTER to Stop.")
        print(" 2. Type 'bg' to run in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        else: self.stop_container()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"])
    parser.add_argument("-i", "--ips") # Kept for compat, but ignored in auto-mode
    parser.add_argument("--bg", action="store_true")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    if tool.is_container_running():
        # Just assume receiver if running, or check process list
        print(f"\n[!] Container is running.")
        # If we want to be smart, we could check if usbipd is running inside to determine mode
        mode = tool.get_active_mode()
        if mode == 'sender': tool.setup_sender(resume=True, auto_bg=args.bg)
        else: tool.setup_receiver(resume=True, auto_bg=args.bg)
        return

    mode_selection = ""
    if args.mode: mode_selection = '1' if args.mode in ['sender', '1'] else '2'
    elif args.ips: mode_selection = '2'
    else:
        print("1. Sender (Steam Deck)")
        print("2. Receiver (Bazzite PC)")
        mode_selection = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()
        if mode_selection == '1': tool.setup_sender(auto_bg=args.bg)
        elif mode_selection == '2': tool.setup_receiver(auto_bg=args.bg)
    except KeyboardInterrupt: tool.stop_container()
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
