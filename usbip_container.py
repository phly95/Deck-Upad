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
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
CUSTOM_IMAGE = "usbip-ready-v6" # Version 6: Auto-Delay Fix
KEEPALIVE_SCRIPT = "/usr/local/bin/usbip-keepalive.sh"

# Target Subnet to Scan
SCAN_SUBNET_PREFIX = "192.168.50."
USBIP_PORT = 3240

# Steam Deck Controller Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

class ContainerUSBIP:
    def __init__(self):
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/bash -c"

    def run_command(self, cmd, shell=False, check=True, input=None):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, input=input
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if check:
                if "usbip list" not in str(cmd):
                    print(f"Command failed: {cmd}")
                    print(f"Stderr: {e.stderr}")
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
            self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)
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

    # --- SCANNER ---
    def check_ip(self, ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            result = sock.connect_ex((ip, USBIP_PORT))
            sock.close()
            if result == 0: return ip
        except: pass
        return None

    def scan_subnet(self):
        print(f"      [Scanner] Sweeping {SCAN_SUBNET_PREFIX}x for Steam Decks...")
        found_hosts = []
        ips_to_scan = [f"{SCAN_SUBNET_PREFIX}{i}" for i in range(1, 255)]
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(self.check_ip, ips_to_scan)
        for ip in results:
            if ip: found_hosts.append(ip)
        return found_hosts

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
        if "usbip-keepalive.sh" in ps_out: return "receiver"
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
    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")
        if resume:
            print(">> Resuming existing Receiver session.")
        else:
            ips = []
            targets = []

            if cli_ips:
                ips = cli_ips
                print(f"Using provided IPs: {ips}")
            else:
                while True:
                    found_hosts = self.scan_subnet()

                    if found_hosts:
                        print(f"      [Scanner] Found Hosts: {found_hosts}")
                        for host in found_hosts:
                            print(f"      Querying {host}...")
                            try:
                                raw_out = self.run_command(f"{self.exec_cmd} 'usbip list -r {host}'")

                                # Auto-detect Valve ID
                                if raw_out and "28de:1205" in raw_out:
                                    match = re.search(r"([\d\.-]+):.*28de:1205", raw_out)
                                    if match:
                                        found_bus = match.group(1)
                                        print(f"      -> Auto-detected Valve Controller at {host} Bus {found_bus}")
                                        targets.append(f"{host}:{found_bus}")
                            except: pass

                        if targets: break
                        print("      [Scanner] Hosts found, but no Valve Controllers exported.")
                    else:
                        print("      [Scanner] No USBIP hosts found on 192.168.50.x")

                    ip_input = input("      Enter IP manually (or ENTER to rescan): ").strip()
                    if ip_input:
                        ips = [x.strip() for x in ip_input.split(',')]
                        break

            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

            if ips and not targets:
                 for sender_ip in ips:
                    try:
                        raw_out = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
                        if "28de:1205" in raw_out:
                             match = re.search(r"([\d\.-]+):.*28de:1205", raw_out)
                             if match: targets.append(f"{sender_ip}:{match.group(1)}")
                    except: pass

            if not targets:
                print("No targets configured. Exiting.")
                return

            # --- THE FIX: SAFETY DELAY ---
            print(f"      [Safety Delay] Waiting 2 seconds for sockets to clear...")
            time.sleep(2)

            # Initial Attach Test
            for t in targets:
                ip, bus = t.split(':')
                print(f"      [TEST] Attaching to {ip} bus {bus}...")
                self.run_command(f"{self.exec_cmd} 'usbip attach -r {ip} -b {bus}'", check=False)

            # Verify Success
            port_check = self.run_command(f"{self.exec_cmd} 'usbip port'")
            if "28de:1205" in str(port_check):
                print("      [SUCCESS] Controller is attached and active!")
            else:
                print("      [WARNING] Attach command finished, but device not seen in port list yet.")

            target_str = " ".join(targets)
            keepalive_code = f"""#!/bin/bash
            TARGETS="{target_str}"
            while true; do
                for PAIR in $TARGETS; do
                    IP=${{PAIR%%:*}}
                    BUS=${{PAIR##*:}}
                    if ! usbip port | grep -q "$IP"; then
                        echo "Re-attaching $IP $BUS..."
                        usbip attach -r $IP -b $BUS
                    fi
                done
                sleep 5
            done
            """
            self.run_command(f"{self.exec_cmd} 'cat > {KEEPALIVE_SCRIPT}'", input=keepalive_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {KEEPALIVE_SCRIPT}'")
            self.run_command(f"{self.exec_cmd} 'nohup {KEEPALIVE_SCRIPT} > /dev/null 2>&1 &'")

        print("\n" + "="*40)
        print(" RECEIVER ACTIVE")
        print(" Type 'bg' to run in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        else: self.stop_container()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"])
    parser.add_argument("-i", "--ips")
    parser.add_argument("--bg", action="store_true")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    if tool.is_container_running():
        active_mode = tool.get_active_mode()
        if active_mode:
            print(f"\n[!] Existing {active_mode.upper()} session detected.")
            if active_mode == 'sender': tool.setup_sender(resume=True, auto_bg=args.bg)
            elif active_mode == 'receiver': tool.setup_receiver(resume=True, auto_bg=args.bg)
            return
        else: tool.stop_container()

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
        elif mode_selection == '2': tool.setup_receiver(cli_ips=[x.strip() for x in args.ips.split(',')] if args.ips else None, auto_bg=args.bg)
    except KeyboardInterrupt: tool.stop_container()
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
