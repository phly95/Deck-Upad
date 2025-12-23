#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import re
import argparse

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
CUSTOM_IMAGE = "usbip-ready-v8" # Version 8: True Container-Side Daemon
INTERNAL_DAEMON_PATH = "/usr/local/bin/usbip_automator.py"

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
                    pass
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
            # Kill the internal python daemon
            self.run_command(f"{self.exec_cmd} 'pkill -f usbip_automator.py'", check=False)
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

        # Added python3 explicitly for the internal daemon
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils python3 --exclude=kernel-debug*"

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

    # --- THE INTERNAL DAEMON INJECTOR ---
    def install_daemon_script(self):
        """Writes the Python logic INTO the container so it runs independently."""

        # This is the Python script that will run INSIDE the container
        # It handles scanning, attaching, and monitoring entirely locally.
        daemon_code = r"""
import subprocess
import time
import socket
import re
import sys
from concurrent.futures import ThreadPoolExecutor

SCAN_SUBNET_PREFIX = "192.168.50."
USBIP_PORT = 3240
SCAN_INTERVAL = 5

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    except: return ""

def check_ip(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        if sock.connect_ex((ip, USBIP_PORT)) == 0:
            sock.close()
            return ip
    except: pass
    return None

def main_loop():
    print("[Daemon] Starting internal scanner...")
    run_cmd("modprobe vhci-hcd")
    ips = [f"{SCAN_SUBNET_PREFIX}{i}" for i in range(1, 255)]

    while True:
        # 1. SCAN
        found_hosts = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            for ip in ex.map(check_ip, ips):
                if ip: found_hosts.append(ip)

        # 2. DISCOVERY & ATTACH
        for host in found_hosts:
            try:
                # Check what devices this host has
                # We use a timeout command to prevent hanging
                out = run_cmd(f"timeout 3 usbip list -r {host}")

                if "28de:1205" in out:
                    match = re.search(r"([\d\.-]+):.*28de:1205", out)
                    if match:
                        bus = match.group(1)

                        # Check if already attached
                        ports = run_cmd("usbip port")
                        # If the remote IP isn't in the port list, attach it
                        if host not in ports:
                            print(f"[Daemon] Found Deck at {host}:{bus}. Attaching...")
                            time.sleep(1) # Safety delay
                            run_cmd(f"usbip attach -r {host} -b {bus}")
            except Exception as e:
                print(f"[Error] {e}")

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    # Flush output immediately so logs appear
    sys.stdout.reconfigure(line_buffering=True)
    main_loop()
"""
        # Write file to container
        self.run_command(f"{self.exec_cmd} 'cat > {INTERNAL_DAEMON_PATH}'", input=daemon_code)
        self.run_command(f"{self.exec_cmd} 'chmod +x {INTERNAL_DAEMON_PATH}'")

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
        if "usbip_automator.py" in ps_out: return "receiver"
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
        else:
            # Install the brain
            self.install_daemon_script()

            # Start the brain in background (nohup)
            print("      [Launcher] Starting internal Automator Daemon...")
            self.run_command(f"{self.exec_cmd} 'nohup python3 {INTERNAL_DAEMON_PATH} > /var/log/usbip_automator.log 2>&1 &'")
            time.sleep(1)

        print("\n" + "="*40)
        print(" RECEIVER ACTIVE (Container-Managed)")
        print(" * Daemon running inside container PID space")
        print(" * Scans 192.168.50.x every 5 seconds")
        print("-" * 40)
        print(" 1. Press ENTER to Stop.")
        print(" 2. Type 'bg' to detach (Daemon keeps running).")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        else: self.stop_container()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"])
    parser.add_argument("--bg", action="store_true")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    if tool.is_container_running():
        active_mode = tool.get_active_mode()
        print(f"\n[!] Container is running.")
        if active_mode == 'sender': tool.setup_sender(resume=True, auto_bg=args.bg)
        elif active_mode == 'receiver': tool.setup_receiver(resume=True, auto_bg=args.bg)
        else:
            # If unknown state, just assume receiver to allow attaching logs
            tool.setup_receiver(resume=True, auto_bg=args.bg)
        return

    mode_selection = ""
    if args.mode: mode_selection = '1' if args.mode in ['sender', '1'] else '2'
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
