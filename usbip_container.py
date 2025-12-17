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
CUSTOM_IMAGE = "usbip-ready"
KEEPALIVE_SCRIPT = "/usr/local/bin/usbip-keepalive.sh"

# UDP Heartbeat Configuration
HEARTBEAT_PORT = 3241
HEARTBEAT_TIMEOUT = 4  # Seconds before Deck reclaims controller

# Steam Deck Controller Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

# --- EMBEDDED PYTHON SCRIPTS (Running Inside Container) ---

# 1. Receiver Heartbeat (PC Side)
# Starts IMMEDIATELY to tell Sender "I am here" before attaching.
RECEIVER_HEARTBEAT_CODE = f"""
import socket
import time
import sys

# Parse IPs
try:
    target_ips = [x.strip() for x in sys.argv[1].split(',')]
except:
    sys.exit(0)

port = {HEARTBEAT_PORT}

print(f"[Heartbeat] Pulse started to {{target_ips}}...")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    for ip in target_ips:
        try:
            sock.sendto(b'HEARTBEAT', (ip, port))
        except:
            pass
    time.sleep(1)
"""

# 2. Sender Watchdog (Steam Deck Side)
# Logic:
#   - We assume device is ALREADY bound when this starts.
#   - We wait for the first Heartbeat.
#   - Once Heartbeats start flowling, we enter "Armed" mode.
#   - If Heartbeats stop while "Armed", we UNBIND immediately.
SENDER_WATCHDOG_CODE = f"""
import socket
import time
import subprocess
import sys

HOST = "0.0.0.0"
PORT = {HEARTBEAT_PORT}
TIMEOUT = {HEARTBEAT_TIMEOUT}
BUS_ID = sys.argv[1]

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

print(f"[Watchdog] Monitoring UDP {{PORT}} for Bus {{BUS_ID}}...")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
sock.setblocking(False)

last_heartbeat = time.time()
session_active = False # False = Waiting for client; True = Client connected

while True:
    try:
        data, addr = sock.recvfrom(1024)
        if data == b'HEARTBEAT':
            now = time.time()

            if not session_active:
                print(f"[Watchdog] Connection Established from {{addr[0]}}!")
                session_active = True

            last_heartbeat = now

    except BlockingIOError:
        pass
    except Exception as e:
        print(f"[Watchdog] Error: {{e}}")

    # DEAD MAN'S SWITCH LOGIC
    if session_active:
        # If we haven't heard from the client in TIMEOUT seconds...
        if time.time() - last_heartbeat > TIMEOUT:
            print("[Watchdog] LOST SIGNAL! Client disconnected.")
            print("[Watchdog] RELEASING CONTROL TO STEAM DECK...")

            # 1. Kill the USBIP Daemon (stops network sharing)
            run_cmd("pkill usbipd")

            # 2. Unbind the driver (This gives it back to the Kernel)
            # We try multiple times to be sure
            run_cmd(f"usbip unbind -b {{BUS_ID}}")
            time.sleep(0.5)
            run_cmd(f"usbip unbind -b {{BUS_ID}}")

            # 3. Trigger Udev (Forces SteamOS to see the 'new' device)
            run_cmd("udevadm trigger")

            print("[Watchdog] Device released. Exiting.")
            sys.exit(0) # We exit; user must restart script to share again.

    time.sleep(0.5)
"""


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
        # Kill python scripts first (watchdogs)
        self.run_command(f"{self.exec_cmd} 'pkill -f python3'", check=False)
        self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)
        self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

        # Force Unbind on Stop
        try:
            print("      Ensuring devices are returned to host...")
            out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
            if out:
                bound_devices = re.findall(r"busid\s+([\d\.-]+)", out)
                for bus_id in bound_devices:
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

        # Install python3 for our scripts
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
        if self.is_container_running():
            print("[Info] Container is already running. Resuming session...")
            return

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

    def find_deck_controller_on_host(self):
        base_path = "/sys/bus/usb/devices"
        candidates = []
        if not os.path.exists(base_path): return []

        for device_id in os.listdir(base_path):
            if ":" in device_id or device_id.startswith("usb"): continue
            vid_path = os.path.join(base_path, device_id, "idVendor")
            pid_path = os.path.join(base_path, device_id, "idProduct")

            if os.path.exists(vid_path) and os.path.exists(pid_path):
                try:
                    with open(vid_path, 'r') as f: vid = f.read().strip()
                    with open(pid_path, 'r') as f: pid = f.read().strip()
                    if vid == VALVE_VID and pid == VALVE_PID:
                        candidates.append(device_id)
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

        target_bus = None
        if resume:
            print(">> Resuming existing Sender session.")
            out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
            if out:
                found = re.search(r"busid\s+([\d\.-]+)", out)
                if found: target_bus = found.group(1)
        else:
            print("      Loading 'usbip-host' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")
            print("      Starting usbip daemon...")
            self.run_command(f"{self.exec_cmd} 'usbipd -D'")

            candidates = self.find_deck_controller_on_host()
            if len(candidates) == 1:
                target_bus = candidates[0]
                print(f"      Auto-selected Steam Deck Controller: {target_bus}")
            elif len(candidates) > 1:
                for i, c in enumerate(candidates): print(f" {i+1}: {c}")
                sel = input("Select #: ")
                target_bus = candidates[int(sel)-1]
            else:
                print("No Steam Deck controller found via Host scan.")
                return

            # CRITICAL CHANGE: Bind IMMEDIATELY so it is ready for the Receiver
            print(f"      Binding {target_bus} to network (Waiting for connection)...")
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'", check=False)

        # INJECT AND START WATCHDOG
        if target_bus:
            print(f"      Starting UDP Heartbeat Watchdog on port {HEARTBEAT_PORT}...")
            wd_path = "/usr/local/bin/sender_watchdog.py"
            self.run_command(f"{self.exec_cmd} 'cat > {wd_path}'", input=SENDER_WATCHDOG_CODE)
            self.run_command(f"{self.exec_cmd} 'nohup python3 {wd_path} {target_bus} > /var/log/watchdog.log 2>&1 &'")

        print("\n" + "="*40)
        print(" SENDER IS RUNNING")
        print(" 1. Controller is now HIDDEN from Steam Deck.")
        print(" 2. Waiting for Receiver (PC) to start.")
        print(" 3. If Receiver connects and then disconnects, Deck regains control.")
        print("="*40)

        if auto_bg: sys.exit(0)
        user_in = input("Type 'bg' to background, or ENTER to stop: ").strip().lower()
        if user_in == 'bg': sys.exit(0)
        else: self.stop_container()

    # --- RECEIVER LOGIC ---
    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        if resume:
            print(">> Resuming Receiver.")
        else:
            if cli_ips:
                ips = cli_ips
            else:
                print("Enter Steam Deck IP addresses (comma separated).")
                ip_input = input("IPs: ").strip()
                ips = [x.strip() for x in ip_input.split(',')]

            print("      Loading 'vhci-hcd' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

            # 1. Start UDP Heartbeat FIRST (Critical Fix)
            # This ensures the Sender knows we are here immediately.
            print("      Starting Heartbeat Emitter (so Sender stays active)...")
            hb_path = "/usr/local/bin/receiver_heartbeat.py"
            ip_str = ",".join(ips)
            self.run_command(f"{self.exec_cmd} 'cat > {hb_path}'", input=RECEIVER_HEARTBEAT_CODE)
            self.run_command(f"{self.exec_cmd} 'nohup python3 {hb_path} {ip_str} > /dev/null 2>&1 &'")

            # Brief pause to let packets fly
            time.sleep(1)

            # 2. Proceed with USBIP Attach
            targets = []
            for sender_ip in ips:
                print(f"\n[Scanning {sender_ip}]...")
                try:
                    output = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
                    print(output)
                    found_bus = input(f"Enter Bus ID from {sender_ip} (ENTER to skip): ").strip()
                    if found_bus:
                        targets.append(f"{sender_ip}:{found_bus}")
                        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {found_bus}'", check=False)
                except:
                    print(f"      Could not connect to {sender_ip}. (Is Sender script running?)")

            if not targets: return

            # 3. Start Keepalive
            target_str = " ".join(targets)
            keepalive_code = f"""#!/bin/bash
            TARGETS="{target_str}"
            while true; do
                for PAIR in $TARGETS; do
                    IP=${{PAIR%%:*}}; BUS=${{PAIR##*:}}
                    if ! usbip port | grep -q "$IP" | grep -q "$BUS"; then
                        echo "Reconnecting $IP $BUS..."
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
        print(" RECEIVER IS RUNNING")
        print(" * Heartbeat is firing.")
        print(" * Keepalive is active.")
        print(" * To return control to Deck, simply stop this script (Ctrl+C).")
        print("="*40)

        if auto_bg: sys.exit(0)
        user_in = input("Type 'bg' to background, or ENTER to stop: ").strip().lower()
        if user_in == 'bg': sys.exit(0)
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
        else:
            tool.stop_container()

    mode = ""
    if args.mode: mode = '1' if args.mode in ['sender', '1'] else '2'
    elif args.ips: mode = '2'
    else:
        print("1. Sender (Steam Deck)\n2. Receiver (PC)")
        mode = input("Select Mode: ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()
        if mode == '1': tool.setup_sender(auto_bg=args.bg)
        elif mode == '2':
            ips = [x.strip() for x in args.ips.split(',')] if args.ips else None
            tool.setup_receiver(cli_ips=ips, auto_bg=args.bg)
    except KeyboardInterrupt:
        tool.stop_container()
    except Exception as e:
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
