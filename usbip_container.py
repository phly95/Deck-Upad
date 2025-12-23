#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import re
import argparse
import threading
import tempfile

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
# We stick to v9 base to avoid rebuilding, but we will patch it at runtime
CUSTOM_IMAGE = "usbip-ready-v9"
INTERNAL_DAEMON_PATH = "/usr/local/bin/usbip_automator.py"
INTERNAL_LOG_PATH = "/var/log/usbip_automator.log"

# Steam Deck Controller Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

class ContainerUSBIP:
    def __init__(self):
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/bash -c"
        self.log_thread = None
        self.stop_logging = False

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
                # Suppress non-critical errors
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
            self.stop_logging = True

            # Kill processes
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
            # We do NOT remove the image to save time
            print("Cleaned up.")

    def ensure_runtime_dependencies(self):
        """Patches the container if it was built without necessary tools."""
        print("      [Init] Verifying container dependencies...")
        # Check for python3 and timeout (coreutils)
        check = self.run_command(f"{self.exec_cmd} 'which python3 timeout'", check=False)
        if not check:
            print("      [Fix] Installing missing tools (python3/coreutils)...")
            # Install without rebuilding image
            self.run_command(f"{self.exec_cmd} 'dnf install -y python3 coreutils procps-ng'", check=False)

    def ensure_image_exists(self):
        print("[1/5] Checking for USBIP tools image...")
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)
        if has_image:
            print(f"      Image '{CUSTOM_IMAGE}' found. Skipping build.")
            return

        print("      Image not found. Building...")
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        # Install base tools
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils coreutils python3 --exclude=kernel-debug*"

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
        # Verify dependencies exist now that it's running
        self.ensure_runtime_dependencies()

    # --- ROBUST DAEMON INJECTION ---
    def install_daemon_script(self):
        """Writes the Python logic to a host temp file, then copies it in."""

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

def log(msg):
    print(msg, flush=True)

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    except: return ""

def check_ip(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        if sock.connect_ex((ip, USBIP_PORT)) == 0:
            sock.close()
            return ip
    except: pass
    return None

def main_loop():
    log("[Daemon] Starting internal scanner on 192.168.50.x...")
    run_cmd("modprobe vhci-hcd")
    ips = [f"{SCAN_SUBNET_PREFIX}{i}" for i in range(1, 255)]

    while True:
        try:
            # 1. SCAN
            log(f"[Daemon] Scanning subnet...")
            found_hosts = []
            with ThreadPoolExecutor(max_workers=15) as ex:
                for ip in ex.map(check_ip, ips):
                    if ip: found_hosts.append(ip)

            if found_hosts:
                log(f"[Daemon] Found hosts: {found_hosts}")

            # 2. DISCOVERY & ATTACH
            for host in found_hosts:
                try:
                    # Timeout protects against hanging connections
                    out = run_cmd(f"timeout 5 usbip list -r {host}")

                    if "28de:1205" in out:
                        match = re.search(r"([\d\.-]+):.*28de:1205", out)
                        if match:
                            bus = match.group(1)
                            ports = run_cmd("usbip port")

                            if host not in ports:
                                log(f"[Daemon] Found Deck at {host}:{bus}. Attaching...")
                                time.sleep(2)
                                res = run_cmd(f"usbip attach -r {host} -b {bus}")
                                log(f"[Daemon] Attach Result: {res}")
                            else:
                                pass # Already attached
                except Exception as inner_e:
                    log(f"[Error] Host check failed: {inner_e}")

        except Exception as e:
            log(f"[Fatal Daemon Error] {e}")

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main_loop()
"""
        # SAFE WRITE: Create temp file on host, copy to container
        # This avoids bash quoting hell.
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write(daemon_code)
            tmp_path = tmp.name

        try:
            self.run_command(f"podman cp {tmp_path} {CONTAINER_NAME}:{INTERNAL_DAEMON_PATH}")
            self.run_command(f"{self.exec_cmd} 'chmod +x {INTERNAL_DAEMON_PATH}'")
        finally:
            os.unlink(tmp_path)

    def stream_logs(self):
        """Tails the internal log file."""
        process = subprocess.Popen(
            shlex.split(f"podman exec {CONTAINER_NAME} tail -f {INTERNAL_LOG_PATH}"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        while not self.stop_logging:
            line = process.stdout.readline()
            if not line: break
            print(f"   {line.strip()}")

        process.terminate()

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
            # Install the brain (robustly)
            self.install_daemon_script()

            # Reset logs
            self.run_command(f"{self.exec_cmd} 'truncate -s 0 {INTERNAL_LOG_PATH}'")

            # Start the brain
            print("      [Launcher] Starting internal Automator Daemon...")
            self.run_command(f"{self.exec_cmd} 'nohup python3 -u {INTERNAL_DAEMON_PATH} > {INTERNAL_LOG_PATH} 2>&1 &'")

            # Quick check if it crashed immediately
            time.sleep(1)
            check = self.run_command(f"{self.exec_cmd} 'pgrep -f usbip_automator.py'", check=False)
            if not check:
                print("\n[CRITICAL ERROR] The internal daemon crashed immediately.")
                print("--- Crash Log ---")
                print(self.run_command(f"{self.exec_cmd} 'cat {INTERNAL_LOG_PATH}'"))
                print("-----------------")
                return

        print("\n" + "="*40)
        print(" RECEIVER ACTIVE - LIVE LOGS (Ctrl+C or 'bg' to detach)")
        print("="*40)

        self.stop_logging = False
        t = threading.Thread(target=self.stream_logs, daemon=True)
        t.start()

        if auto_bg:
            self.stop_logging = True
            sys.exit(0)

        try:
            while True:
                user_in = input().strip().lower()
                if user_in == 'bg':
                    print("[Backgrounding] Logs hidden. Daemon continues running.")
                    self.stop_logging = True
                    sys.exit(0)
                elif user_in == 'stop':
                    self.stop_container()
                    break
        except KeyboardInterrupt:
            self.stop_container()

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
