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

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
CUSTOM_IMAGE = "usbip-ready-v2"
LISTENER_SCRIPT = "/usr/local/bin/usbip_listen.py"
ADVERTISE_SCRIPT = "/usr/local/bin/usbip_advertise.py"

# Steam Deck Controller Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

class ContainerUSBIP:
    def __init__(self):
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/bash -c"

    def run_command(self, cmd, shell=False, check=True, input=None, capture=True):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            if capture:
                result = subprocess.run(
                    cmd, shell=shell, check=check,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, input=input
                )
                return result.stdout.strip()
            else:
                # Stream output to console
                subprocess.run(
                    cmd, shell=shell, check=check,
                    text=True, input=input
                )
                return None
        except subprocess.CalledProcessError as e:
            if check:
                if capture:
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
            self.run_command(f"{self.exec_cmd} 'pkill -f usbip_listen.py'", check=False)
            self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)
            self.run_command(f"{self.exec_cmd} 'pkill -f usbip_advertise.py'", check=False)

            try:
                print("      Detaching all imported USBIP devices (Receiver)...")
                for i in range(8):
                    port_str = f"{i:02}"
                    self.run_command(f"{self.exec_cmd} 'usbip detach -p {port_str}'", check=False)
            except: pass

            try:
                print("      Unbinding devices to return control to Host...")
                out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
                if out:
                    bound_devices = re.findall(r"busid\s+([\d\.-]+)", out)
                    for bus_id in bound_devices:
                        print(f"      Releasing Bus {bus_id}...")
                        self.run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
                        self.run_command(f"{self.exec_cmd} 'udevadm trigger'", check=False)
            except Exception as e:
                print(f"      Error during unbind: {e}")

            self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
            self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
            self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            print("Cleaned up.")

    def ensure_image_exists(self):
        print(f"[1/5] Checking for USBIP tools image ({CUSTOM_IMAGE})...")
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)

        if has_image:
            try:
                # Use python3 --version to verify image health without 'which'
                self.run_command(f"podman run --rm --pull=never {CUSTOM_IMAGE} python3 --version")
                print("      Image found and verified. Skipping build.")
                return
            except Exception as e:
                print(f"      Image verification failed (Error: {e})")
                print("      Rebuilding image (Internet Required)...")
                self.run_command(f"podman rmi -f {CUSTOM_IMAGE}", check=False)

        print("      Image not found. Building...")
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity", capture=False)

        print("      Installing packages...")
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils python3 --exclude=kernel-debug*"

        try:
            self.run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'", capture=False)
            print(f"      Saving to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")
            self.run_command(f"podman rm -f {BUILDER_NAME}")
        except Exception as e:
            print("\n[ERROR] Build failed. Check internet connection.")
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
            "--privileged --net=host "
            "-v /dev:/dev -v /lib/modules:/lib/modules:ro -v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- DISCOVERY ---
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
                    if vid == VALVE_VID and pid == VALVE_PID: candidates.append(device_id)
                except: continue
        return candidates

    def get_active_mode(self):
        ps_out = self.run_command(f"{self.exec_cmd} 'ps aux'", check=False)
        if "usbipd" in ps_out: return "sender"
        if "usbip_listen.py" in ps_out: return "receiver"
        return None

    # --- LOGGING & INTERACTIVE MENU ---
    def _stream_logs(self, log_file):
        """Streams logs in a background thread."""
        self.log_proc = subprocess.Popen(
            f"podman exec {CONTAINER_NAME} tail -f {log_file}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        try:
            for line in self.log_proc.stdout:
                print(line, end='')
        except: pass

    def log_menu_loop(self, log_file):
        print("\n" + "="*55)
        print(" LIVE LOGS ACTIVE")
        print(" (Logs will mix with your typing - just type and hit Enter)")
        print("-" * 55)
        print(" Commands:")
        print("   stop  : Stop container and exit")
        print("   bg    : Detach (keep running) and exit script")
        print("   clear : Clear screen")
        print("="*55)

        t = threading.Thread(target=self._stream_logs, args=(log_file,))
        t.daemon = True
        t.start()

        while True:
            try:
                user_input = input()
                cmd = user_input.strip().lower()

                if cmd in ['stop', 'exit', 'quit']:
                    if hasattr(self, 'log_proc'): self.log_proc.terminate()
                    self.stop_container()
                    sys.exit(0)

                elif cmd in ['bg', 'background']:
                    print("Backgrounding...")
                    sys.exit(0)

                elif cmd == 'clear':
                    os.system('clear')
                    print("Live Logs (stop / bg):")

            except KeyboardInterrupt:
                print("\nType 'stop' and press Enter to exit.")

    # --- MODES ---
    def setup_sender(self, resume=False, auto_bg=False):
        print("\n--- SENDER MODE (Steam Deck) ---")
        if resume:
            print(">> Resuming existing Sender session.")
        else:
            print("      Loading 'usbip-host' kernel module...")
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
                sel = input("Select #: ")
                target_bus = candidates[int(sel)-1]
            else:
                print("No Steam Deck controller found via Host scan.")
                return

            print(f"      Binding {target_bus}...")
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'")

            print("      Starting Advertiser (UDP 5005) & Ack Listener (UDP 5006)...")
            advertise_code = f"""
import socket, time, json, sys, threading
BUS_ID = "{target_bus}"
ADVERT_PORT = 5005
ACK_PORT = 5006

def ack_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(('0.0.0.0', ACK_PORT))
        print(f" [Sender] Listening for Connection Acknowledgments on port {{ACK_PORT}}...")
        sys.stdout.flush()
        while True:
            data, addr = s.recvfrom(1024)
            sender_ip = addr[0]
            try:
                msg = json.loads(data.decode())
                status = msg.get('status', 'Unknown')
                print(f" [!] Bazzite PC detected at {{sender_ip}}! Status: {{status}}")
                sys.stdout.flush()
            except: pass
    except Exception as e: print(f"Ack Error: {{e}}")

t = threading.Thread(target=ack_listener)
t.daemon = True
t.start()

s_broad = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_broad.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print(f" [Sender] Broadcasting Bus {{BUS_ID}}...")
sys.stdout.flush()

while True:
    try:
        msg = json.dumps({{"bus": BUS_ID}}).encode('utf-8')
        # Standard Broadcast (Relied on by WiFi container forwarding)
        try: s_broad.sendto(msg, ('<broadcast>', ADVERT_PORT))
        except: pass
    except: pass
    time.sleep(2)
"""
            self.run_command(f"{self.exec_cmd} 'cat > {ADVERTISE_SCRIPT}'", input=advertise_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {ADVERTISE_SCRIPT}'")
            self.run_command(f"{self.exec_cmd} 'nohup python3 -u {ADVERTISE_SCRIPT} > /var/log/usbip_sender.log 2>&1 &'")

        if auto_bg: sys.exit(0)
        self.log_menu_loop("/var/log/usbip_sender.log")

    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")
        if resume:
            print(">> Resuming existing Receiver session.")
        else:
            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")
            print("      Starting Auto-Discovery Listener (UDP 5005)...")

            listener_code = """
import socket, json, subprocess, time, sys
ADVERT_PORT = 5005
ACK_PORT = 5006
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try: s.bind(('0.0.0.0', ADVERT_PORT))
except Exception as e:
    print(f"Bind failed: {{e}}")
    sys.exit(1)
print(" [Receiver] Listening for advertisements on port 5005...")
sys.stdout.flush()
last_attempts = {}
def send_ack(ip, status_msg):
    try:
        ack_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = json.dumps({"status": status_msg}).encode('utf-8')
        ack_s.sendto(payload, (ip, ACK_PORT))
    except: pass
def is_connected(target_ip, target_bus):
    try:
        res = subprocess.run(["usbip", "port"], capture_output=True, text=True)
        expected = f"usbip://{{target_ip}}:3240/{{target_bus}}"
        return expected in res.stdout
    except: return False
while True:
    try:
        data, addr = s.recvfrom(1024)
        sender_ip = addr[0]
        try: msg = json.loads(data.decode()); bus = msg.get('bus')
        except: continue
        if not bus: continue
        key = f"{sender_ip}:{bus}"
        now = time.time()
        if now - last_attempts.get(key, 0) > 5:
            last_attempts[key] = now
            print(f" [!] Found Steam Deck at {sender_ip} (Bus {bus})")
            send_ack(sender_ip, "Connecting...")
            sys.stdout.flush()
            if is_connected(sender_ip, bus):
                print(f"     -> Already connected.")
                send_ack(sender_ip, "Connected")
            else:
                print(f"     -> Initiating pairing...")
                att = subprocess.run(["usbip", "attach", "-r", sender_ip, "-b", bus], capture_output=True, text=True)
                if att.returncode == 0:
                    print(f" [OK] Successfully attached!")
                    send_ack(sender_ip, "Connected")
                else:
                    print(f" [ERR] Attachment Failed: {att.stderr.strip()}")
                    send_ack(sender_ip, "Failed")
            sys.stdout.flush()
    except Exception as e: print(f"Listener Error: {e}")
"""
            self.run_command(f"{self.exec_cmd} 'cat > {LISTENER_SCRIPT}'", input=listener_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {LISTENER_SCRIPT}'")
            self.run_command(f"{self.exec_cmd} 'nohup python3 -u {LISTENER_SCRIPT} > /var/log/usbip_listen.log 2>&1 &'")

        if auto_bg: sys.exit(0)
        self.log_menu_loop("/var/log/usbip_listen.log")

def main():
    parser = argparse.ArgumentParser(description="USBIP Container Wrapper")
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"], help="Mode: sender (1) or receiver (2)")
    parser.add_argument("--bg", action="store_true", help="Background immediately")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    print("USBIP Container Wrapper (Auto-Discovery & Auto-Pairing)")

    if tool.is_container_running():
        active_mode = tool.get_active_mode()
        if active_mode:
            print(f"\n[!] Existing {active_mode.upper()} session detected.")
            if active_mode == 'sender': tool.setup_sender(resume=True, auto_bg=args.bg)
            elif active_mode == 'receiver': tool.setup_receiver(resume=True, auto_bg=args.bg)
            return
        else:
            print("[!] Container running but no active session detected. Cleaning up...")
            tool.stop_container()

    mode_selection = ""
    if args.mode:
        if args.mode in ['sender', '1']: mode_selection = '1'
        elif args.mode in ['receiver', '2']: mode_selection = '2'
    else:
        print("1. Sender (Steam Deck)")
        print("2. Receiver (Bazzite PC)")
        mode_selection = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()
        if mode_selection == '1': tool.setup_sender(auto_bg=args.bg)
        elif mode_selection == '2': tool.setup_receiver(cli_ips=None, auto_bg=args.bg)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
