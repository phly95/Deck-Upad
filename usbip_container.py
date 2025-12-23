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
CUSTOM_IMAGE = "usbip-ready-v2"
KEEPALIVE_SCRIPT = "/usr/local/bin/usbip-keepalive.sh"

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
                # Suppress expected errors during scanning
                if "avahi-browse" not in str(cmd):
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
            self.run_command(f"{self.exec_cmd} 'pkill avahi-publish'", check=False)

            # Receiver Cleanup
            try:
                print("      Detaching imported USBIP devices...")
                # Only detach ports that are actually imported to avoid errors
                self.run_command(f"{self.exec_cmd} 'usbip detach -p 00'", check=False)
            except: pass

            # Sender Cleanup (SAFER: Only unbind Valve devices)
            try:
                print("      Unbinding Valve devices to return control to Host...")
                out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
                if out:
                    # Capture groups: 1=BusID
                    # Regex looks for: busid 1-1 (28de:1205)
                    # This STRICTLY matches only Valve IDs
                    matches = re.findall(r"busid\s+([\d\.-]+)\s+\(" + VALVE_VID + r":" + VALVE_PID + r"\)", out)

                    if matches:
                        for bus_id in matches:
                            print(f"      Releasing Steam Deck Controller (Bus {bus_id})...")
                            self.run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
                            self.run_command(f"{self.exec_cmd} 'udevadm trigger'", check=False)
                    else:
                        print("      No bound Steam Deck controllers found to release.")
            except Exception as e:
                print(f"      Cleanup warning: {e}")

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

        print("      Image not found. Building (includes Avahi discovery)...")
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils avahi-tools --exclude=kernel-debug*"

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
            "-v /var/run/dbus:/var/run/dbus "
            "-v /var/run/avahi-daemon/socket:/var/run/avahi-daemon/socket "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- DISCOVERY UTILS ---
    def start_advertising(self, bus_id):
        print(f"      [Discovery] Announcing 'SteamDeck-USBIP-{bus_id}'...")
        cmd = f"avahi-publish -s 'SteamDeck-USBIP' -p _usbip._tcp 3240 --txt='busid={bus_id}'"
        self.run_command(f"{self.exec_cmd} 'nohup {cmd} > /dev/null 2>&1 &'")

    def scan_for_senders(self):
        print("      [Discovery] Scanning network...")
        found_ips = set()
        try:
            # -r: resolve, -p: parsable, -t: terminate (dump cache)
            out = self.run_command(f"{self.exec_cmd} 'avahi-browse -r -p -t _usbip._tcp'", check=False)
            if out:
                for line in out.splitlines():
                    parts = line.split(';')
                    if len(parts) > 7 and parts[0] == '=':
                        ip = parts[7]
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                            found_ips.add(ip)
        except: pass
        return list(found_ips)

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
            self.start_advertising(target_bus)

        print("\n" + "="*40)
        print(" SENDER ACTIVE (Announcing on Network)")
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
            if cli_ips:
                ips = cli_ips
                print(f"Using provided IPs: {ips}")
            else:
                # --- FIXED DISCOVERY LOOP ---
                while True:
                    ips = self.scan_for_senders()

                    if ips:
                        print(f"      [Discovery] Found Steam Decks: {ips}")
                        break

                    print("      [!] No Steam Decks found.")
                    ip_input = input("      Enter IP manually (or ENTER to retry): ").strip()

                    if ip_input:
                        ips = [x.strip() for x in ip_input.split(',')]
                        break

                    print("      Retrying scan...")
                    time.sleep(1) # Brief pause before rescanning

            if not ips:
                print("No IPs configured. Exiting.")
                return

            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")
            targets = []

            for sender_ip in ips:
                print(f"\n[Scanning {sender_ip}]...")
                try:
                    output = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
                    print(output)
                    found_bus = None
                    if "28de:1205" in output:
                         match = re.search(r"([\d\.-]+):.*28de:1205", output)
                         if match: found_bus = match.group(1)

                    if found_bus:
                        print(f"      Auto-detected Valve Controller at Bus {found_bus}")
                    else:
                        found_bus = input(f"Enter Bus ID from above (or ENTER to skip): ").strip()

                    if found_bus:
                        targets.append(f"{sender_ip}:{found_bus}")
                        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {found_bus}'", check=False)
                except:
                    print(f"      Could not connect to {sender_ip}. Skipping.")

            if not targets: return

            target_str = " ".join(targets)
            keepalive_code = f"""#!/bin/bash
            TARGETS="{target_str}"
            while true; do
                for PAIR in $TARGETS; do
                    IP=${{PAIR%%:*}}
                    BUS=${{PAIR##*:}}
                    if ! usbip port | grep -q "$IP" | grep -q "$BUS"; then
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
        print(" RECEIVER ACTIVE (Auto-Reconnect Enabled)")
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
