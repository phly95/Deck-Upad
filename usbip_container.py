#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import re

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
CUSTOM_IMAGE = "usbip-ready"
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
            [cite_start]# [cite: 2]
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, input=input
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            [cite_start]# [cite: 3]
            if check:
                print(f"Command failed: {cmd}")
                print(f"Stderr: {e.stderr}")
                raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            [cite_start]# [cite: 4]
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def is_container_running(self):
        """Checks if the sidecar container is currently active."""
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def stop_container(self):
        print("\nStopping containers...")
        self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)
        self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

        # Attempt to detach all ports cleanly before killing container
        # This prevents "zombie" connections on the host kernel
        try:
            print("      Detaching all imported USBIP devices...")
            # Simple loop to detach ports 00 through 08 (common range)
            for i in range(8):
                port_str = f"{i:02}"
                self.run_command(f"{self.exec_cmd} 'usbip detach -p {port_str}'", check=False)
        except:
            pass

        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        [cite_start]# [cite: 5]
        print("Cleaned up.")

    def ensure_image_exists(self):
        print("[1/5] Checking for USBIP tools image...")
        [cite_start]# [cite: 5]
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)
        if has_image:
            print("      Image found. Skipping build.")
            return

        print("      Image not found. Building...")
        [cite_start]# [cite: 6]
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        print("      Installing packages...")
        [cite_start]# [cite: 7]
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils --exclude=kernel-debug*"

        try:
            self.run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'")
            print(f"      Saving to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")
            self.run_command(f"podman rm -f {BUILDER_NAME}")
        except Exception as e:
            [cite_start]# [cite: 8]
            print("\n[ERROR] Build failed. Check internet.")
            self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            sys.exit(1)

    def start_runtime_container(self):
        if self.is_container_running():
            print("[Info] Container is already running. Resuming session...")
            return

        print("[3/5] Starting Runtime Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        # CRITICAL: Mount /sys and /dev so container can act on the Host Kernel
        [cite_start]# [cite: 9]
        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- HOST-SIDE DISCOVERY ---
    def find_deck_controller_on_host(self):
        [cite_start]# [cite: 10]
        """Scans the Host OS /sys/bus/usb to find the Neptune controller."""
        base_path = "/sys/bus/usb/devices"
        candidates = []

        if not os.path.exists(base_path):
            return []

        for device_id in os.listdir(base_path):
            if ":" in device_id or device_id.startswith("usb"):
                continue

            vid_path = os.path.join(base_path, device_id, "idVendor")
            pid_path = os.path.join(base_path, device_id, "idProduct")

            if os.path.exists(vid_path) and os.path.exists(pid_path):
                try:
                    with open(vid_path, 'r') as f: vid = f.read().strip()
                    with open(pid_path, 'r') as f: pid = f.read().strip()

                    [cite_start]# [cite: 13]
                    if vid == VALVE_VID and pid == VALVE_PID:
                        candidates.append(device_id)
                except: continue
        return candidates

    def get_active_mode(self):
        """Detects if the running container is acting as Sender or Receiver."""
        # Check for Sender (usbipd running)
        ps_out = self.run_command(f"{self.exec_cmd} 'ps aux'", check=False)
        if "usbipd" in ps_out:
            return "sender"
        # Check for Receiver (keepalive script running)
        if "usbip-keepalive.sh" in ps_out:
            return "receiver"
        return None

    # --- SENDER LOGIC ---
    def setup_sender(self, resume=False):
        print("\n--- SENDER MODE (Steam Deck) ---")

        if resume:
            print(">> Resuming existing Sender session.")
        else:
            print("      Loading 'usbip-host' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")
            print("      Starting usbip daemon...")
            self.run_command(f"{self.exec_cmd} 'usbipd -D'")

            candidates = self.find_deck_controller_on_host()
            target_bus = None
            if len(candidates) == 1:
                target_bus = candidates[0]
                print(f"      Auto-selected Steam Deck Controller: {target_bus}")
            elif len(candidates) > 1:
                print("\nMultiple Valve devices found:")
                for i, c in enumerate(candidates):
                    print(f" {i+1}: {c}")
                sel = input("Select #: ")
                target_bus = candidates[int(sel)-1]
            else:
                print("No Steam Deck controller found via Host scan.")
                return

            print(f"      Binding {target_bus}...")
            [cite_start]# [cite: 18]
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'")

        print("\n" + "="*40)
        print(" SENDER IS RUNNING")
        print(" 1. Press ENTER to Stop and Cleanup.")
        print(" 2. Type 'bg' and ENTER to keep running in background (Safe to Close).")
        print("="*40)

        user_in = input().strip().lower()
        if user_in == 'bg':
            print("Running in background. Run this script again to stop it.")
            sys.exit(0)
        else:
            self.stop_container()

    # --- RECEIVER LOGIC ---
    def setup_receiver(self, resume=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        if resume:
            print(">> Resuming existing Receiver session (Keep-alive active).")
        else:
            print("Enter Steam Deck IP addresses (comma separated for multiple Decks).")
            ip_input = input("IPs: ").strip()
            ips = [x.strip() for x in ip_input.split(',')]

            print("      Loading 'vhci-hcd' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

            targets = [] # Stores "IP:BUSID" strings

            # LOOP through all provided IPs
            for sender_ip in ips:
                print(f"\n[Scanning {sender_ip}]...")
                try:
                    [cite_start]# [cite: 21]
                    output = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
                    print(output)

                    found_bus = input(f"Enter Bus ID to attach from {sender_ip} (or ENTER to skip): ").strip()
                    if found_bus:
                        targets.append(f"{sender_ip}:{found_bus}")
                        # Initial attach
                        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {found_bus}'", check=False)
                except:
                    print(f"      Could not connect to {sender_ip}. Skipping.")

            if not targets:
                print("\nNo devices selected. Exiting.")
                return

            # INJECT MULTI-DEVICE KEEPALIVE SCRIPT
            target_str = " ".join(targets)

            keepalive_code = f"""#!/bin/bash
            # List of targets in format IP:BUS
            TARGETS="{target_str}"

            echo "Starting USBIP Keepalive for: $TARGETS"

            while true; do
                for PAIR in $TARGETS; do
                    IP=${{PAIR%%:*}}
                    BUS=${{PAIR##*:}}

                    # Simple check: If 'usbip port' doesn't show this IP/BUS combo, try to attach
                    # We grep for the specific Bus ID associated with the IP to confirm attachment
                    if ! usbip port | grep -q "$IP" | grep -q "$BUS"; then
                        echo "[$(date)] Reconnecting $IP $BUS..."
                        usbip attach -r $IP -b $BUS
                    fi
                done
                sleep 5
            done
            """

            # Write script to container
            self.run_command(f"{self.exec_cmd} 'cat > {KEEPALIVE_SCRIPT}'", input=keepalive_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {KEEPALIVE_SCRIPT}'")

            # Run it in background inside container
            print(f"\n      Starting Multi-Device Auto-Reconnect Agent...")
            self.run_command(f"{self.exec_cmd} 'nohup {KEEPALIVE_SCRIPT} > /dev/null 2>&1 &'")
            time.sleep(1)

        print("\n" + "="*40)
        print(" RECEIVER IS RUNNING (Multi-Device Support)")
        print(" * All configured Decks will auto-reconnect on wake.")
        print(" * It is safe to close this terminal if you choose Background mode.")
        print("-" * 40)
        print(" 1. Press ENTER to Detach All and Stop.")
        print(" 2. Type 'bg' and ENTER to keep running in background.")
        print("="*40)

        user_in = input().strip().lower()
        if user_in == 'bg':
            print("Running in background. Run this script again to stop it.")
            sys.exit(0)
        else:
            self.stop_container()

def main():
    tool = ContainerUSBIP()
    tool.check_root()

    print("USBIP Container Wrapper (Persistent, Auto-Reconnect, Multi-Deck)")

    # CHECK FOR EXISTING SESSION
    if tool.is_container_running():
        active_mode = tool.get_active_mode()
        if active_mode:
            print(f"\n[!] Existing {active_mode.upper()} session detected.")
            if active_mode == 'sender':
                tool.setup_sender(resume=True)
            elif active_mode == 'receiver':
                tool.setup_receiver(resume=True)
            return
        else:
            print("[!] Container running but no active session detected. Cleaning up...")
            tool.stop_container()

    print("1. Sender (Steam Deck)")
    print("2. Receiver (Bazzite PC)")
    mode = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()

        if mode == '1':
            tool.setup_sender()
        [cite_start]# [cite: 25]
        elif mode == '2':
            tool.setup_receiver()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        tool.stop_container()
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
