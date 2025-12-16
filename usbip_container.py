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
                print(f"Command failed: {cmd}")
                print(f"Stderr: {e.stderr}")
                raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def cleanup(self):
        print("\n\n--- Cleaning Up ---")
        self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)
        print("Stopping containers...")
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        print("Done.")

    def ensure_image_exists(self):
        print("[1/5] Checking for USBIP tools image...")
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)
        if has_image:
            print("      Image found. Skipping build.")
            return

        print("      Image not found. Building...")
        print("[2/5] Creating Builder Container (Internet Required)...")
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        print("      Installing packages...")
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
        print("[3/5] Starting Runtime Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        # CRITICAL: Mount /sys and /dev so container can act on the Host Kernel
        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- HOST-SIDE DISCOVERY (Bypasses Container Blindness) ---
    def find_deck_controller_on_host(self):
        """Scans the Host OS /sys/bus/usb to find the Neptune controller."""
        print("      Scanning Host /sys/bus/usb/devices/...")
        base_path = "/sys/bus/usb/devices"

        candidates = []

        if not os.path.exists(base_path):
            print("      Warning: /sys/bus/usb/devices not found.")
            return []

        for device_id in os.listdir(base_path):
            # Skip root hubs (usb1, usb2) and interface endpoints (1-1:1.0)
            if ":" in device_id or device_id.startswith("usb"):
                continue

            vid_path = os.path.join(base_path, device_id, "idVendor")
            pid_path = os.path.join(base_path, device_id, "idProduct")

            if os.path.exists(vid_path) and os.path.exists(pid_path):
                try:
                    with open(vid_path, 'r') as f: vid = f.read().strip()
                    with open(pid_path, 'r') as f: pid = f.read().strip()

                    if vid == VALVE_VID and pid == VALVE_PID:
                        candidates.append(device_id)
                        print(f"      FOUND NEPTUNE: BusID {device_id} ({vid}:{pid})")
                except: continue

        return candidates

    # --- SENDER LOGIC (STEAM DECK) ---
    def setup_sender(self):
        print("\n--- SENDER MODE (Steam Deck) ---")

        # 1. Load Module via Container
        print("      Loading 'usbip-host' kernel module...")
        self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")

        # 2. Start Daemon via Container
        print("      Starting usbip daemon...")
        self.run_command(f"{self.exec_cmd} 'usbipd -D'")

        # 3. Find Device using HOST PYTHON (Reliable)
        candidates = self.find_deck_controller_on_host()

        target_bus = None
        if not candidates:
            print("\n[WARNING] Could not auto-detect Steam Deck Controller (Neptune).")
            print("Falling back to listing all devices via container (might be empty)...")
            # Fallback code...
        elif len(candidates) == 1:
            target_bus = candidates[0]
            print(f"\nAuto-selected Steam Deck Controller: {target_bus}")
        else:
            print("\nMultiple Valve devices found:")
            for i, c in enumerate(candidates):
                print(f" {i+1}: {c}")
            sel = input("Select #: ")
            target_bus = candidates[int(sel)-1]

        # 4. Bind via Container
        if target_bus:
            print(f"\nBinding {target_bus}...")
            # We use the container to execute the bind, accessing the mapped /sys
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'")

            print("\n" + "="*40)
            print(f" DEVICE BOUND: {target_bus}")
            print(f" The Controller is now accessible over network.")
            print(f" Go to your Bazzite PC Receiver.")
            print(" Press ENTER here to Unbind and Exit.")
            print("="*40)

            try:
                input()
            finally:
                print("Unbinding...")
                self.run_command(f"{self.exec_cmd} 'usbip unbind -b {target_bus}'", check=False)

    # --- RECEIVER LOGIC (BAZZITE) ---
    def setup_receiver(self):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        sender_ip = input("Enter Steam Deck IP: ").strip()

        # 1. Load Module (Attaches virtual device to HOST kernel)
        print("      Loading 'vhci-hcd' kernel module...")
        self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

        # 2. Scan Remote
        print(f"      Scanning {sender_ip}...")
        try:
            output = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
        except:
            print("Could not connect to Deck. Ensure Sender script is running there.")
            return

        print(output)

        bus_id = input("\nEnter Bus ID from above (e.g., 3-1): ").strip()

        # 3. Attach (This creates the /dev/input node on the HOST OS)
        print(f"      Attaching {bus_id}...")
        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {bus_id}'")

        print("\n" + "="*40)
        print(" SUCCESS! Controller attached.")
        print(" It is now available to Bazzite OS and Games.")
        print(" Press ENTER to Detach and Exit.")
        print("="*40)

        try:
            input()
        finally:
            print("Detaching...")
            self.run_command(f"{self.exec_cmd} 'usbip detach -p 00'", check=False)

def main():
    tool = ContainerUSBIP()
    tool.check_root()

    print("USBIP Container Wrapper (Hybrid Discovery)")
    print("1. Sender (Steam Deck)")
    print("2. Receiver (Bazzite PC)")
    mode = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()

        if mode == '1':
            tool.setup_sender()
        elif mode == '2':
            tool.setup_receiver()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
    finally:
        tool.cleanup()

if __name__ == "__main__":
    main()
