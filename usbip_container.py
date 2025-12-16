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

class ContainerUSBIP:
    def __init__(self):
        # We update this command dynamically depending on which container is active
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
        # Ensure builder is gone too
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        print("Done.")

    def ensure_image_exists(self):
        """Builds the custom image if it doesn't exist."""
        print("[1/5] Checking for USBIP tools image...")
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)

        if has_image:
            print("      Image found. Skipping build.")
            return

        print("      Image not found. Building...")
        print("[2/5] Creating Builder Container (Internet Required)...")

        # 1. Start BUILDER (No Host Mounts, just internet)
        self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self.run_command(
            f"podman run -d --name {BUILDER_NAME} "
            f"{BASE_IMAGE} sleep infinity"
        )

        # 2. Install Tools
        print("      Installing packages (this may take a minute)...")
        # We exclude kernel-debug to save space, but we let it install kernel-core
        # because usbip tools often depend on exact kernel versions.
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils --exclude=kernel-debug*"

        try:
            self.run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'")

            # 3. Commit to Image
            print(f"      Saving to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")

            # 4. Cleanup Builder
            self.run_command(f"podman rm -f {BUILDER_NAME}")
            print("      Build Complete.")

        except Exception as e:
            print("\n[ERROR] Build failed. Check your internet connection.")
            print("Cleaning up builder...")
            self.run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            sys.exit(1)

    def start_runtime_container(self):
        """Starts the privileged container with host access."""
        print("[3/5] Starting Runtime Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # CRITICAL:
        # --privileged: Access to Host Hardware/Kernel
        # --net=host: Simple IP networking
        # -v /dev:/dev: See USB devices
        # -v /lib/modules:/lib/modules:ro: Load Host Kernel Modules
        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    # --- SENDER LOGIC (STEAM DECK) ---
    def setup_sender(self):
        print("\n--- SENDER MODE (Steam Deck) ---")

        print("      Loading 'usbip-host' kernel module...")
        self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")

        print("      Starting usbip daemon...")
        self.run_command(f"{self.exec_cmd} 'usbipd -D'")

        print("      Scanning local USB devices...")
        output = self.run_command(f"{self.exec_cmd} 'usbip list -l'")

        devices = []
        current_bus = None
        for line in output.split('\n'):
            if "busid=" in line:
                current_bus = line.split("busid=")[1].split(' ')[0]
            elif current_bus and re.search(r'\([0-9a-f]{4}:[0-9a-f]{4}\)', line):
                desc = line.strip()
                devices.append({'bus': current_bus, 'desc': desc})
                current_bus = None

        print("\nAvailable Devices:")
        valve_candidates = []
        for i, dev in enumerate(devices):
            print(f" {i+1}: Bus {dev['bus']} - {dev['desc']}")
            if "Valve" in dev['desc'] or "28de" in dev['desc']:
                valve_candidates.append(i+1)

        sel = input(f"\nSelect Device # to Bind {valve_candidates}: ").strip()
        if not sel.isdigit(): return

        target = devices[int(sel)-1]

        print(f"\nBinding {target['bus']}...")
        self.run_command(f"{self.exec_cmd} 'usbip bind -b {target['bus']}'")

        print("\n" + "="*40)
        print(f" DEVICE BOUND: {target['bus']}")
        print(f" Server is running. Go to your Bazzite PC now.")
        print(" Press ENTER here to Unbind and Exit.")
        print("="*40)

        try:
            input()
        finally:
            print("Unbinding...")
            self.run_command(f"{self.exec_cmd} 'usbip unbind -b {target['bus']}'", check=False)

    # --- RECEIVER LOGIC (BAZZITE) ---
    def setup_receiver(self):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        sender_ip = input("Enter Steam Deck IP: ").strip()

        print("      Loading 'vhci-hcd' kernel module...")
        self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

        print(f"      Scanning {sender_ip}...")
        try:
            output = self.run_command(f"{self.exec_cmd} 'usbip list -r {sender_ip}'")
        except:
            print("Could not connect to Deck. Ensure Sender script is running there.")
            return

        print(output)

        bus_id = input("\nEnter Bus ID from above (e.g., 1-1): ").strip()

        print(f"      Attaching {bus_id}...")
        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {bus_id}'")

        print("\n" + "="*40)
        print(" SUCCESS! Controller attached.")
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

    print("USBIP Container Wrapper")
    print("1. Sender (Steam Deck)")
    print("2. Receiver (Bazzite PC)")
    mode = input("Select Mode (1/2): ").strip()

    try:
        # Step 1: Build Image (if needed)
        tool.ensure_image_exists()

        # Step 2: Run Runtime Container
        tool.start_runtime_container()

        # Step 3: Run Logic
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
