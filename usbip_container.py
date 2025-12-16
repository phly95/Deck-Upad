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
BASE_IMAGE = "fedora:41"  # Fedora base for compatibility with Bazzite/SteamOS
CUSTOM_IMAGE = "usbip-ready"

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
        # Attempt to stop daemon inside
        self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)
        print("Stopping container...")
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        print("Done.")

    def initialize_container(self):
        print("\n[1/4] Initializing USBIP Container...")

        # Check if we already built the custom image
        has_image = self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False)
        use_image = CUSTOM_IMAGE if has_image else BASE_IMAGE

        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # CRITICAL: --privileged gives access to Host Kernel Modules
        # CRITICAL: --net=host allows simple IP communication
        # CRITICAL: Volumes mount USB bus so we can see devices
        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{use_image} sleep infinity"
        )

        # Install tools if using base image
        if use_image == BASE_IMAGE:
            print("[2/4] Installing USBIP tools (Internet Required)...")
            # Fedora/Bazzite/SteamOS compatible tools
            install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils"

            try:
                self.run_command(f"{self.exec_cmd} '{install_cmd}'")
                print(f"      Caching image to '{CUSTOM_IMAGE}'...")
                self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
            except Exception as e:
                print("Failed to install tools. Check internet connection.")
                raise e
        else:
            print("[2/4] Using Cached Tools (Offline Ready).")

    # --- SENDER LOGIC (STEAM DECK) ---
    def setup_sender(self):
        print("\n--- SENDER MODE (Steam Deck) ---")

        # 1. Load Host Kernel Module (Privileged container can do this!)
        print("      Loading 'usbip-host' kernel module...")
        self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")

        # 2. Start Daemon
        print("      Starting usbip daemon...")
        self.run_command(f"{self.exec_cmd} 'usbipd -D'")

        # 3. List Devices
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

        # 4. Bind
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

        # 1. Load Host Kernel Module
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

        bus_id = input("\nEnter Bus ID from above (e.g., 1-1): ").strip()

        # 3. Attach
        print(f"      Attaching {bus_id}...")
        self.run_command(f"{self.exec_cmd} 'usbip attach -r {sender_ip} -b {bus_id}'")

        print("\n" + "="*40)
        print(" SUCCESS! Controller attached.")
        print(" Press ENTER to Detach and Exit.")
        print("="*40)

        try:
            input()
        finally:
            # We need the port number to detach, not the bus id
            # Usually port 00 if it's the first one
            print("Detaching...")
            # Ideally we parse 'usbip port' to find the port number,
            # but simple detach 00 often works for single device
            self.run_command(f"{self.exec_cmd} 'usbip detach -p 00'", check=False)

def main():
    tool = ContainerUSBIP()
    tool.check_root()

    print("USBIP Container Wrapper")
    print("1. Sender (Steam Deck)")
    print("2. Receiver (Bazzite PC)")
    mode = input("Select Mode (1/2): ").strip()

    try:
        tool.initialize_container()
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
