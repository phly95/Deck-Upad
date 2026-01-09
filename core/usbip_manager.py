import subprocess
import time
import os
import sys
import shlex
import re

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"  # Using Fedora for reliable usbip tools
CUSTOM_IMAGE = "usbip-ready-v9"

# Steam Deck Hardware ID
VALVE_VID = "28de"
VALVE_PID = "1205"

class UsbIpManager:
    def __init__(self):
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/bash -c"
        self._check_root()

    def _check_root(self):
        if os.geteuid() != 0:
            raise PermissionError("UsbIpManager must be run as root.")

    # --- Public API ---

    def start_sender_mode(self):
        """
        [Deck Side] Starts container, finds controller, binds it.
        Returns the Bus ID (e.g., '1-3') if successful, or None.
        """
        print("[UsbIpManager] Initializing Sender (Deck)...")
        self._ensure_container_running()

        # 1. Load Host Modules
        print("   Loading kernel modules...")
        self._run_command(f"{self.exec_cmd} 'modprobe usbip-host'", check=False)

        # 2. Start Daemon
        print("   Starting usbipd...")
        self._run_command(f"{self.exec_cmd} 'usbipd -D'", check=False)

        # 3. Find and Bind
        bus_id = self._find_valve_controller_bus()
        if not bus_id:
            print("[UsbIpManager] No Steam Deck Controller found!")
            return None

        print(f"   Binding Controller at Bus {bus_id}...")
        # Unbind first just in case
        self._run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
        self._run_command(f"{self.exec_cmd} 'usbip bind -b {bus_id}'")
        return bus_id

    def start_receiver_mode(self):
        """
        [Host Side] Starts container, loads vhci-hcd.
        """
        print("[UsbIpManager] Initializing Receiver (Host)...")
        self._ensure_container_running()
        print("   Loading vhci-hcd...")
        self._run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'", check=False)

    def connect_device(self, client_ip, bus_id):
        """
        [Host Side] Attaches to the remote device.
        """
        print(f"[UsbIpManager] Attaching to {client_ip}:{bus_id}...")
        try:
            # Check if already attached
            ports = self._run_command(f"{self.exec_cmd} 'usbip port'", check=False)
            if f"Remote Bus Id: {bus_id}" in ports and client_ip in ports:
                print("   Already attached.")
                return True

            # Attach
            # Note: We detach port 00 just in case to keep it clean, or we can manage ports dynamically
            # For now, let's just try to attach.
            out = self._run_command(f"{self.exec_cmd} 'usbip attach -r {client_ip} -b {bus_id}'")
            print(f"   Result: {out}")
            return True
        except Exception as e:
            print(f"[ERROR] Attach failed: {e}")
            return False

    def detach_all(self):
        if self._is_container_running():
            print("[UsbIpManager] Detaching all devices...")
            # Receiver cleanup
            self._run_command(f"{self.exec_cmd} 'usbip detach -p 00'", check=False)
            self._run_command(f"{self.exec_cmd} 'usbip detach -p 01'", check=False)

            # Sender cleanup (Unbind)
            # We don't unbind automatically on close usually, to avoid resetting the controller
            # while the user might still need it, but for a clean exit:
            pass

    def cleanup(self):
        print("[UsbIpManager] Stopping container...")
        self._run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

    # --- Internal Helpers ---

    def _run_command(self, cmd, shell=False, check=True):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if check: raise e
            return None

    def _is_container_running(self):
        res = self._run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def _ensure_container_running(self):
        if self._is_container_running(): return

        # Check Image
        if not self._run_command(f"podman images -q {CUSTOM_IMAGE}", check=False):
            print(f"[UsbIpManager] Building image '{CUSTOM_IMAGE}'...")
            self._run_command(f"podman rm -f {BUILDER_NAME}", check=False)
            self._run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

            # Install tools
            install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils coreutils python3 --exclude=kernel-debug*"
            self._run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'")

            self._run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")
            self._run_command(f"podman rm -f {BUILDER_NAME}")

        # Run Container
        print(f"[UsbIpManager] Starting {CONTAINER_NAME}...")
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        self._run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=host "
            "-v /dev:/dev "
            "-v /lib/modules:/lib/modules:ro "
            "-v /sys:/sys "
            f"{CUSTOM_IMAGE} sleep infinity"
        )

    def _find_valve_controller_bus(self):
        # We look in the Host's sysfs, because /sys is mounted into the container
        # But we need to run this check on the HOST (where this script runs),
        # or inside the container?
        # Since we mount /sys, looking at /sys/bus/usb/devices on the host is easiest.

        base_path = "/sys/bus/usb/devices"
        if not os.path.exists(base_path): return None

        for device_id in os.listdir(base_path):
            # Skip root hubs (usb1, usb2) and interface endpoints (1-1:1.0)
            if ":" in device_id or device_id.startswith("usb"): continue

            vid_path = os.path.join(base_path, device_id, "idVendor")
            pid_path = os.path.join(base_path, device_id, "idProduct")

            if os.path.exists(vid_path) and os.path.exists(pid_path):
                try:
                    with open(vid_path, 'r') as f: vid = f.read().strip()
                    with open(pid_path, 'r') as f: pid = f.read().strip()
                    if vid == VALVE_VID and pid == VALVE_PID:
                        return device_id
                except: continue
        return None
