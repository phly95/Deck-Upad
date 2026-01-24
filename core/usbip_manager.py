import subprocess
import time
import os
import sys
import shlex
import re

# --- Configuration ---
CONTAINER_NAME = "usbip-sidecar"
BUILDER_NAME = "usbip-builder"
BASE_IMAGE = "fedora:41"
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

    def ensure_image_exists(self):
        """
        Ensures the USBIP image is built. Requires Internet.
        """
        if self._run_command(f"podman images -q {CUSTOM_IMAGE}", check=False):
            return

        print(f"[UsbIpManager] Building image '{CUSTOM_IMAGE}' (Internet Required)...")
        self._run_command(f"podman rm -f {BUILDER_NAME}", check=False)
        self._run_command(f"podman run -d --name {BUILDER_NAME} {BASE_IMAGE} sleep infinity")

        try:
            # FIX FOR STEAMOS: Disable zchunk to prevent "No space left on device" errors
            print("   Configuring DNF for limited storage (SteamOS fix)...")
            self._run_command(f"podman exec {BUILDER_NAME} /bin/bash -c 'echo zchunk=False >> /etc/dnf/dnf.conf && dnf clean all'")

            # Install USBIP tools and kernel modules tools
            # Added --setopt=install_weak_deps=False to save space
            install_cmd = "dnf install -y --setopt=install_weak_deps=False usbip kmod hostname procps-ng findutils coreutils python3 --exclude=kernel-debug*"
            print("   Installing dependencies (this may take a minute)...")
            self._run_command(f"podman exec {BUILDER_NAME} /bin/bash -c '{install_cmd}'")

            print(f"   Committing to {CUSTOM_IMAGE}...")
            self._run_command(f"podman commit {BUILDER_NAME} {CUSTOM_IMAGE}")
        except Exception as e:
            print(f"[CRITICAL] Build failed: {e}")
            raise e
        finally:
            self._run_command(f"podman rm -f {BUILDER_NAME}", check=False)

    # --- Public API ---

    def start_sender_mode(self):
        """
        [Deck Side] Starts container, finds controller, binds it.
        """
        print("[UsbIpManager] Initializing Sender (Deck)...")
        self._start_container()

        print("   Loading kernel modules...")
        self._run_command(f"{self.exec_cmd} 'modprobe usbip-host'", check=False)
        print("   Starting usbipd...")
        self._run_command(f"{self.exec_cmd} 'usbipd -D'", check=False)

        bus_id = self._find_valve_controller_bus()
        if not bus_id:
            print("[UsbIpManager] No Steam Deck Controller found!")
            return None

        print(f"   Binding Controller at Bus {bus_id}...")
        # Unbind first just in case
        self._run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
        self._run_command(f"{self.exec_cmd} 'usbip bind -b {bus_id}'")
        return bus_id

    def release_device(self, bus_id):
        """
        [Critical] Unbinds from USBIP and returns control to SteamOS.
        """
        if not bus_id: return
        print(f"[UsbIpManager] Restoring Controls (Unbinding {bus_id})...")
        if self._is_container_running():
            # Unbind from usbip-host
            self._run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
            # Trigger udev to re-bind the generic driver
            self._run_command(f"{self.exec_cmd} 'udevadm trigger'", check=False)

    def start_receiver_mode(self):
        """
        [Host Side] Starts container, loads vhci-hcd.
        """
        print("[UsbIpManager] Initializing Receiver (Host)...")
        self._start_container()
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

            out = self._run_command(f"{self.exec_cmd} 'usbip attach -r {client_ip} -b {bus_id}'")
            print(f"   Result: {out}")
            return True
        except Exception as e:
            print(f"[ERROR] Attach failed: {e}")
            return False

    def detach_all_ports(self):
        """
        [Host Side] Detaches all imported USBIP devices to prevent kernel hangs.
        """
        if not self._is_container_running(): return

        print("[UsbIpManager] Detaching all virtual USB ports...")
        try:
            # List imported devices
            out = self._run_command(f"{self.exec_cmd} 'usbip port'", check=False)
            if not out: return

            # Regex to find port numbers like "Port 00: <...>"
            matches = re.findall(r"Port\s+(\d+):", out)
            for port in matches:
                print(f"   Detaching Port {port}...")
                self._run_command(f"{self.exec_cmd} 'usbip detach -p {port}'", check=False)
        except Exception as e:
            print(f"[Warning] Error during detach: {e}")

    def cleanup(self):
        # 1. Cleanly detach ports (Prevents Kernel Hangs/Sleep issues)
        self.detach_all_ports()

        # 2. Attempt to unload module (Receiver) or unbind (Sender)
        # This is "Best Effort" cleanup
        if self._is_container_running():
            try:
                # Try unloading vhci-hcd to fully clear state on Host
                self._run_command(f"{self.exec_cmd} 'modprobe -r vhci-hcd'", check=False)
            except: pass

        print("[UsbIpManager] Stopping container...")
        self._run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

    # --- Internal Helpers ---

    def _start_container(self):
        if self._is_container_running(): return

        if not self._run_command(f"podman images -q {CUSTOM_IMAGE}", check=False):
             print("[WARNING] Image missing. Attempting build...")
             self.ensure_image_exists()

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

    def _find_valve_controller_bus(self):
        base_path = "/sys/bus/usb/devices"
        if not os.path.exists(base_path): return None

        for device_id in os.listdir(base_path):
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
