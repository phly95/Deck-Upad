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

    def is_container_running(self):
        """Checks if the sidecar container is currently active."""
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def stop_container(self):
            print("\nStopping containers...")

            # --- [FIX START] Sender Cleanup: Release devices back to Host ---
            try:
                print("      Releasing local devices back to host...")
                # We look into the sysfs directory for usbip-host to see what is currently bound.
                # We must do this BEFORE killing the container, using the container's usbip tool.
                unbind_cmd = (
                    "for busid in $(ls /sys/bus/usb/drivers/usbip-host/ 2>/dev/null | grep -E '^[0-9]+-[0-9]+'); do "
                    "  echo Releasing $busid...; "
                    "  usbip unbind -b $busid; "
                    "done"
                )
                # We wrap it in /bin/bash -c to ensure the loop and wildcards run correctly
                self.run_command(f"{self.exec_cmd} '/bin/bash -c \"{unbind_cmd}\"'", check=False)
            except Exception as e:
                # If this fails, we just print a warning and continue to force kill
                print(f"      [Warning] Could not unbind devices: {e}")
            # --- [FIX END] ---

            self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)
            self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

            # Receiver Cleanup (Existing logic)
            try:
                print("      Detaching all imported USBIP devices...")
                for i in range(8):
                    port_str = f"{i:02}"
                    self.run_command(f"{self.exec_cmd} 'usbip detach -p {port_str}'", check=False)
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

        print("      Installing packages...")
        install_cmd = "dnf install -y usbip kmod hostname procps-ng findutils iputils --exclude=kernel-debug*"

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

    def get_active_mode(self):
        ps_out = self.run_command(f"{self.exec_cmd} 'ps aux'", check=False)
        if "usbipd" in ps_out: return "sender"
        if "usbip-keepalive.sh" in ps_out: return "receiver"
        return None

    # --- SENDER LOGIC ---
    def setup_sender(self, resume=False, host_ip=None, auto_bg=False):
        print("\n--- SENDER MODE (Steam Deck) ---")

        if resume:
            print(">> Resuming existing Sender session.")
        else:
            # If not provided via CLI, ask for it (Optional)
            target_ip = host_ip
            if not target_ip:
                print("Tip: Enter your PC IP to auto-release controller when PC is off.")
                val = input("PC IP Address (Press ENTER to skip): ").strip()
                if val: target_ip = val

            print("      Loading 'usbip-host' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")
            print("      Starting usbip daemon...")
            self.run_command(f"{self.exec_cmd} 'usbipd -D'")

            candidates = self.find_deck_controller_on_host()
            target_bus = candidates[0] if len(candidates) == 1 else None

            if not target_bus:
                if len(candidates) > 1:
                    print("\nMultiple Valve devices found:")
                    for i, c in enumerate(candidates): print(f" {i+1}: {c}")
                    sel = input("Select #: ")
                    target_bus = candidates[int(sel)-1]
                else:
                    print("No Steam Deck controller found via Host scan.")
                    return

            # Keepalive Script with "Host Watchdog"
            sender_keepalive = f"""#!/bin/bash
            BUS_ID="{target_bus}"
            HOST_IP="{target_ip if target_ip else ''}"

            echo "Starting Sender Keepalive for $BUS_ID (Host: $HOST_IP)"

            bind_device() {{
                # Only bind if not already bound
                DRIVER_PATH="/sys/bus/usb/devices/$BUS_ID/driver"
                if [ -e "$DRIVER_PATH" ]; then
                    CURRENT=$(readlink "$DRIVER_PATH")
                    if [[ "$CURRENT" == *"usbip-host"* ]]; then return; fi
                fi
                echo "Binding $BUS_ID..."
                usbip bind -b $BUS_ID
            }}

            unbind_device() {{
                # Only unbind if currently bound to usbip
                DRIVER_PATH="/sys/bus/usb/devices/$BUS_ID/driver"
                if [ -e "$DRIVER_PATH" ]; then
                    CURRENT=$(readlink "$DRIVER_PATH")
                    if [[ "$CURRENT" == *"usbip-host"* ]]; then
                        echo "Unbinding $BUS_ID (Host Offline)..."
                        usbip unbind -b $BUS_ID
                    fi
                fi
            }}

            while true; do
                if [ -n "$HOST_IP" ]; then
                    # Watchdog Mode: Check if Host is reachable
                    if ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1; then
                        # Host UP -> Steal Controller
                        bind_device
                    else
                        # Host DOWN -> Release Controller
                        unbind_device
                    fi
                else
                    # Dumb Mode: Always keep bound
                    bind_device
                fi
                sleep 3
            done
            """

            self.run_command(f"{self.exec_cmd} 'cat > {KEEPALIVE_SCRIPT}'", input=sender_keepalive)
            self.run_command(f"{self.exec_cmd} 'chmod +x {KEEPALIVE_SCRIPT}'")
            print(f"      Starting Watchdog Agent...")
            self.run_command(f"{self.exec_cmd} 'nohup {KEEPALIVE_SCRIPT} > /dev/null 2>&1 &'")

        print("\n" + "="*40)
        print(" SENDER IS RUNNING")
        if host_ip:
            print(f" * Watching Host ({host_ip}).")
            print(" * If PC is OFF, controller works on Deck.")
            print(" * If PC is ON, controller moves to PC.")
        else:
            print(" * No Host IP provided. Controller will stay bound to Network.")
        print("-" * 40)
        print(" 1. Press ENTER to Stop and Cleanup.")
        print(" 2. Type 'bg' and ENTER to keep running in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        self.stop_container()

    # --- RECEIVER LOGIC ---
    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        if resume:
            print(">> Resuming existing Receiver session.")
        else:
            ips = cli_ips
            if not ips:
                ip_input = input("Enter Steam Deck IPs (comma separated): ").strip()
                ips = [x.strip() for x in ip_input.split(',')]

            print("      Loading 'vhci-hcd' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

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
                except: print(f"      Skipping {sender_ip}.")

            if not targets: return

            target_str = " ".join(targets)
            keepalive_code = f"""#!/bin/bash
            TARGETS="{target_str}"
            while true; do
                for PAIR in $TARGETS; do
                    IP=${{PAIR%%:*}}; BUS=${{PAIR##*:}}
                    if ! usbip port | grep -q "$IP" | grep -q "$BUS"; then
                        usbip attach -r $IP -b $BUS
                    fi
                done
                sleep 5
            done
            """

            self.run_command(f"{self.exec_cmd} 'cat > {KEEPALIVE_SCRIPT}'", input=keepalive_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {KEEPALIVE_SCRIPT}'")
            print(f"\n      Starting Receiver Agent...")
            self.run_command(f"{self.exec_cmd} 'nohup {KEEPALIVE_SCRIPT} > /dev/null 2>&1 &'")
            time.sleep(1)

        print("\n" + "="*40)
        print(" RECEIVER IS RUNNING")
        print(" 1. Press ENTER to Detach All and Stop.")
        print(" 2. Type 'bg' and ENTER to keep running in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        self.stop_container()

    # --- HOST DISCOVERY ---
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"])
    parser.add_argument("-i", "--ips", help="IPs (Comma separated). Used as Client IP list for Receiver OR Host IP for Sender watchdog.")
    parser.add_argument("--bg", action="store_true", help="Auto-background")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    if tool.is_container_running():
        mode = tool.get_active_mode()
        if mode:
            print(f"\n[!] Existing {mode.upper()} session.")
            if mode == 'sender': tool.setup_sender(resume=True, auto_bg=args.bg)
            elif mode == 'receiver': tool.setup_receiver(resume=True, auto_bg=args.bg)
            return
        else: tool.stop_container()

    mode_sel = ""
    if args.mode: mode_sel = '1' if args.mode in ['sender','1'] else '2'
    elif args.ips:
        # Guess mode based on context? Default to receiver if IPs provided, unless user explicitly says sender
        # Actually, for Sender mode, -i implies "Host IP". For Receiver, it implies "Sender IPs".
        # We will default to Prompt if mode not specified.
        pass

    if not mode_sel:
        print("1. Sender (Steam Deck)")
        print("2. Receiver (Bazzite PC)")
        mode_sel = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()

        cli_ips = [x.strip() for x in args.ips.split(',')] if args.ips else None

        if mode_sel == '1':
            # Use the first IP in the list as the Host IP for watchdog
            host_ip = cli_ips[0] if cli_ips else None
            tool.setup_sender(host_ip=host_ip, auto_bg=args.bg)
        elif mode_sel == '2':
            tool.setup_receiver(cli_ips=cli_ips, auto_bg=args.bg)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        tool.stop_container()
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
        tool.stop_container()

if __name__ == "__main__":
    main()
