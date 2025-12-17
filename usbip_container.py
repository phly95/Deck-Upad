#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
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
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def stop_container(self):
        print("\nStopping containers...")

        # --- Sender Cleanup: Release devices back to Host ---
        try:
            print("      Releasing local devices back to host...")
            unbind_cmd = (
                "for busid in $(ls /sys/bus/usb/drivers/usbip-host/ 2>/dev/null | grep -E '^[0-9]+-[0-9]+'); do "
                "  echo Releasing $busid...; "
                "  usbip unbind -b $busid; "
                "done"
            )
            self.run_command(f"{self.exec_cmd} '/bin/bash -c \"{unbind_cmd}\"'", check=False)
        except Exception as e:
            print(f"      [Warning] Could not unbind devices: {e}")

        self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)
        self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

        # Receiver Cleanup
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

    # --- SENDER LOGIC (Steam Deck) ---
    def setup_sender(self, resume=False, host_ip=None, auto_bg=False):
        print("\n--- SENDER MODE (Steam Deck) ---")

        if resume:
            print(">> Resuming existing Sender session.")
        else:
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

            # Note: We rely on ping to detect if Host is UP.
            # Host Firewall MUST allow ICMP (Ping) for this to work!
            sender_keepalive = f"""#!/bin/bash
            BUS_ID="{target_bus}"
            HOST_IP="{target_ip if target_ip else ''}"

            echo "Starting Sender Keepalive for $BUS_ID"

            bind_device() {{
                DRIVER_PATH="/sys/bus/usb/devices/$BUS_ID/driver"
                # Check if already bound to usbip-host
                if [ -e "$DRIVER_PATH" ]; then
                    CURRENT=$(readlink "$DRIVER_PATH")
                    if [[ "$CURRENT" == *"usbip-host"* ]]; then return; fi
                fi
                echo "Binding $BUS_ID..."
                usbip bind -b $BUS_ID
            }}

            unbind_device() {{
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
                    if ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1; then
                        bind_device
                    else
                        unbind_device
                    fi
                else
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
            print(" * NOTE: Ensure your PC Firewall allows Pings!")
        print("-" * 40)
        print(" 1. Press ENTER to Stop and Cleanup.")
        print(" 2. Type 'bg' and ENTER to keep running in background.")
        print("="*40)

        if auto_bg: sys.exit(0)
        if input().strip().lower() == 'bg': sys.exit(0)
        self.stop_container()

    # --- RECEIVER LOGIC (PC) ---
    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        if resume:
            print(">> Resuming existing Receiver session.")
        else:
            ips = cli_ips
            if not ips:
                ip_input = input("Enter Steam Deck IP(s) (comma separated): ").strip()
                ips = [x.strip() for x in ip_input.split(',')]

            print("      Loading 'vhci-hcd' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe vhci-hcd'")

            # Convert list of IPs to space-separated string for bash
            ip_list_str = " ".join(ips)

            # Updated Receiver Keepalive: "Hunter/Seeker" Mode
            # It constantly scans the target IPs for the Valve VID:PID (28de:1205).
            # If found, it attaches automatically.
            receiver_keepalive = f"""#!/bin/bash
            TARGET_IPS="{ip_list_str}"
            TARGET_VID="{VALVE_VID}"
            TARGET_PID="{VALVE_PID}"

            echo "Starting Hunter Agent for Valve Controller ($TARGET_VID:$TARGET_PID)..."

            while true; do
                for IP in $TARGET_IPS; do
                    # 1. Check if we are already connected to this IP
                    # (Simple check: is there a port using this IP?)
                    if usbip port | grep -q "$IP"; then
                        continue
                    fi

                    # 2. Scan remote list for our specific controller
                    OUTPUT=$(usbip list -r $IP 2>/dev/null)

                    # Grep for the VID:PID and extract the Bus ID (e.g., "1-3")
                    # Output format is usually: "   1-3: Valve... (28de:1205)"
                    REMOTE_BUS=$(echo "$OUTPUT" | grep "$TARGET_VID:$TARGET_PID" | awk -F: '{{print $1}}' | xargs)

                    if [ -n "$REMOTE_BUS" ]; then
                        echo "Found Controller at $IP Bus $REMOTE_BUS. Attaching..."
                        usbip attach -r $IP -b $REMOTE_BUS
                    fi
                done
                sleep 5
            done
            """

            self.run_command(f"{self.exec_cmd} 'cat > {KEEPALIVE_SCRIPT}'", input=receiver_keepalive)
            self.run_command(f"{self.exec_cmd} 'chmod +x {KEEPALIVE_SCRIPT}'")
            print(f"\n      Starting Receiver Agent...")
            self.run_command(f"{self.exec_cmd} 'nohup {KEEPALIVE_SCRIPT} > /dev/null 2>&1 &'")
            time.sleep(1)

        print("\n" + "="*40)
        print(" RECEIVER IS RUNNING (Auto-Hunt Mode)")
        print(" * It will automatically attach when the Deck becomes available.")
        print("-" * 40)
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
    parser.add_argument("-i", "--ips", help="IPs (Comma separated).")
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

    if not mode_sel:
        print("1. Sender (Steam Deck)")
        print("2. Receiver (Bazzite PC)")
        mode_sel = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()

        cli_ips = [x.strip() for x in args.ips.split(',')] if args.ips else None

        if mode_sel == '1':
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
