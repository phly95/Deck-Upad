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

            # 1. Stop the Receiver side logic
            self.run_command(f"{self.exec_cmd} 'pkill -f usbip-keepalive.sh'", check=False)

            # 2. Stop the Sender side daemon
            self.run_command(f"{self.exec_cmd} 'pkill usbipd'", check=False)

            # 3. Receiver Cleanup: Detach imported ports
            try:
                print("      Detaching all imported USBIP devices (Receiver)...")
                for i in range(8):
                    port_str = f"{i:02}"
                    self.run_command(f"{self.exec_cmd} 'usbip detach -p {port_str}'", check=False)
            except:
                pass

            # --- NEW SECTION: SENDER CLEANUP ---
            # 4. Sender Cleanup: Unbind the device so Steam Deck gets it back
            try:
                print("      Unbinding devices to return control to Host...")
                # We list local devices to find which one is bound to usbip-host
                # output format example: "busid=3-1"
                out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)

                if out:
                    # Regex to find bus IDs (like '1-1', '3-2') that are currently exported
                    # Note: The output usually looks like " - busid 1-1 (28de:1205)"
                    bound_devices = re.findall(r"busid\s+([\d\.-]+)", out)

                    for bus_id in bound_devices:
                        print(f"      Releasing Bus {bus_id}...")
                        self.run_command(f"{self.exec_cmd} 'usbip unbind -b {bus_id}'", check=False)
                        # Optional: specific to Steam Deck, trigger udev to re-detect immediately
                        self.run_command(f"{self.exec_cmd} 'udevadm trigger'", check=False)
            except Exception as e:
                print(f"      Error during unbind: {e}")
            # -----------------------------------

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
        if self.is_container_running():
            print("[Info] Container is already running. Resuming session...")
            return

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

    # --- HOST-SIDE DISCOVERY ---
    def find_deck_controller_on_host(self):
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
    def setup_sender(self, resume=False, auto_bg=False):
        print("\n--- SENDER MODE (Steam Deck) ---")

        target_bus = None

        if resume:
            print(">> Resuming existing Sender session.")
            out = self.run_command(f"{self.exec_cmd} 'usbip list -l'", check=False)
            if out:
                found = re.search(r"busid\s+([\d\.-]+)", out)
                if found:
                    target_bus = found.group(1)
        else:
            print("      Loading 'usbip-host' kernel module...")
            self.run_command(f"{self.exec_cmd} 'modprobe usbip-host'")
            print("      Starting usbip daemon...")
            self.run_command(f"{self.exec_cmd} 'usbipd -D'")

            candidates = self.find_deck_controller_on_host()

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
            self.run_command(f"{self.exec_cmd} 'usbip bind -b {target_bus}'")

        # --- IMPROVED: SYSFS WATCHDOG ---
        if target_bus:
            print(f"      Starting Kernel Watchdog for {target_bus}...")

            # This script monitors the specific device's socket file descriptor in /sys
            watchdog_code = f"""#!/bin/bash
            BUS_ID="{target_bus}"
            SYS_PATH="/sys/bus/usb/devices/$BUS_ID/usbip_sockfd"

            echo "[Watchdog] Monitoring $SYS_PATH"

            # 1. Wait for active attachment (Socket FD > -1)
            # We check if the file content is NOT "-1"
            while true; do
                if [ -f "$SYS_PATH" ]; then
                    SOCK_FD=$(cat "$SYS_PATH")
                    if [ "$SOCK_FD" != "-1" ]; then
                        echo "[Watchdog] Client ATTACHED (Socket: $SOCK_FD)."
                        break
                    fi
                fi
                sleep 1
            done

            # 2. Wait for detach (Socket FD returns to -1)
            while true; do
                if [ -f "$SYS_PATH" ]; then
                    SOCK_FD=$(cat "$SYS_PATH")
                    if [ "$SOCK_FD" == "-1" ]; then
                        echo "[Watchdog] Client DETACHED. Releasing device..."

                        # Unbind device so Steam Deck takes it back
                        usbip unbind -b $BUS_ID

                        # Kill daemon to reset state
                        pkill usbipd

                        # Trigger udev for immediate UI detection
                        udevadm trigger
                        exit 0
                    fi
                else
                    # Fallback: If sys path is gone, something weird happened, just exit
                    echo "[Watchdog] Device path vanished. Exiting."
                    exit 1
                fi
                sleep 2
            done
            """

            watchdog_path = "/usr/local/bin/sender-watchdog.sh"
            self.run_command(f"{self.exec_cmd} 'cat > {watchdog_path}'", input=watchdog_code)
            self.run_command(f"{self.exec_cmd} 'chmod +x {watchdog_path}'")
            # Run in background
            self.run_command(f"{self.exec_cmd} 'nohup {watchdog_path} > /var/log/watchdog.log 2>&1 &'")
        # ---------------------------------------

        print("\n" + "="*40)
        print(" SENDER IS RUNNING")
        print(" * Watchdog Active: Waiting for Receiver to Attach...")
        print(" * Once attached, if the Receiver stops, the Deck")
        print("   will automatically reclaim the controller.")
        print("="*40)

        if auto_bg:
            print(">> Auto-backgrounding enabled. Exiting script, container remains running.")
            sys.exit(0)

        user_in = input("Type 'bg' to background, or ENTER to stop manually: ").strip().lower()
        if user_in == 'bg':
            print("Running in background. Run this script again to stop it.")
            sys.exit(0)
        else:
            self.stop_container()

    # --- RECEIVER LOGIC ---
    def setup_receiver(self, resume=False, cli_ips=None, auto_bg=False):
        print("\n--- RECEIVER MODE (Bazzite PC) ---")

        if resume:
            print(">> Resuming existing Receiver session (Keep-alive active).")
        else:
            if cli_ips:
                ips = cli_ips
                print(f"Using provided IPs: {ips}")
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

        if auto_bg:
            print(">> Auto-backgrounding enabled. Exiting script, container remains running.")
            sys.exit(0)

        user_in = input().strip().lower()
        if user_in == 'bg':
            print("Running in background. Run this script again to stop it.")
            sys.exit(0)
        else:
            self.stop_container()

def main():
    # --- ARGUMENT PARSING ---
    parser = argparse.ArgumentParser(description="USBIP Container Wrapper")
    parser.add_argument("-m", "--mode", choices=["sender", "receiver", "1", "2"], help="Mode: sender (1) or receiver (2)")
    parser.add_argument("-i", "--ips", help="Comma-separated IPs (Receiver mode only)")
    parser.add_argument("--bg", action="store_true", help="Automatically run in background (detach) after setup")
    args = parser.parse_args()

    tool = ContainerUSBIP()
    tool.check_root()

    print("USBIP Container Wrapper (Persistent, Auto-Reconnect, Multi-Deck)")

    # CHECK FOR EXISTING SESSION
    if tool.is_container_running():
        active_mode = tool.get_active_mode()
        if active_mode:
            print(f"\n[!] Existing {active_mode.upper()} session detected.")
            # If args provided, warn user, but default to resuming
            if args.mode or args.ips:
                print("    (Ignoring flags because session is already active)")

            if active_mode == 'sender':
                tool.setup_sender(resume=True, auto_bg=args.bg)
            elif active_mode == 'receiver':
                tool.setup_receiver(resume=True, auto_bg=args.bg)
            return
        else:
            print("[!] Container running but no active session detected. Cleaning up...")
            tool.stop_container()

    # DETERMINE MODE
    mode_selection = ""
    if args.mode:
        if args.mode in ['sender', '1']: mode_selection = '1'
        elif args.mode in ['receiver', '2']: mode_selection = '2'
    # Implicit Receiver mode if IPs are provided
    elif args.ips:
        mode_selection = '2'
    else:
        print("1. Sender (Steam Deck)")
        print("2. Receiver (Bazzite PC)")
        mode_selection = input("Select Mode (1/2): ").strip()

    try:
        tool.ensure_image_exists()
        tool.start_runtime_container()

        if mode_selection == '1':
            tool.setup_sender(auto_bg=args.bg)
        elif mode_selection == '2':
            cli_ips = [x.strip() for x in args.ips.split(',')] if args.ips else None
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
