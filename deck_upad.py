#!/usr/bin/env python3
import argparse
import sys
import signal
import os
import subprocess
import time
import shutil
import socket

from services.host_daemon import HostService
from services.client_agent import ClientService

PID_FILE = "/tmp/deck_upad.pid"

def run_cmd(cmd, check_output=False):
    if check_output:
        return subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    else:
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return None

def robust_podman_rm(containers):
    res = run_cmd(f"podman rm -f {containers}", check_output=True)
    if res.returncode != 0:
        err_msg = res.stderr.decode()
        if "migrate" in err_msg or "invalid internal status" in err_msg:
            print(f"[Cleanup] Podman state inconsistent. Repairing (podman system migrate)...")
            run_cmd("podman system migrate")
            run_cmd(f"podman rm -f {containers}")

def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def wait_for_network_restore(timeout=15):
    print("[Startup] Verifying Internet Connectivity...")
    start = time.time()
    while time.time() - start < timeout:
        if check_internet(): return True
        time.sleep(1)
    print("[Startup] Warning: Internet not detected.")
    return False

# --- AUTOMATIC STORAGE CONFIGURATION ---
def configure_storage_location():
    """
    1. Migrates storage from small /var to /home if needed.
    2. Injects a custom storage.conf to fix OverlayFS on SteamOS /home (casefold).
    """
    if os.geteuid() != 0:
        return

    VAR_PATH = "/var/lib/containers"
    sudo_user = os.environ.get('SUDO_USER')
    if not sudo_user:
        return

    user_home = os.path.expanduser(f"~{sudo_user}")
    target_storage = os.path.join(user_home, "deck-upad-container-storage")
    config_path = os.path.join(target_storage, "storage.conf")

    # --- STEP 1: CHECK DISK SPACE & MIGRATE IF NEEDED ---
    needs_migration = False

    # Check if we are already symlinked
    is_symlinked = os.path.islink(VAR_PATH)

    # If not symlinked, check space
    if not is_symlinked:
        try:
            stats = os.statvfs("/var")
            free_gb = (stats.f_bavail * stats.f_frsize) / (1024**3)
            if free_gb < 5:
                needs_migration = True
                print("="*60)
                print(f"[STORAGE ALERT] /var has only {free_gb:.2f} GB free.")
                print("[AUTO-FIX] Moving Podman storage to /home to prevent full disk...")
                print("="*60)
        except: pass

    if needs_migration:
        # Stop and Nuke
        run_cmd("podman stop -a")
        run_cmd("podman system reset --force")
        time.sleep(2)

        # Remove old folder
        if os.path.exists(VAR_PATH):
            try: shutil.rmtree(VAR_PATH)
            except: run_cmd(f"rm -rf {VAR_PATH}")

        # Create Target
        if not os.path.exists(target_storage):
            os.makedirs(target_storage, exist_ok=True)
            try:
                uid = int(os.environ.get('SUDO_UID'))
                gid = int(os.environ.get('SUDO_GID'))
                os.chown(target_storage, uid, gid)
            except: pass

        # Link
        try:
            os.symlink(target_storage, VAR_PATH)
            print("[AUTO-FIX] Symlink created successfully.")
        except Exception as e:
            print(f"[CRITICAL] Failed to link storage: {e}")
            sys.exit(1)

    # --- STEP 2: INJECT COMPATIBLE STORAGE CONFIG ---
    # Even if we didn't migrate just now, if we are running from /home (symlinked),
    # we MUST fix the storage driver because kernel overlayfs fails on /home (ext4 casefold).

    if os.path.islink(VAR_PATH):
        # Determine best driver
        if shutil.which("fuse-overlayfs"):
            # Preferred: fuse-overlayfs
            driver_config = """
[storage]
driver = "overlay"
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
"""
        else:
            # Fallback: vfs (slow but guaranteed to work)
            print("[Startup] fuse-overlayfs not found. Falling back to VFS driver.")
            driver_config = """
[storage]
driver = "vfs"
"""

        # Write config if missing or force update
        # We write it to the target storage folder
        if not os.path.exists(target_storage):
             os.makedirs(target_storage, exist_ok=True)

        try:
            with open(config_path, "w") as f:
                f.write(driver_config)

            # CRITICAL: Tell Podman to use this config
            os.environ["CONTAINERS_STORAGE_CONF"] = config_path
            # print(f"[Startup] Applied compatibility config: {config_path}")
        except Exception as e:
            print(f"[Startup] Warning: Failed to write storage config: {e}")

# ----------------------------------------

def perform_aggressive_cleanup(force=False):
    if not force and not os.path.exists(PID_FILE): return

    print("[Startup] Cleaning up previous session state...")
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f: old_pid = int(f.read().strip())
            if old_pid != os.getpid():
                try: os.kill(old_pid, signal.SIGKILL)
                except: pass
        except: pass
        try: os.remove(PID_FILE)
        except: pass

    containers = (
        "wifi-bridge usbip-sidecar stream-receiver "
        "wifi-bridge-builder usbip-sidecar-builder stream-receiver-builder "
        "deck-upad-test-rec"
    )

    run_cmd(f"podman stop -t 0 {containers}")
    robust_podman_rm(containers)

    run_cmd("nmcli connection down veth-host-conn")
    run_cmd("nmcli connection delete veth-host-conn")
    run_cmd("ip link delete veth-host")

    if shutil.which("firewall-cmd"):
        ports = "2000:65535"
        run_cmd(f"firewall-cmd --remove-port={ports}/udp")
        run_cmd(f"firewall-cmd --remove-port={ports}/tcp")

    run_cmd("nmcli device set wlan0 managed yes")
    run_cmd("nmcli device connect wlan0")

    wait_for_network_restore()

def write_pid_file():
    try:
        with open(PID_FILE, 'w') as f: f.write(str(os.getpid()))
    except: pass

def remove_pid_file():
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

def main():
    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    parser.add_argument("--role", choices=["host", "client"], required=False)
    parser.add_argument("--ssid", default="DeckUpad")
    parser.add_argument("--password", default="DeckUpad123")
    parser.add_argument("--channel", default=165, type=int)
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax")
    parser.add_argument("--country", default="US")
    parser.add_argument("--force-clean", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true", help="Run cleanup routine and exit")

    parser.add_argument("--p2p-iface", help="Explicit interface for P2P/Hotspot (e.g., wlan0)")
    parser.add_argument("--internet-iface", default="none", help="Interface for Internet (e.g., eth0 or wlan1)")
    parser.add_argument("--internet-ssid", help="SSID for upstream internet (if using WiFi)")
    parser.add_argument("--internet-pass", help="Password for upstream internet (if using WiFi)")

    args = parser.parse_args()

    # 1. Run Storage Fix & Config Injection
    configure_storage_location()

    should_force = args.force_clean or args.cleanup_only
    perform_aggressive_cleanup(force=should_force)

    if args.cleanup_only:
        print("[Startup] Cleanup Complete. Exiting.")
        sys.exit(0)

    if not args.role:
        parser.error("the following arguments are required: --role")

    write_pid_file()

    service = None

    def signal_handler(sig, frame):
        print("\n[Main] Signal received. Shutting down...")
        if service: service.stop()
        remove_pid_file()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.role == "host":
            print("--- LAUNCHING HOST DAEMON ---")
            service = HostService()
            service.start(
                ssid=args.ssid,
                password=args.password,
                channel=args.channel,
                wifi_mode=args.wifi_mode,
                country=args.country,
                p2p_iface=args.p2p_iface,
                internet_iface=args.internet_iface,
                internet_ssid=args.internet_ssid,
                internet_pass=args.internet_pass
            )
        else:
            print("--- LAUNCHING CLIENT AGENT ---")
            service = ClientService()
            service.start(ssid=args.ssid, password=args.password, country=args.country)
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Script crashed: {e}")
        if service:
            try: service.stop()
            except: pass
        perform_aggressive_cleanup(force=True)
        sys.exit(1)
    finally:
        remove_pid_file()

if __name__ == "__main__":
    main()
