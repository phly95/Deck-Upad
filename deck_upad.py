#!/usr/bin/env python3
import argparse
import sys
import signal
import os
import subprocess
import time
import shutil
import socket
import re

from services.host_daemon import HostService
from services.client_agent import ClientService

PID_FILE = "/tmp/deck_upad.pid"
# Global Snapshot: Stores { 'wlan0': 'aa:bb:cc...', 'wlan1': '11:22:33...' }
SYSTEM_WIFI_MAP = {}
ORIGINAL_IFACE = None
ORIGINAL_MAC = None

def run_cmd(cmd, check_output=False):
    if check_output:
        return subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
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

def wait_for_network_restore(timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        if check_internet(): return True
        time.sleep(1)
    return False

# --- HARDWARE IDENTIFICATION ---

def get_interface_mac(iface_name):
    """Reads the permanent MAC address of an interface."""
    try:
        path = f"/sys/class/net/{iface_name}/address"
        if os.path.exists(path):
            with open(path, 'r') as f:
                return f.read().strip().lower()
    except: pass
    return None

def find_interface_by_mac(target_mac):
    """Scans all network interfaces to find the one matching the MAC."""
    if not target_mac: return None
    try:
        if os.path.exists("/sys/class/net"):
            for iface in os.listdir("/sys/class/net"):
                mac = get_interface_mac(iface)
                if mac == target_mac:
                    return iface
    except: pass
    return None

def capture_system_state():
    """
    Scans ALL wireless interfaces and records their Name->MAC mapping.
    This runs at startup to establish the 'Correct' state.
    """
    global SYSTEM_WIFI_MAP
    SYSTEM_WIFI_MAP = {}

    # List all net devices
    try:
        if os.path.exists("/sys/class/net"):
            for iface in os.listdir("/sys/class/net"):
                # Check if wireless
                if os.path.isdir(f"/sys/class/net/{iface}/wireless"):
                    mac = get_interface_mac(iface)
                    if mac:
                        SYSTEM_WIFI_MAP[iface] = mac
    except: pass

    # Double check with iw
    if not SYSTEM_WIFI_MAP:
        try:
            res = run_cmd("iw dev", check_output=True)
            if res and res.stdout:
                current_iface = None
                for line in res.stdout.decode().splitlines():
                    if "Interface" in line:
                        current_iface = line.split()[1]
                    if "addr" in line and current_iface:
                        mac = line.split()[1].strip().lower()
                        SYSTEM_WIFI_MAP[current_iface] = mac
        except: pass

    if SYSTEM_WIFI_MAP:
        print("[Startup] Captured System WiFi State:")
        for iface, mac in SYSTEM_WIFI_MAP.items():
            print(f"   - {iface} : {mac}")
    else:
        print("[Startup] Warning: No WiFi interfaces detected.")

def get_active_wifi_interface():
    # Helper to just get *one* active interface (legacy fallback)
    if SYSTEM_WIFI_MAP:
        # Prefer ORIGINAL_IFACE if available
        if ORIGINAL_IFACE and ORIGINAL_IFACE in SYSTEM_WIFI_MAP:
            return ORIGINAL_IFACE
        return list(SYSTEM_WIFI_MAP.keys())[0]
    return "wlan0"

def get_driver_for_interface(iface_name):
    if not iface_name: return None
    try:
        res = run_cmd(f"ethtool -i {iface_name}", check_output=True)
        if res and res.stdout:
            for line in res.stdout.decode().splitlines():
                if line.startswith("driver:"):
                    return line.split(":")[1].strip()
    except: pass
    try:
        path = f"/sys/class/net/{iface_name}/device/driver"
        if os.path.exists(path):
            return os.path.basename(os.readlink(path))
    except: pass
    return None

def find_driver_fallback():
    try:
        res = run_cmd("lspci -k", check_output=True)
        if res and res.stdout:
            lines = res.stdout.decode().splitlines()
            for i, line in enumerate(lines):
                if "Network controller" in line or "Wireless" in line:
                    for j in range(1, 4):
                        if i+j < len(lines) and "Kernel driver in use:" in lines[i+j]:
                            return lines[i+j].split(":")[1].strip()
    except: pass
    return None

# --- DRIVER RESET & RESTORE LOGIC ---

def reset_wifi_driver():
    """
    Identifies the driver used by the primary interface and resets it.
    """
    print("[Cleanup] Analyzing WiFi Hardware state...")

    driver = None
    if ORIGINAL_IFACE: driver = get_driver_for_interface(ORIGINAL_IFACE)
    if not driver and SYSTEM_WIFI_MAP:
        for iface in SYSTEM_WIFI_MAP.keys():
            driver = get_driver_for_interface(iface)
            if driver: break

    if not driver:
        driver = find_driver_fallback()

    if not driver:
        print("   >> Could not detect WiFi driver. Skipping hardware reset.")
        return False

    print(f"   >> Detected Driver: {driver}")

    try:
        if "ath11k" in driver:
            print(f"   >> Performing OLED/Qualcomm Reset ({driver})...")
            run_cmd(f"modprobe -r {driver}")
            time.sleep(1)
            run_cmd(f"modprobe {driver}")

        elif "rtw88" in driver:
            print(f"   >> Performing LCD/Realtek Reset ({driver})...")
            run_cmd("modprobe -r rtw88_8822ce")
            run_cmd("modprobe -r rtw88_pci")
            run_cmd(f"modprobe -r {driver}")
            time.sleep(1)
            run_cmd("modprobe rtw88_pci")
            run_cmd("modprobe rtw88_8822ce")

        else:
            print(f"   >> Performing Generic Driver Reset ({driver})...")
            run_cmd(f"modprobe -r {driver}")
            time.sleep(1)
            run_cmd(f"modprobe {driver}")

        print("   >> Waiting for hardware to initialize...")
        for _ in range(15):
            found = False
            if os.path.exists("/sys/class/net"):
                for iface in os.listdir("/sys/class/net"):
                    if iface.startswith("wlan") or iface.startswith("wlp"):
                        found = True
            if found: break
            time.sleep(1)
        return True

    except Exception as e:
        print(f"   [Warning] Driver reset failed: {e}")
        return False

def smart_rename_interface(target_mac, desired_name):
    """
    Finds the interface with target_mac and renames it to desired_name.
    """
    if not target_mac or not desired_name: return None

    current_name = find_interface_by_mac(target_mac)
    if not current_name:
        return None # Card not found (yet)

    if current_name == desired_name:
        return current_name

    print(f"[Cleanup] Renaming drift: {current_name} ({target_mac}) -> {desired_name}...")

    # Check for collision
    collision_mac = get_interface_mac(desired_name)
    if collision_mac:
        print(f"   [Notice] Name {desired_name} taken by {collision_mac}. Moving squatter...")
        run_cmd(f"ip link set {desired_name} down")
        run_cmd(f"ip link set {desired_name} name {desired_name}_tmp")
        run_cmd(f"ip link set {desired_name}_tmp up")

    try:
        run_cmd(f"ip link set {current_name} down")
        res = run_cmd(f"ip link set {current_name} name {desired_name}", check_output=True)
        if res.returncode != 0:
            print(f"   [Warning] Rename failed: {res.stderr.decode().strip()}")
            return current_name
        run_cmd(f"ip link set {desired_name} up")
        return desired_name
    except Exception as e:
        print(f"   [Warning] Rename exception: {e}")
        return current_name

# --- STORAGE FIX ---
def configure_storage_location():
    if os.geteuid() != 0: return
    VAR_PATH = "/var/lib/containers"
    sudo_user = os.environ.get('SUDO_USER')
    if not sudo_user: return

    user_home = os.path.expanduser(f"~{sudo_user}")
    target_storage = os.path.join(user_home, "deck-upad-container-storage")
    config_path = os.path.join(target_storage, "storage.conf")

    needs_migration = False
    is_symlinked = os.path.islink(VAR_PATH)

    if not is_symlinked:
        try:
            stats = os.statvfs("/var")
            free_gb = (stats.f_bavail * stats.f_frsize) / (1024**3)
            if free_gb < 5: needs_migration = True
        except: pass

    if needs_migration:
        print(f"[STORAGE FIX] Migrating Podman storage to {target_storage}...")
        run_cmd("podman stop -a")
        run_cmd("podman system reset --force")
        time.sleep(1)
        if os.path.exists(VAR_PATH):
            try: shutil.rmtree(VAR_PATH)
            except: run_cmd(f"rm -rf {VAR_PATH}")
        if not os.path.exists(target_storage):
            os.makedirs(target_storage, exist_ok=True)
            try:
                uid = int(os.environ.get('SUDO_UID'))
                gid = int(os.environ.get('SUDO_GID'))
                os.chown(target_storage, uid, gid)
            except: pass
        try: os.symlink(target_storage, VAR_PATH)
        except: pass

    if os.path.islink(VAR_PATH):
        if shutil.which("fuse-overlayfs"):
            driver_config = """[storage]\ndriver = "overlay"\n[storage.options.overlay]\nmount_program = "/usr/bin/fuse-overlayfs"\n"""
        else:
            driver_config = """[storage]\ndriver = "vfs"\n"""
        if not os.path.exists(target_storage): os.makedirs(target_storage, exist_ok=True)
        try:
            with open(config_path, "w") as f: f.write(driver_config)
            os.environ["CONTAINERS_STORAGE_CONF"] = config_path
        except: pass

# ----------------------------------------

def perform_aggressive_cleanup(force=False):
    global ORIGINAL_IFACE, ORIGINAL_MAC
    if not force and not os.path.exists(PID_FILE): return

    print("\n[Cleanup] Starting Cleanup Routine...")
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

    # 1. Stop Containers & Bridges
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

    # --- PHASE 1: SMART SOFT RESTORE ---
    print("[Cleanup] Waiting for WiFi hardware to return from container...")

    # Wait for the card with our MAC to appear (Name might be drifted)
    found_name = None
    if ORIGINAL_MAC:
        for _ in range(10):
            found_name = find_interface_by_mac(ORIGINAL_MAC)
            if found_name: break
            time.sleep(0.5)

    if found_name and ORIGINAL_IFACE:
        # If the card is back but named wrong (e.g. wlan9), fix it NOW
        if found_name != ORIGINAL_IFACE:
            print(f"   >> Interface drift detected ({found_name}). Correcting to {ORIGINAL_IFACE}...")
            corrected_name = smart_rename_interface(ORIGINAL_MAC, ORIGINAL_IFACE)
            if corrected_name: found_name = corrected_name

    # Try restore on the corrected name
    target_iface = found_name or ORIGINAL_IFACE or "wlan0"

    print(f"[Cleanup] Attempting Soft Restore on {target_iface}...")
    run_cmd("rfkill unblock wifi")
    run_cmd("rfkill unblock all")
    run_cmd(f"nmcli device set {target_iface} managed yes")
    run_cmd(f"nmcli device set {target_iface} autoconnect yes")

    if wait_for_network_restore(timeout=5):
        print("[Cleanup] Network restored gracefully.")
        return

    # --- PHASE 2: HARDWARE RESET (The Nuclear Option) ---
    print("[Cleanup] Soft restore failed. Initiating Driver Reset...")

    run_cmd("systemctl stop NetworkManager")
    run_cmd("pkill wpa_supplicant")

    was_reset = reset_wifi_driver()

    # --- PHASE 3: RECONSTRUCTION ---
    # After reset, names are scrambled again. Fix them based on Snapshot.
    if was_reset and SYSTEM_WIFI_MAP:
        print("[Cleanup] Reconstructing Interface Map...")
        for original_name, mac in SYSTEM_WIFI_MAP.items():
            smart_rename_interface(mac, original_name)

    # Use the restored name
    final_iface = ORIGINAL_IFACE if (ORIGINAL_IFACE and ORIGINAL_MAC) else "wlan0"

    print(f"   >> Restarting Services for {final_iface}...")
    run_cmd(f"ip link set {final_iface} down")
    run_cmd(f"ip addr flush dev {final_iface}")
    run_cmd(f"iw dev {final_iface} set type managed")
    run_cmd(f"ip link set {final_iface} up")

    run_cmd("systemctl restart wpa_supplicant")
    run_cmd("systemctl start NetworkManager")
    time.sleep(2)

    run_cmd(f"nmcli device set {final_iface} managed yes")
    run_cmd(f"nmcli device set {final_iface} autoconnect yes")

    if not wait_for_network_restore(timeout=10):
        print("[Cleanup] Warning: Could not automatically reconnect.")

def write_pid_file():
    try:
        with open(PID_FILE, 'w') as f: f.write(str(os.getpid()))
    except: pass

def remove_pid_file():
    if os.path.exists(PID_FILE):
        try: os.remove(PID_FILE)
        except: pass

def main():
    global ORIGINAL_IFACE, ORIGINAL_MAC
    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    parser.add_argument("--role", choices=["host", "client"], required=False)
    parser.add_argument("--ssid", default="DeckUpad")
    parser.add_argument("--password", default="DeckUpad123")
    parser.add_argument("--channel", default=165, type=int)
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax")
    parser.add_argument("--country", default="US")
    parser.add_argument("--force-clean", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true", help="Run cleanup routine and exit")

    parser.add_argument("--p2p-iface", help="Explicit interface for P2P/Hotspot")
    parser.add_argument("--internet-iface", default="none", help="Interface for Internet")
    parser.add_argument("--internet-ssid", help="SSID for upstream internet")
    parser.add_argument("--internet-pass", help="Password for upstream internet")

    # New Flag for Inverse Topology (Deck acts as AP, PC connects)
    parser.add_argument("--inverse", action="store_true", help="Invert Network Topology")

    args = parser.parse_args()

    # 1. CAPTURE SYSTEM SNAPSHOT
    capture_system_state()

    detected = get_active_wifi_interface()
    ORIGINAL_IFACE = args.p2p_iface if args.p2p_iface else detected
    if not ORIGINAL_IFACE: ORIGINAL_IFACE = "wlan0"

    ORIGINAL_MAC = get_interface_mac(ORIGINAL_IFACE)
    if ORIGINAL_MAC:
        # print(f"[Startup] Tracking Hardware: {ORIGINAL_IFACE} [{ORIGINAL_MAC}]")
        pass

    # Run Storage Fix
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
        if service:
            try: service.stop()
            except: pass
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.role == "host":
            print(f"--- LAUNCHING HOST DAEMON (Inverse: {args.inverse}) ---")
            service = HostService()
            service.start(
                ssid=args.ssid,
                password=args.password,
                channel=args.channel,
                wifi_mode=args.wifi_mode,
                country=args.country,
                p2p_iface=ORIGINAL_IFACE,
                internet_iface=args.internet_iface,
                internet_ssid=args.internet_ssid,
                internet_pass=args.internet_pass,
                inverse=args.inverse
            )
        else:
            print(f"--- LAUNCHING CLIENT AGENT (Inverse: {args.inverse}) ---")
            service = ClientService()
            service.start(
                ssid=args.ssid,
                password=args.password,
                country=args.country,
                inverse=args.inverse
            )
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Script crashed: {e}")
        if service:
            try: service.stop()
            except: pass
    finally:
        perform_aggressive_cleanup(force=True)
        remove_pid_file()

if __name__ == "__main__":
    main()
