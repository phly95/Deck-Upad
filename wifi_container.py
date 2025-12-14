#!/usr/bin/env python3
import subprocess
import time
import sys
import shutil
import re
import signal
import os
import shlex
import traceback

# Configuration
CONTAINER_NAME = "vpn-test"
IMAGE = "alpine:latest"
HOST_WG_CONF = "/tmp/wg-host.conf"
NM_CONN_NAME = "wg-vpn-test"

def run_command(cmd, shell=False, check=True, input=None):
    """Run a shell command and return stdout."""
    # Fix: Split string commands into list if shell is False to avoid FileNotFoundError
    if not shell and isinstance(cmd, str):
        cmd = shlex.split(cmd)

    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            input=input
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if check:
            raise e
        return None

def check_root():
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo).")
        sys.exit(1)

def get_active_wifi_interface():
    """Detects the active wireless interface on the host."""
    try:
        # Get device that is wifi and connected or disconnected
        output = run_command("nmcli -t -f DEVICE,TYPE,STATE device")
        for line in output.split('\n'):
            if ":wifi:" in line:
                dev = line.split(':')[0]
                return dev

        # Fallback to iw
        output = run_command("iw dev | grep Interface", shell=True)
        if output:
            return output.split()[-1]

    except Exception:
        pass
    return "wlp9s0" # Default fallback from user history

def scan_wifi(interface):
    """Scans for SSIDs using nmcli before moving the card."""
    print(f"Scanning for networks on {interface}...")
    try:
        # Rescan first
        run_command(f"nmcli device wifi rescan ifname {interface}", check=False)
        time.sleep(2)
        output = run_command("nmcli -t -f SSID,SIGNAL,SECURITY device wifi list")
        networks = []
        seen = set()
        for line in output.split('\n'):
            parts = line.split(':')
            if len(parts) >= 1:
                ssid = parts[0]
                if ssid and ssid not in seen:
                    networks.append(ssid)
                    seen.add(ssid)
        return networks
    except Exception as e:
        print(f"Scan failed: {e}")
        return []

def cleanup():
    """Restores the host network configuration."""
    print("\n\n--- Cleaning Up ---")

    # 1. Bring down Host VPN
    print("Removing Host VPN connection...")
    run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
    run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
    run_command("nmcli connection delete wg-host", check=False)

    # Remove the temporary config file if it exists
    if os.path.exists(HOST_WG_CONF):
        try:
            os.remove(HOST_WG_CONF)
        except OSError:
            pass

    # 2. Stop Container (Returns WiFi Card to Host)
    print("Stopping container (Returns WiFi card to Host)...")
    run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
    run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

    # 3. Reconnect Host WiFi
    print("Restoring Host Network Manager...")
    try:
        interface = get_active_wifi_interface()
        run_command(f"nmcli device connect {interface}", check=False)
        print("Done. Host internet should return shortly.")
    except Exception:
        print("Warning: Could not auto-trigger WiFi reconnect.")

    sys.exit(0)

def main():
    check_root()
    # Note: We rely on the try/finally block to handle signals now

    try:
        wifi_interface = get_active_wifi_interface()
        print(f"Detected WiFi Interface: {wifi_interface}")

        # --- 1. Network Selection ---
        networks = scan_wifi(wifi_interface)

        print("\nAvailable Networks:")
        for idx, ssid in enumerate(networks):
            print(f"{idx + 1}: {ssid}")

        while True:
            choice = input("\nSelect Network (Number) or type SSID manually: ")
            if choice.isdigit() and 1 <= int(choice) <= len(networks):
                target_ssid = networks[int(choice)-1]
                break
            elif choice:
                target_ssid = choice
                break

        target_pass = input(f"Password for '{target_ssid}': ")

        # --- 2. Container Setup ---
        print("\n[1/6] initializing Container...")
        # Remove old if exists
        run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # Run Container
        run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--cap-add=NET_ADMIN --cap-add=NET_RAW "
            "--sysctl net.ipv4.ip_forward=1 "
            "--dns 8.8.8.8 "
            f"{IMAGE} sleep infinity"
        )

        print("[2/6] Installing tools (using Host Internet)...")
        run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw wireguard-tools iptables")

        # --- 3. Hardware Handoff ---
        print(f"[3/6] Moving {wifi_interface} to container...")
        run_command(f"nmcli device disconnect {wifi_interface}")

        ctr_pid = run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")

        run_command(f"iw phy phy0 set netns {ctr_pid}")

        # --- 4. WiFi Connection Inside Container ---
        print(f"[4/6] Connecting to '{target_ssid}' inside container...")

        exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"

        # Setup Interface
        run_command(f"{exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        run_command(f"{exec_cmd} 'ip link set wlan0 up'")

        # Generate Config
        psk_cmd = f"wpa_passphrase \"{target_ssid}\" \"{target_pass}\" > /etc/wpa_supplicant.conf"
        run_command(f"{exec_cmd} '{psk_cmd}'")

        # Connect
        run_command(f"{exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf -s'")

        # DHCP
        print("      Requesting IP...")
        run_command(f"{exec_cmd} 'udhcpc -i wlan0'")

        # Fix Routing
        try:
            gateway_ip = run_command(f"{exec_cmd} \"ip route show | grep 'dev wlan0' | grep 'src' | head -n 1 | awk '{{print \\$1}}' | sed 's/0\\/.*//' | awk -F. '{{print \\$1\\\".\\\"\\$2\\\".\\\"\\$3\\\".16}}'\"")
            if not gateway_ip or len(gateway_ip) < 7:
                 gateway_ip = "172.16.16.16"
        except:
            gateway_ip = "172.16.16.16"

        # Apply Routing
        run_command(f"{exec_cmd} 'ip route del default || true'")
        run_command(f"{exec_cmd} 'ip route add default via {gateway_ip} dev wlan0'")

        # --- 5. WireGuard Setup ---
        print("[5/6] Configuring WireGuard VPN...")

        # Generate Keys
        # Removed .encode() because run_command uses text=True
        ctr_priv = run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        ctr_pub = run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=ctr_priv).strip()
        host_priv = run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        host_pub = run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=host_priv).strip()

        ctr_bridge_ip = run_command(f"podman inspect -f '{{{{.NetworkSettings.IPAddress}}}}' {CONTAINER_NAME}")

        # Container Config (Server)
        wg0_conf = f"""[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = {ctr_priv}

[Peer]
PublicKey = {host_pub}
AllowedIPs = 10.13.13.2/32
"""
        # Removed .encode() because run_command uses text=True
        run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wireguard/wg0.conf'", shell=True, input=wg0_conf)

        # Start WG & NAT
        run_command(f"{exec_cmd} 'wg-quick up wg0'")
        run_command(f"{exec_cmd} 'iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE'")
        run_command(f"{exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

        # Host Config (Client)
        print("[6/6] Connecting Host to VPN...")
        wg_host_conf = f"""[Interface]
Address = 10.13.13.2/24
PrivateKey = {host_priv}
DNS = 8.8.8.8

[Peer]
PublicKey = {ctr_pub}
Endpoint = {ctr_bridge_ip}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        # FIX: Force remove existing config file if it exists to prevent permission errors
        if os.path.exists(HOST_WG_CONF):
            try:
                os.remove(HOST_WG_CONF)
            except OSError:
                print(f"Warning: Could not remove old config at {HOST_WG_CONF}. Overwriting might fail.")

        with open(HOST_WG_CONF, "w") as f:
            f.write(wg_host_conf)

        # Import to NetworkManager
        run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        run_command("nmcli connection delete wg-host", check=False)
        run_command(f"nmcli connection import type wireguard file {HOST_WG_CONF}")
        run_command(f"nmcli connection modify wg-host connection.id {NM_CONN_NAME}")
        run_command(f"nmcli connection up {NM_CONN_NAME}")

        # --- 6. Success Report ---
        lan_ip = run_command(f"{exec_cmd} 'ip -4 addr show wlan0 | grep inet | awk \"{{print \\$2}}\"'").split('/')[0]

        print("\n" + "="*40)
        print("   CONNECTION ESTABLISHED")
        print("="*40)
        print(f"LAN IP (Container):   {lan_ip}")
        print(f"Host VPN IP:          10.13.13.2")
        print(f"Gateway VPN IP:       10.13.13.1")
        print(f"External Connection:  Routed through Container")
        print("="*40)

        input("\nPress ENTER to stop VPN and restore Host WiFi...")

    except KeyboardInterrupt:
        print("\nUser interrupted.")
    except Exception as e:
        print(f"\nCRITICAL ERROR: Script crashed -> {e}")
        print("Automatically restoring WiFi settings...")
        traceback.print_exc()
    finally:
        # This guarantees cleanup runs on crash, interrupt, or normal exit
        cleanup()

if __name__ == "__main__":
    main()
