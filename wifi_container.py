#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback

# --- Configuration ---
CONTAINER_NAME = "vpn-test"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "vpn-ap-ready" # Cached image with tools installed
HOST_WG_CONF = "/tmp/wg-host.conf"
NM_CONN_NAME = "wg-vpn-test"

# AP Configuration
AP_GATEWAY_IP = "192.168.50.1"
AP_DHCP_RANGE = "192.168.50.10,192.168.50.50,12h"

class ContainerVPN:
    def __init__(self):
        self.wifi_interface = self.get_active_wifi_interface()
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"

    def run_command(self, cmd, shell=False, check=True, input=None):
        """Run a shell command and return stdout."""
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

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def get_active_wifi_interface(self):
        try:
            output = self.run_command("nmcli -t -f DEVICE,TYPE,STATE device")
            for line in output.split('\n'):
                if ":wifi:" in line:
                    return line.split(':')[0]
            output = self.run_command("iw dev | grep Interface", shell=True)
            if output:
                return output.split()[-1]
        except Exception:
            pass
        return "wlp9s0"

    def scan_wifi(self):
        print(f"Scanning networks on {self.wifi_interface}...")
        try:
            self.run_command(f"nmcli device wifi rescan ifname {self.wifi_interface}", check=False)
            time.sleep(2)
            output = self.run_command("nmcli -t -f SSID,SIGNAL,SECURITY device wifi list")
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
        except Exception:
            return []

    def cleanup(self):
        print("\n\n--- Cleaning Up ---")
        self.run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command("nmcli connection delete wg-host", check=False)

        if os.path.exists(HOST_WG_CONF):
            try:
                os.remove(HOST_WG_CONF)
            except OSError:
                pass

        print("Stopping container (Returns WiFi card)...")
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        print("Restoring Host Network Manager...")
        try:
            # Re-detect interface in case it changed
            iface = self.get_active_wifi_interface()
            self.run_command(f"nmcli device connect {iface}", check=False)
            print("Done. Host internet should return shortly.")
        except Exception:
            print("Warning: Could not auto-trigger WiFi reconnect.")

    def image_exists(self, image_name):
        try:
            res = self.run_command(f"podman images -q {image_name}", check=False)
            return bool(res)
        except:
            return False

    def initialize_container(self):
        print("\n[1/6] Initializing Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # Check for cached image
        use_image = BASE_IMAGE
        needs_install = True

        if self.image_exists(CUSTOM_IMAGE):
            print(f"      Found cached image '{CUSTOM_IMAGE}'. Offline mode supported.")
            use_image = CUSTOM_IMAGE
            needs_install = False
        else:
            print(f"      Cached image not found. Using '{BASE_IMAGE}'. Internet required to install tools.")

        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--cap-add=NET_ADMIN --cap-add=NET_RAW "
            "--sysctl net.ipv4.ip_forward=1 "
            "--dns 8.8.8.8 "
            f"{use_image} sleep infinity"
        )

        if needs_install:
            print("[2/6] Installing tools...")
            # Retry logic for flaky host internet connection
            max_retries = 3
            for i in range(max_retries):
                try:
                    self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw wireguard-tools iptables hostapd dnsmasq")
                    break
                except subprocess.CalledProcessError:
                    if i < max_retries - 1:
                        print(f"      Install failed (Host Internet not ready?). Retrying {i+1}/{max_retries} in 5s...")
                        time.sleep(5)
                    else:
                        print("      ERROR: Failed to install tools. Please ensure Host has Internet.")
                        raise

            # Commit image so we don't need internet next time
            print(f"      Caching tools to '{CUSTOM_IMAGE}' for future offline use...")
            self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        else:
            print("[2/6] Tools already installed (Cached).")

    def move_wifi_card(self):
        print(f"[3/6] Moving {self.wifi_interface} to container...")
        self.run_command(f"nmcli device disconnect {self.wifi_interface}")
        ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
        self.run_command(f"iw phy phy0 set netns {ctr_pid}")

    def setup_client_mode(self, ssid, password):
        print(f"[4/6] Connecting to '{ssid}' (Client Mode)...")

        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")

        psk_cmd = f"wpa_passphrase \"{ssid}\" \"{password}\" > /etc/wpa_supplicant.conf"
        self.run_command(f"{self.exec_cmd} '{psk_cmd}'")
        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf -s'")

        print("      Requesting IP via DHCP...")
        self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        # Routing Logic (Python Parsing)
        gateway_ip = "172.16.16.16" # Default Fallback
        try:
            # Get raw route info from container
            route_output = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0'")
            if route_output:
                for line in route_output.split('\n'):
                    # Look for subnet line (e.g., 172.16.16.0/24 ... src ...)
                    if 'src' in line and '/' in line:
                        parts = line.split()
                        subnet_cidr = parts[0] # 172.16.16.0/24
                        subnet = subnet_cidr.split('/')[0] # 172.16.16.0

                        # Reconstruct gateway ending in .16 based on subnet
                        octets = subnet.split('.')
                        if len(octets) == 4:
                            gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.16"
                        break
        except Exception as e:
            print(f"Warning: Failed to auto-detect gateway, using fallback {gateway_ip}. Error: {e}")

        print(f"      Setting default gateway to {gateway_ip}...")
        self.run_command(f"{self.exec_cmd} 'ip route del default || true'")
        self.run_command(f"{self.exec_cmd} 'ip route add default via {gateway_ip} dev wlan0'")

    def setup_ap_mode(self, ssid, password):
        print(f"[4/6] Starting Hotspot '{ssid}' (AP Mode - 5GHz 80MHz AX)...")

        # 1. Setup Interface
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan0'")

        # 2. Config hostapd
        # Config optimized for 5GHz 80MHz (WiFi 6/AX) on Channel 36
        hostapd_conf = f"""interface=wlan0
ssid={ssid}
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
ht_capab=[HT40+]
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
he_oper_chwidth=1
he_oper_centr_freq_seg0_idx=42
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""

        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)

        # 3. Start hostapd in background
        print("      Starting hostapd...")
        self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")

        # 4. Config & Start dnsmasq (DHCP)
        print("      Starting DHCP server...")
        dnsmasq_conf = f"""interface=wlan0
dhcp-range={AP_DHCP_RANGE}
dhcp-option=3,{AP_GATEWAY_IP}
dhcp-option=6,8.8.8.8"""

        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

    def setup_wireguard(self):
        print("[5/6] Configuring WireGuard VPN...")

        # Generate Keys
        ctr_priv = self.run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        ctr_pub = self.run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=ctr_priv).strip()
        host_priv = self.run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        host_pub = self.run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=host_priv).strip()

        ctr_bridge_ip = self.run_command(f"podman inspect -f '{{{{.NetworkSettings.IPAddress}}}}' {CONTAINER_NAME}")

        # Container Config (Server)
        wg0_conf = f"""[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = {ctr_priv}

[Peer]
PublicKey = {host_pub}
AllowedIPs = 10.13.13.2/32
"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wireguard/wg0.conf'", shell=True, input=wg0_conf)

        # Start WG & NAT
        self.run_command(f"{self.exec_cmd} 'wg-quick up wg0'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

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
        if os.path.exists(HOST_WG_CONF):
            try:
                os.remove(HOST_WG_CONF)
            except OSError:
                pass

        with open(HOST_WG_CONF, "w") as f:
            f.write(wg_host_conf)

        # Import to NetworkManager
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command("nmcli connection delete wg-host", check=False)
        self.run_command(f"nmcli connection import type wireguard file {HOST_WG_CONF}")
        self.run_command(f"nmcli connection modify wg-host connection.id {NM_CONN_NAME}")
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

    def show_status(self, mode):
        lan_ip = "N/A"
        try:
            lan_ip = self.run_command(f"{self.exec_cmd} 'ip -4 addr show wlan0 | grep inet | awk \"{{print \\$2}}\"'").split('/')[0]
        except:
            pass

        print("\n" + "="*40)
        print(f"   CONNECTION ESTABLISHED ({mode})")
        print("="*40)
        print(f"Container WLAN IP:    {lan_ip}")
        print(f"Host VPN IP:          10.13.13.2")
        print(f"Gateway VPN IP:       10.13.13.1")
        if mode == "AP Mode":
            print(f"SSID:                 Active")
            print(f"DHCP Range:           {AP_DHCP_RANGE}")
        else:
            print(f"External Connection:  Routed through Container")
        print("="*40)

def main():
    vpn = ContainerVPN()
    vpn.check_root()

    try:
        print(f"Detected WiFi Interface: {vpn.wifi_interface}")

        # --- Mode Selection ---
        print("\nSelect Mode:")
        print("1. Connect to existing WiFi (Client)")
        print("2. Create WiFi Hotspot (Host/AP)")

        while True:
            mode_choice = input("Enter choice (1 or 2): ")
            if mode_choice in ['1', '2']:
                break

        ssid = ""
        password = ""

        if mode_choice == '1':
            networks = vpn.scan_wifi()
            print("\nAvailable Networks:")
            for idx, net in enumerate(networks):
                print(f"{idx + 1}: {net}")

            while True:
                choice = input("\nSelect Network (Number) or type SSID manually: ")
                if choice.isdigit() and 1 <= int(choice) <= len(networks):
                    ssid = networks[int(choice)-1]
                    break
                elif choice:
                    ssid = choice
                    break
        else:
            ssid = input("\nEnter name for new Hotspot (SSID): ")

        password = input(f"Enter Password for '{ssid}': ")

        # --- Execution ---
        vpn.initialize_container()
        vpn.move_wifi_card()

        if mode_choice == '1':
            vpn.setup_client_mode(ssid, password)
            status_mode = "Client Mode"
        else:
            vpn.setup_ap_mode(ssid, password)
            status_mode = "AP Mode"

        vpn.setup_wireguard()
        vpn.show_status(status_mode)

        input("\nPress ENTER to stop VPN and restore Host WiFi...")

    except KeyboardInterrupt:
        print("\nUser interrupted.")
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
        traceback.print_exc()
    finally:
        vpn.cleanup()

if __name__ == "__main__":
    main()
