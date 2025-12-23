#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import json
import re

# --- Configuration ---
CONTAINER_NAME = "wifi-bridge"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "wifi-bridge-ready"
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"
STATE_FILE = "wifi_session.json"

# --- Network Config ---
# For Client Mode (NAT + Reflector)
IP_CTR_NAT = "10.13.13.1"
IP_HOST_NAT = "10.13.13.2"

# For AP Mode (Bridged)
AP_GATEWAY_IP = "192.168.50.1"
AP_DHCP_RANGE = "192.168.50.10,192.168.50.100,12h"

class ContainerNetwork:
    def __init__(self):
        self.wifi_interface = self.get_active_wifi_interface()
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"
        self.shutdown_on_exit = True

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
                raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def is_container_running(self):
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def get_container_ip(self, iface="wlan0"):
        """Extracts the IP assigned to the container's WiFi interface."""
        try:
            out = self.run_command(f"{self.exec_cmd} 'ip -4 addr show {iface}'", check=False)
            if out:
                # Look for 'inet 192.168.x.x/xx'
                match = re.search(r"inet\s+([0-9.]+)/", out)
                if match:
                    return match.group(1)
        except: pass
        return "Unknown"

    # --- Hardware Utils ---
    def get_active_wifi_interface(self):
        try:
            output = self.run_command("nmcli -t -f DEVICE,TYPE,STATE device")
            for line in output.split('\n'):
                if ":wifi:" in line: return line.split(':')[0]
            output = self.run_command("iw dev | grep Interface", shell=True)
            if output: return output.split()[-1]
        except: pass
        return "wlan0"

    def scan_wifi(self):
        print(f"Scanning networks on {self.wifi_interface}...")
        try:
            self.run_command(f"nmcli device wifi rescan ifname {self.wifi_interface}", check=False)
            time.sleep(2)
            output = self.run_command("nmcli -t -f SSID device wifi list")
            networks = []
            seen = set()
            for line in output.split('\n'):
                ssid = line.replace('\\:', ':').strip()
                if ssid and ssid not in seen:
                    networks.append(ssid)
                    seen.add(ssid)
            return networks
        except: return []

    # --- Container Lifecycle ---
    def initialize_container(self):
        print("\n[1/5] Initializing Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        use_image = CUSTOM_IMAGE if self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False) else BASE_IMAGE

        self.run_command(
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--cap-add=NET_ADMIN --cap-add=NET_RAW "
            "--sysctl net.ipv4.ip_forward=1 "
            "--dns 8.8.8.8 "
            f"{use_image} sleep infinity"
        )

        if use_image == BASE_IMAGE:
            print("[2/5] Installing tools (Includes Bridge & Avahi)...")
            self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw iptables hostapd dnsmasq iproute2 bridge-utils avahi avahi-tools dbus")
            print(f"      Caching image to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        else:
            print("[2/5] Using Cached Tools.")

    def move_wifi_card(self):
        print(f"[3/5] Moving {self.wifi_interface} to container...")

        phy = "phy0" 
        try:
            out = self.run_command(f"iw dev {self.wifi_interface} info", check=False)
            if out:
                m = re.search(r"wiphy\s+(\d+)", out)
                if m: phy = f"phy{m.group(1)}"
        except: pass
        print(f"      Detected hardware index: {phy}")

        self.run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
        
        try:
            self.run_command(f"iw phy {phy} set netns {ctr_pid}")
        except Exception as e:
            print(f"\n[ERROR] Failed to move {phy}. Possible causes:")
            print(" - The interface is in use (kill wpa_supplicant on host?)")
            raise e

        time.sleep(1)

        print("      Renaming wireless interface to 'wlan0'...")
        try:
            iw_out = self.run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            found_iface = None
            if iw_out:
                for line in iw_out.split('\n'):
                    if "Interface" in line:
                        found_iface = line.split()[-1]
                        break
            
            if found_iface:
                if found_iface != "wlan0":
                    self.run_command(f"{self.exec_cmd} 'ip link set {found_iface} name wlan0'")
                    print(f"      Success: {found_iface} -> wlan0")
                else:
                    print("      Interface is already named wlan0.")
            else:
                print("      [CRITICAL WARNING] No wireless interface found inside container!")
        except Exception as e:
            print(f"      Warning during rename: {e}")

        return ctr_pid

    # --- Mode: AP (Host) - The "Transparent" Bridge Method ---
    def setup_ap_mode_bridged(self, ssid, password, ctr_pid):
        print(f"[4/5] Configuring Transparent Bridge (Host <-> AP)...")
        
        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        
        self.run_command(f"{self.exec_cmd} 'ip link add name br0 type bridge'")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip link set br0 up'")
        self.run_command(f"{self.exec_cmd} 'brctl addif br0 {VETH_CTR}'")

        self.run_command(f"ip link set {VETH_HOST} up")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev br0'")
        
        nm_cmd = f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 192.168.50.2/24 gw4 {AP_GATEWAY_IP}"
        self.run_command(nm_cmd)
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

        print(f"      Starting AP '{ssid}'...")
        hostapd_conf = f"""interface=wlan0
bridge=br0
ssid={ssid}
country_code=US
hw_mode=g
channel=6
ieee80211n=1
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""
        
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        
        try:
            self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")
        except subprocess.CalledProcessError as e:
            print(f"\n[HOSTAPD ERROR]\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
            raise e

        dnsmasq_conf = f"""interface=br0
dhcp-range={AP_DHCP_RANGE}
dhcp-option=3,{AP_GATEWAY_IP}
dhcp-option=6,8.8.8.8"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

    # --- Mode: Client (Guest) - The "Reflector" Method ---
    def setup_client_mode_with_discovery(self, ssid, password, ctr_pid):
        print(f"[4/5] Connecting to '{ssid}' (Client Mode + mDNS Reflector)...")

        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {IP_CTR_NAT}/24 dev {VETH_CTR}'")
        
        self.run_command(f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {IP_HOST_NAT}/24 gw4 {IP_CTR_NAT}")
        self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.dns '8.8.8.8'")
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

        wpa_conf = f"""ctrl_interface=/var/run/wpa_supplicant
update_config=1
country=US
network={{
    ssid="{ssid}"
    psk="{password}"
}}
"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wpa_supplicant.conf'", shell=True, input=wpa_conf)
        
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf'")
        self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST_NAT}'")

        print("      Starting mDNS/Avahi Reflector...")
        avahi_conf = """[server]
use-ipv4=yes
use-ipv6=no
ratelimit-interval-usec=1000000
ratelimit-burst=1000
[wide-area]
enable-wide-area=yes
[publish]
publish-hinfo=no
publish-workstation=no
[reflector]
enable-reflector=yes
reflect-ipv=no
"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'mkdir -p /etc/avahi'")
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/avahi/avahi-daemon.conf'", shell=True, input=avahi_conf)
        
        # Init DBus machine-id and directory
        self.run_command(f"{self.exec_cmd} 'dbus-uuidgen > /var/lib/dbus/machine-id'", check=False)
        self.run_command(f"{self.exec_cmd} 'mkdir -p /var/run/dbus'", check=False)

        self.run_command(f"{self.exec_cmd} 'dbus-daemon --system --fork'")
        self.run_command(f"{self.exec_cmd} 'avahi-daemon -D'")

    def cleanup(self):
        if not self.shutdown_on_exit:
            print("\n[Background Mode] Script detached.")
            return

        print("\n\n--- Cleaning Up ---")
        self.run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command(f"ip link delete {VETH_HOST}", check=False)
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        
        print("Restoring WiFi to Host...")
        try:
            iface = self.get_active_wifi_interface()
            self.run_command(f"nmcli device connect {iface}", check=False)
        except: pass

def main():
    vpn = ContainerNetwork()
    vpn.check_root()

    try:
        if vpn.is_container_running():
            print("[!] Container is already running. Stop it manually or use 'podman stop'.")
            return

        print("\n" + "="*40)
        print("  WIFI CONTAINER")
        print("="*40)
        print("1. Client Mode (Join WiFi + Fix Discovery)")
        print("2. AP Mode (Create WiFi + True Bridging)")
        
        mode = input("Select Mode (1/2): ").strip()

        if mode == '1':
            nets = vpn.scan_wifi()
            print("\nAvailable Networks:")
            for i, n in enumerate(nets): print(f"{i+1}: {n}")
            sel = input("Select #: ")
            try: ssid = nets[int(sel)-1]
            except: ssid = input("Enter SSID: ")
            password = input(f"Password for {ssid}: ")
            
            vpn.initialize_container()
            ctr_pid = vpn.move_wifi_card()
            vpn.setup_client_mode_with_discovery(ssid, password, ctr_pid)
            
            # --- UPDATED: Fetch real IP ---
            wifi_ip = vpn.get_container_ip("wlan0")
            
            print("\n" + "="*40)
            print("  CONNECTION SUCCESSFUL")
            print("="*40)
            print(f"WiFi IP (External):  {wifi_ip}")
            print(f"Host IP (Internal):  {IP_HOST_NAT}")
            print("="*40)
            print("You are now connected. mDNS reflection is active.")

        elif mode == '2':
            ssid = input("Enter SSID for New AP: ")
            password = input("Enter Password: ")
            
            vpn.initialize_container()
            ctr_pid = vpn.move_wifi_card()
            vpn.setup_ap_mode_bridged(ssid, password, ctr_pid)
            
            print("\n" + "="*40)
            print(f"  AP '{ssid}' CREATED")
            print("="*40)
            print(f"Host IP: {AP_GATEWAY_IP}")

        else:
            print("Invalid mode.")
            return

        print("Press [Enter] to Stop and Cleanup...")
        input()
    
    except KeyboardInterrupt: pass
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        vpn.cleanup()

if __name__ == "__main__":
    main()
