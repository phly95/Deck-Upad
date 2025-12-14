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
CUSTOM_IMAGE = "vpn-ap-ready"
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
            if check: raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    def get_active_wifi_interface(self):
        try:
            output = self.run_command("nmcli -t -f DEVICE,TYPE,STATE device")
            for line in output.split('\n'):
                if ":wifi:" in line: return line.split(':')[0]
            output = self.run_command("iw dev | grep Interface", shell=True)
            if output: return output.split()[-1]
        except: pass
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
                if len(parts) >= 1 and parts[0] and parts[0] not in seen:
                    networks.append(parts[0])
                    seen.add(parts[0])
            return networks
        except: return []

    def cleanup(self):
        print("\n\n--- Cleaning Up ---")
        self.run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command("nmcli connection delete wg-host", check=False)

        if os.path.exists(HOST_WG_CONF):
            try:
                os.remove(HOST_WG_CONF)
            except:
                pass

        print("Stopping container...")
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        print("Restoring Host Network Manager...")
        try:
            iface = self.get_active_wifi_interface()
            self.run_command(f"nmcli device connect {iface}", check=False)
            print("Done. Host internet should return shortly.")
        except: print("Warning: Could not auto-trigger WiFi reconnect.")

    def initialize_container(self):
        print("\n[1/6] Initializing Container...")
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
            print("[2/6] Installing tools (Internet Required)...")
            max_retries = 3
            for i in range(max_retries):
                try:
                    self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw wireguard-tools iptables hostapd dnsmasq")
                    break
                except:
                    if i < max_retries - 1:
                        print(f"      Retry {i+1}/{max_retries}...")
                        time.sleep(5)
                    else: raise
            print(f"      Caching image to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        else:
            print("[2/6] Using Cached Tools (Offline Ready).")

    def move_wifi_card(self):
        print(f"[3/6] Moving {self.wifi_interface} to container...")
        # Check=False prevents crash if device is already disconnected/idle
        self.run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
        self.run_command(f"iw phy phy0 set netns {ctr_pid}")

    def setup_client_mode(self, ssid, password):
        print(f"[4/6] Connecting to '{ssid}' (Client Mode)...")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        psk_cmd = f"wpa_passphrase \"{ssid}\" \"{password}\" > /etc/wpa_supplicant.conf"
        self.run_command(f"{self.exec_cmd} '{psk_cmd}'")
        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf -s'")
        print("      Requesting IP...")
        self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        # Robust Gateway Detection
        gateway_ip = "172.16.16.16"
        try:
            output = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0'")
            if output:
                for line in output.split('\n'):
                    if 'src' in line and '/' in line:
                        subnet = line.split()[0].split('/')[0]
                        octets = subnet.split('.')
                        if len(octets) == 4:
                            if subnet.startswith("192.168.50"):
                                gateway_ip = "192.168.50.1"
                            else:
                                gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.16"
                        break
        except: pass

        self.run_command(f"{self.exec_cmd} 'ip route del default || true'")
        self.run_command(f"{self.exec_cmd} 'ip route add default via {gateway_ip} dev wlan0'")

    def setup_ap_mode(self, ssid, password):
        print(f"[4/6] Starting Hotspot '{ssid}' (AP Mode - 5GHz AX)...")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan0'")

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
        self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")

        dnsmasq_conf = f"""interface=wlan0
dhcp-range={AP_DHCP_RANGE}
dhcp-option=3,{AP_GATEWAY_IP}
dhcp-option=6,8.8.8.8"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

    def setup_dmz_forwarding(self, is_ap_mode):
        """Forwards incoming WiFi traffic directly to the Host."""
        print("      Setting up DMZ (Forwarding all WiFi traffic to Host)...")
        if is_ap_mode:
            # AP Mode: Allow DHCP(67) and DNS(53) to hit container, forward rest to Host
            self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 67 -j ACCEPT'")
            self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j ACCEPT'")
            self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination 10.13.13.2'")
        else:
            # Client Mode: Forward EVERYTHING to Host
            self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination 10.13.13.2'")

    def setup_wireguard(self):
        print("[5/6] Configuring WireGuard VPN...")
        ctr_priv = self.run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        ctr_pub = self.run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=ctr_priv).strip()
        host_priv = self.run_command(f"podman exec {CONTAINER_NAME} wg genkey")
        host_pub = self.run_command(f"podman exec -i {CONTAINER_NAME} wg pubkey", shell=True, input=host_priv).strip()
        ctr_ip = self.run_command(f"podman inspect -f '{{{{.NetworkSettings.IPAddress}}}}' {CONTAINER_NAME}")

        wg0_conf = f"""[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = {ctr_priv}
[Peer]
PublicKey = {host_pub}
AllowedIPs = 10.13.13.2/32"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wireguard/wg0.conf'", shell=True, input=wg0_conf)

        self.run_command(f"{self.exec_cmd} 'wg-quick up wg0'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

        wg_host_conf = f"""[Interface]
Address = 10.13.13.2/24
PrivateKey = {host_priv}
DNS = 8.8.8.8
[Peer]
PublicKey = {ctr_pub}
Endpoint = {ctr_ip}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""

        if os.path.exists(HOST_WG_CONF):
            try:
                os.remove(HOST_WG_CONF)
            except:
                pass

        with open(HOST_WG_CONF, "w") as f: f.write(wg_host_conf)

        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command("nmcli connection delete wg-host", check=False)
        self.run_command(f"nmcli connection import type wireguard file {HOST_WG_CONF}")
        self.run_command(f"nmcli connection modify wg-host connection.id {NM_CONN_NAME}")
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

    def show_status(self, mode):
        lan_ip = "Unknown"
        try: lan_ip = self.run_command(f"{self.exec_cmd} 'ip -4 addr show wlan0 | grep inet | awk \"{{print \\$2}}\"'").split('/')[0]
        except: pass

        print("\n" + "="*40)
        print(f"   CONNECTION ESTABLISHED ({mode})")
        print("="*40)
        print(f"YOUR IP ADDRESS:      {lan_ip}")
        print("-" * 40)
        if mode == "AP Mode":
            print(f"Host IP to Ping:      192.168.50.1")
            print(f"Client Range:         192.168.50.10 - 50")
        else:
            print(f"Host IP to Ping:      192.168.50.1")
        print("="*40)

def main():
    vpn = ContainerVPN()
    vpn.check_root()
    try:
        print(f"Detected WiFi: {vpn.wifi_interface}")
        print("\nSelect Mode:\n1. Client (Join)\n2. Host (Create AP)")
        while True:
            c = input("Choice (1/2): ")
            if c in ['1','2']: break

        ssid = ""
        if c == '1':
            nets = vpn.scan_wifi()
            print("\nNetworks:")
            for i, n in enumerate(nets): print(f"{i+1}: {n}")
            while True:
                sel = input("Select # or SSID: ")
                if sel.isdigit() and 1 <= int(sel) <= len(nets):
                    ssid = nets[int(sel)-1]; break
                elif sel: ssid = sel; break
        else:
            ssid = input("Enter new SSID: ")

        pw = input(f"Password for {ssid}: ")

        vpn.initialize_container()
        vpn.move_wifi_card()

        if c == '1':
            vpn.setup_client_mode(ssid, pw)
            vpn.setup_wireguard()
            vpn.setup_dmz_forwarding(is_ap_mode=False)
            vpn.show_status("Client Mode")
        else:
            vpn.setup_ap_mode(ssid, pw)
            vpn.setup_wireguard()
            vpn.setup_dmz_forwarding(is_ap_mode=True)
            vpn.show_status("AP Mode")

        input("\nPress ENTER to stop...")
    except KeyboardInterrupt: print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
    finally: vpn.cleanup()

if __name__ == "__main__":
    main()
