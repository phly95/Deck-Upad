#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import json
import re
import random

# --- Configuration ---
CONTAINER_NAME = "vpn-test"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "vpn-ap-ready"
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"
STATE_FILE = "wifi_session.json"

# IPs for the Virtual Cable (Host <-> Container)
IP_CTR = "10.13.13.1"
IP_HOST = "10.13.13.2"
SUBNET_CIDR = "24"

# AP Configuration (Internal Hotspot)
AP_GATEWAY_IP = "192.168.50.1"
AP_DHCP_RANGE = "192.168.50.10,192.168.50.50,12h"

class ContainerVPN:
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
                print(f"\n[CMD ERROR]: {cmd}")
                print(f"[STDERR]: {e.stderr}")
                raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    # --- Session Management ---
    def save_session(self, mode, ssid, password, net_config=None, repeater_config=None):
        data = {
            "mode": mode,
            "ssid": ssid,
            "password": password,
            "net_config": net_config,
            "repeater_config": repeater_config
        }
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(data, f)
            os.chmod(STATE_FILE, 0o600)
            print(f"\n[Session Saved] State written to {STATE_FILE}")
        except Exception as e:
            print(f"Warning: Could not save session: {e}")

    def load_session(self):
        if not os.path.exists(STATE_FILE): return None
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except: return None

    def clear_session(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            print("[Session Cleared] Saved state removed.")

    # --- State Detection ---
    def is_container_running(self):
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def get_active_mode(self):
        try:
            ps = self.run_command(f"{self.exec_cmd} 'ps'").lower()
            if "hostapd" in ps and "wpa_supplicant" in ps: return "Repeater Mode"
            if "hostapd" in ps: return "AP Mode"
            if "wpa_supplicant" in ps: return "Client Mode"
        except: pass
        return None

    def get_current_network_state(self):
            config = {"ip": None, "cidr": "24", "gateway": None}
            try:
                ip_line = self.run_command(f"{self.exec_cmd} 'ip -4 addr show wlan0 | grep inet'", check=False)
                if ip_line:
                    parts = ip_line.split()
                    if len(parts) >= 2:
                        cidr_full = parts[1]
                        if '/' in cidr_full:
                            config['ip'], config['cidr'] = cidr_full.split('/')
                        else:
                            config['ip'] = cidr_full

                route_line = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0 | grep default'", check=False)
                if route_line:
                    parts = route_line.split()
                    if 'via' in parts:
                        idx = parts.index('via')
                        if idx + 1 < len(parts):
                            config['gateway'] = parts[idx + 1]
                return config if config['ip'] else None
            except: return None

    # --- WiFi Utils ---
    def get_active_wifi_interface(self):
        try:
            output = self.run_command("nmcli -t -f DEVICE,TYPE,STATE device")
            for line in output.split('\n'):
                if ":wifi:" in line: return line.split(':')[0]
            output = self.run_command("iw dev | grep Interface", shell=True)
            if output: return output.split()[-1]
        except: pass
        return "wlp9s0"

    def scan_wifi(self, band_filter=None):
        print(f"Scanning networks on {self.wifi_interface}...")
        try:
            self.run_command(f"nmcli device wifi rescan ifname {self.wifi_interface}", check=False)
            time.sleep(2)
            # Robust Scan (SSID Only to prevent parsing errors)
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

    def get_wifi_channel(self, iface="wlan0"):
        try:
            output = self.run_command(f"{self.exec_cmd} 'iw dev {iface} info'", check=False)
            if output:
                match = re.search(r"channel\s+(\d+)", output)
                if match: return int(match.group(1))

            output = self.run_command(f"{self.exec_cmd} 'iw dev {iface} link'", check=False)
            if output:
                match = re.search(r"freq:\s+(\d+)", output)
                pass
        except: pass
        return 36

    def cleanup(self):
        if not self.shutdown_on_exit:
            print("\n[Background Mode] Detaching script. Container left running.")
            return

        print("\n\n--- Cleaning Up ---")
        self.run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command(f"ip link delete {VETH_HOST}", check=False)

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
                    # Added iproute2-tc here for FQ_CoDel support
                    self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw iptables hostapd dnsmasq iproute2 iproute2-tc")
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
        self.run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
        self.run_command(f"iw phy phy0 set netns {ctr_pid}")
        return ctr_pid

    def setup_veth_link(self, ctr_pid, is_client_mode):
        print(f"[5/6] Creating High-Speed Veth Link (Host <-> Container)...")
        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_HOST} txqueuelen 1000")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")

        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {IP_CTR}/{SUBNET_CIDR} dev {VETH_CTR}'")

        nm_cmd = f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {IP_HOST}/{SUBNET_CIDR}"

        if is_client_mode:
            print("      Configuring Container as Default Gateway...")
            nm_cmd += f" gw4 {IP_CTR}"
        else:
            print("      AP Mode: Skipping Default Gateway configuration.")

        self.run_command(nm_cmd)

        if is_client_mode:
            self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.dns '8.8.8.8'")
            self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.route-metric 50")
        else:
            self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.route-metric 600")

        self.run_command(f"nmcli connection up {NM_CONN_NAME}")
        self.run_command(f"ip route add 192.168.50.0/24 via {IP_CTR} dev {VETH_HOST}", check=False)

        print("      Enabling Global NAT & Forwarding...")
        # 1. NAT for Internet Access (wlan0)
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

        # 2. NAT for Local AP Access (wlan1) - ESSENTIAL for Ping from Host -> Client
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE' 2>/dev/null || true")

        # 3. Host (veth) <-> Internet (wlan0)
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")

        # 4. Clients (wlan1) <-> Internet (wlan0)
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan1 -o wlan0 -j ACCEPT' 2>/dev/null || true")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o wlan1 -m state --state RELATED,ESTABLISHED -j ACCEPT' 2>/dev/null || true")

        # 5. Host (veth) <-> Clients (wlan1)
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan1 -j ACCEPT' 2>/dev/null || true")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan1 -o {VETH_CTR} -j ACCEPT' 2>/dev/null || true")

    def enable_aqm(self):
        """Enables FQ_CoDel (Fair Queuing Controlled Delay) to fix bufferbloat."""
        print("      Enabling Active Queue Management (FQ_CoDel)...")
        # FIXED: Quotes moved to encompass the || true logic so shell handles it
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan0 root fq_codel 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev {VETH_CTR} root fq_codel 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan1 root fq_codel 2>/dev/null || true'")

    def optimize_wifi(self):
        print("      Optimizing WiFi Latency (Power Save OFF)...")
        self.run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 addrgenmode none' 2>/dev/null || true")

    def connect_wlan0(self, ssid, password, run_dhcp=True):
        print(f"      Connecting wlan0 to '{ssid}'...")

        self.run_command(f"{self.exec_cmd} 'killall wpa_supplicant 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'killall udhcpc 2>/dev/null || true'")

        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 down 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip addr flush dev wlan0 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.optimize_wifi()

        # Generate Config (Auto-Negotiate)
        psk_hex = f'psk="{password}"'
        try:
            out = self.run_command(f"{self.exec_cmd} 'wpa_passphrase \"{ssid}\" \"{password}\"'")
            for line in out.split('\n'):
                if 'psk=' in line and '#' not in line:
                    psk_hex = line.strip()
        except: pass

        conf = f"""ctrl_interface=/var/run/wpa_supplicant
update_config=1
country=US

network={{
    ssid="{ssid}"
    {psk_hex}
    scan_ssid=1
}}
"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wpa_supplicant.conf'", shell=True, input=conf)

        # Start Supplicant with default driver
        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf'")

        self.run_command(f"{self.exec_cmd} 'ip route del default 2>/dev/null || true'")

        print("      Waiting for Upstream Connection (Max 30s)...")
        connected = False
        for i in range(30):
            if self.run_command(f"{self.exec_cmd} 'iw dev wlan0 link | grep SSID'", check=False):
                connected = True
                break
            time.sleep(1)
            if i > 0 and i % 5 == 0: print(f"      ... waiting ({i}s)")

        if not connected:
            print("\n[ERROR] Connection timed out.")
            print("Debug (iw dev wlan0 link):")
            print(self.run_command(f"{self.exec_cmd} 'iw dev wlan0 link'", check=False))
            raise Exception("Failed to connect to upstream WiFi")

        if run_dhcp:
            self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

    def setup_client_mode(self, ssid, password, static_config=None):
        print(f"[4/6] Initializing Client Mode...")
        should_dhcp = (static_config is None)
        self.connect_wlan0(ssid, password, run_dhcp=should_dhcp)

        gateway_ip = "172.16.16.16"

        if static_config and static_config.get('ip'):
            print(f"      [RESUME] Taking IP by force: {static_config['ip']}")
            try:
                cidr = static_config.get('cidr', '24')
                self.run_command(f"{self.exec_cmd} 'ip addr add {static_config['ip']}/{cidr} dev wlan0'")
                gw = static_config.get('gateway')
                if gw:
                    self.run_command(f"{self.exec_cmd} 'ip route add default via {gw} dev wlan0'")
                    gateway_ip = gw
                else:
                    self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")
            except:
                self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        if should_dhcp:
             try:
                output = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0'")
                if output:
                    for line in output.split('\n'):
                        if 'src' in line and '/' in line:
                            subnet = line.split()[0].split('/')[0]
                            octets = subnet.split('.')
                            if len(octets) == 4:
                                if subnet.startswith("192.168.50"): gateway_ip = "192.168.50.1"
                                else: gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.16"
                            break
             except: pass

        self.run_command(f"{self.exec_cmd} 'ip route del default 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip route add default via {gateway_ip} dev wlan0 2>/dev/null || true'")

        print("      Enabling DMZ...")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def setup_ap_mode(self, ssid, password):
        print(f"[4/6] Starting Hotspot '{ssid}' (AP Mode - Channel 165)...")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan0'")
        self.optimize_wifi()

        # UPDATED: Channel 165 (20 MHz)
        hostapd_conf = f"""interface=wlan0
ssid={ssid}
country_code=US
hw_mode=a
channel=165
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
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

        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 67 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def setup_repeater_mode(self, client_ssid, client_pass, ap_ssid, ap_pass):
        print(f"[4/6] Initializing Repeater Mode (Auto-Sync Band)...")

        self.connect_wlan0(client_ssid, client_pass, run_dhcp=True)

        active_channel = self.get_wifi_channel("wlan0")
        print(f"      Detected Upstream Channel: {active_channel}")

        hw_mode = "g"
        if active_channel > 14: hw_mode = "a"
        print(f"      Setting Hardware Mode: {hw_mode}")

        print(f"      Starting Hotspot '{ap_ssid}' on wlan1 (Channel {active_channel})...")
        rand_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan1 type __ap addr {rand_mac} 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan1 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan1'")

        hostapd_conf = f"""interface=wlan1
ssid={ap_ssid}
country_code=US
hw_mode={hw_mode}
channel={active_channel}
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
wpa=2
wpa_passphrase={ap_pass}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)

        try:
            self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")
        except Exception as e:
            print("\n[CRITICAL ERROR] Failed to start Hostapd.")
            print("Try running 'iw list' inside container to see 'valid interface combinations'.")
            raise e

        # --- FIX ADDED HERE ---
        # Forward traffic hitting the AP interface (wlan1) to the internal Host IP
        print("      Enabling DMZ for Repeater Clients...")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan1 -j DNAT --to-destination {IP_HOST}'")
        # ----------------------

        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=f"interface=wlan1\ndhcp-range={AP_DHCP_RANGE}\ndhcp-option=3,{AP_GATEWAY_IP}\ndhcp-option=6,8.8.8.8")
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")


    def setup_crossband_repeater_mode(self, client_ssid, client_pass, ap_ssid, ap_pass):
        print(f"[4/6] Initializing Cross-Band Repeater (2.4GHz -> 5GHz 20MHz)...")

        self.connect_wlan0(client_ssid, client_pass, run_dhcp=True)

        print(f"      Starting High-Performance Hotspot '{ap_ssid}' on wlan1...")
        print(f"      (Target: Channel 165, 20MHz, 5GHz)")

        rand_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan1 type __ap addr {rand_mac} 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan1 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan1'")

        # UPDATED: Channel 165 (20 MHz), removed HT40+/VHT80 settings
        hostapd_conf = f"""interface=wlan1
ssid={ap_ssid}
country_code=US
hw_mode=a
channel=165
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
wpa=2
wpa_passphrase={ap_pass}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)

        try:
            self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")
        except Exception as e:
            print("\n[CRITICAL ERROR] Failed to start 5GHz AP while connected to 2.4GHz.")
            print("Your WiFi card likely does not support simultaneous dual-band (RSDB).")
            raise e

        # Forward traffic hitting the AP interface (wlan1) to the internal Host IP
        print("      Enabling DMZ for Repeater Clients...")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan1 -j DNAT --to-destination {IP_HOST}'")

        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=f"interface=wlan1\ndhcp-range={AP_DHCP_RANGE}\ndhcp-option=3,{AP_GATEWAY_IP}\ndhcp-option=6,8.8.8.8")
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")


    def show_status(self, mode):
            lan_ip = "Unknown"
            wan_ip = "Unknown"

            if mode == "AP Mode":
                lan_ip = AP_GATEWAY_IP
            elif mode == "Client Mode":
                state = self.get_current_network_state()
                if state: lan_ip = state['ip']
            elif "Repeater" in mode or "CrossBand" in mode:
                lan_ip = AP_GATEWAY_IP
                state = self.get_current_network_state()
                if state: wan_ip = state['ip']

            print("\n" + "="*45)
            print(f"   CONNECTION ESTABLISHED ({mode})")
            print("="*45)
            if "Repeater" in mode or "CrossBand" in mode:
                print(f"WAN IP (Internet):    {wan_ip}")
                print(f"LAN IP (Your AP):     {lan_ip}")
            else:
                print(f"WIFI IP:              {lan_ip}")

            print(f"INTERNAL VETH IP:     {IP_HOST}")
            print("-" * 45)
            if mode == "AP Mode":
                print(f"You are the HOST. Clients: 192.168.50.10 - 50")
            elif "Repeater" in mode or "CrossBand" in mode:
                print(f"Internet Source: wlan0 -> Broadcasting: wlan1")
            else:
                print(f"You are a CLIENT. Host IP: 192.168.50.1")
            print("="*45)
            print(" [Enter] or 'stop' : Full Cleanup & Exit")
            print(" 'pause'           : Save Session, Cleanup & Exit")
            print(" 'bg'              : Detach (Run in Background)")
            print("="*45)

def main():
    vpn = ContainerVPN()
    vpn.check_root()
    try:
        # --- RESUME ATTACH ---
        if vpn.is_container_running():
            active_mode = vpn.get_active_mode()
            if active_mode:
                print(f"\n[!] Detected running session: {active_mode}")
                print("    Resuming control...")
                vpn.show_status(active_mode)

                user_in = input().strip().lower()
                if user_in == 'bg': vpn.shutdown_on_exit = False
                elif user_in == 'pause':
                    print("Cannot pause an attached session (credentials unknown). Use 'stop'.")
                return
            else:
                print("[!] Container running but no active session found. Restarting...")
                vpn.cleanup()

        # --- LOAD SAVED SESSION ---
        ssid = ""
        password = ""
        mode_code = "1"
        net_config = None
        repeater_config = None

        saved_session = vpn.load_session()
        use_saved = False

        if saved_session:
            print(f"\n[?] PAUSED SESSION FOUND: {saved_session['mode']}")
            if 'Repeater' in saved_session['mode'] or 'CrossBand' in saved_session['mode']:
                r = saved_session.get('repeater_config', {})
                print(f"    In: {r.get('client_ssid')} -> Out: {r.get('ap_ssid')}")
            else:
                print(f"    SSID: {saved_session['ssid']}")

            choice = input("    Resume this session? (Y/n): ").strip().lower()
            if choice != 'n':
                use_saved = True
                ssid = saved_session['ssid']
                password = saved_session['password']
                net_config = saved_session.get('net_config')
                repeater_config = saved_session.get('repeater_config')

                if saved_session['mode'] == 'Client Mode': mode_code = '1'
                elif saved_session['mode'] == 'AP Mode': mode_code = '2'
                elif saved_session['mode'] == 'Repeater Mode': mode_code = '3'
                elif saved_session['mode'] == 'CrossBand Mode': mode_code = '4'
            else:
                vpn.clear_session()

        # --- MANUAL SETUP ---
        if not use_saved:
            print(f"Detected WiFi: {vpn.wifi_interface}")
            print("\nSelect Mode:")
            print("1. Client (Join WiFi)")
            print("2. Host (Create AP)")
            print("3. Repeater (Join WiFi -> Create AP same band, Recommended for Host PC without Ethernet, QoS-optimized for stability)")
            print("4. Cross-Band Repeater (May not work, 2.4GHz In -> 5GHz 80MHz Out)")

            while True:
                c = input("Choice (1-4): ")
                if c in ['1','2','3','4']:
                    mode_code = c
                    break

            # Logic for Repeater Mode Inputs
            if mode_code == '3' or mode_code == '4':

                # --- NEW WARNING BLOCK START ---
                warning_marker = ".repeater_ack"
                if not os.path.exists(warning_marker):
                    print("\n" + "!"*60)
                    print(" WARNING: HIGH POLLING FREQUENCY & SPECTRUM USAGE")
                    print("!"*60)
                    print("This mode uses a very high polling frequency that can degrade")
                    print("the spectrum your home internet AP is using for other devices and your neighbors.")
                    print("\nIt is HIGHLY RECOMMENDED to adjust your home AP to something")
                    print("less intrusive, such as:")
                    print("  - 40 MHz width")
                    print("  - Upper range of UNII-3 (e.g., Channel 149+). Check a WiFi scanner to see what 5GHz spectrum is in use")
                    print("  - If you must overlap with another AP, aim to use the upper range of the channel to avoid")
                    print("interfering with neighboring primary channels")
                    print("  - When you do so, you're cutting the effective frequency from the top of the neighboring channel,")
                    print("which is why: Aim for the top if you must.")
                    print("\nRelevance:")
                    print("  - HIGH priority for apartment buildings (congestion risk).")
                    print("  - Lower priority for rural homes.")
                    print("!"*60)

                    try:
                        input("Press [Enter] to acknowledge and continue...")
                        # Create marker file to suppress this warning in future
                        with open(warning_marker, "w") as f:
                            f.write("acknowledged")
                    except KeyboardInterrupt:
                        print("\nAborted.")
                        return
                # --- NEW WARNING BLOCK END ---

                # We do not use filter here anymore since we scan ALL bands
                nets = vpn.scan_wifi()
                print("\n[Input] Select UPSTREAM Network (Internet Source):")
                if not nets:
                    print("No networks found! (Check filters or range)")

                # Nets is list of strings
                for i, n in enumerate(nets):
                    print(f"{i+1}: {n}")

                selected_net = None
                while True:
                    sel = input("Select # or SSID: ")
                    if sel.isdigit() and 1 <= int(sel) <= len(nets):
                        client_ssid = nets[int(sel)-1]
                        break
                    elif sel:
                        client_ssid = sel
                        break

                client_pass = input(f"Password for {client_ssid}: ")

                print("\n[Output] Configure LOCAL Hotspot:")
                ap_ssid = input("Enter new SSID for your AP: ")
                ap_pass = input(f"Password for {ap_ssid}: ")

                repeater_config = {
                    "client_ssid": client_ssid, "client_pass": client_pass,
                    "ap_ssid": ap_ssid, "ap_pass": ap_pass
                }

            # Logic for Standard Modes
            else:
                if mode_code == '1':
                    nets = vpn.scan_wifi()
                    print("\nNetworks:")
                    for i, n in enumerate(nets):
                        print(f"{i+1}: {n}")

                    while True:
                        sel = input("Select # or SSID: ")
                        if sel.isdigit() and 1 <= int(sel) <= len(nets):
                            ssid = nets[int(sel)-1]
                            break
                        elif sel:
                            ssid = sel
                            break

                else:
                    ssid = input("Enter new SSID: ")

                password = input(f"Password for {ssid}: ")

        # --- EXECUTION ---
        vpn.initialize_container()
        ctr_pid = vpn.move_wifi_card()

        active_mode_str = ""
        if mode_code == '1':
            active_mode_str = "Client Mode"
            vpn.setup_client_mode(ssid, password, static_config=net_config)
            vpn.setup_veth_link(ctr_pid, is_client_mode=True)
        elif mode_code == '2':
            active_mode_str = "AP Mode"
            vpn.setup_ap_mode(ssid, password)
            vpn.setup_veth_link(ctr_pid, is_client_mode=False)
        elif mode_code == '3':
            active_mode_str = "Repeater Mode"
            rc = repeater_config
            vpn.setup_repeater_mode(rc['client_ssid'], rc['client_pass'], rc['ap_ssid'], rc['ap_pass'])
            vpn.setup_veth_link(ctr_pid, is_client_mode=True)
        elif mode_code == '4':
            active_mode_str = "CrossBand Mode"
            rc = repeater_config
            vpn.setup_crossband_repeater_mode(rc['client_ssid'], rc['client_pass'], rc['ap_ssid'], rc['ap_pass'])
            vpn.setup_veth_link(ctr_pid, is_client_mode=True)

        # Apply AQM *AFTER* veth links are up
        vpn.enable_aqm()

        vpn.show_status(active_mode_str)

        # --- INPUT LOOP ---
        user_in = input().strip().lower()

        if user_in == 'bg':
            vpn.shutdown_on_exit = False
        elif user_in == 'pause':
            nc = vpn.get_current_network_state()
            vpn.save_session(active_mode_str, ssid, password, net_config=nc, repeater_config=repeater_config)
            vpn.shutdown_on_exit = True
        elif user_in == 'stop' or user_in == '':
            vpn.clear_session()
            vpn.shutdown_on_exit = True

    except KeyboardInterrupt: print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
    finally: vpn.cleanup()

if __name__ == "__main__":
    main()
