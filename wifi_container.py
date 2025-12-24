#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import json
import re
import argparse
import signal

# --- Configuration ---
CONTAINER_NAME = "wifi-bridge"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "wifi-bridge-ready"
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"
STATE_FILE = "wifi_session.json"

# --- Network Config ---
IP_CTR_NAT = "10.13.13.1"
IP_HOST_NAT = "10.13.13.2"
AP_GATEWAY_IP = "192.168.50.1" # Container side
AP_HOST_IP = "192.168.50.2"    # Host side (Gateway for clients)
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
            if check: raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    # --- Host Routing & NAT Helpers ---
    def get_host_upstream_interface(self):
        """Finds the interface the Host uses for Internet (e.g., eth0)."""
        try:
            out = self.run_command("ip route get 8.8.8.8", check=False)
            if out:
                match = re.search(r"dev\s+(\S+)", out)
                if match: return match.group(1)
        except: pass
        return None

    def enable_host_internet_sharing(self, source_interface):
        """Enables IP Forwarding and NAT on the Host OS."""
        upstream = self.get_host_upstream_interface()
        if not upstream:
            print("      [WARNING] No Host Internet connection found. Clients won't have Internet.")
            return

        print(f"      [Routing] Sharing Host Internet ({upstream}) -> Container ({source_interface})...")
        self.run_command("sysctl -w net.ipv4.ip_forward=1", check=False)
        self.run_command(f"iptables -A FORWARD -i {source_interface} -o {upstream} -j ACCEPT", check=False)
        self.run_command(f"iptables -A FORWARD -i {upstream} -o {source_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT", check=False)

        check_nat = self.run_command(f"iptables -t nat -C POSTROUTING -o {upstream} -j MASQUERADE", check=False)
        if check_nat is None:
            self.run_command(f"iptables -t nat -A POSTROUTING -o {upstream} -j MASQUERADE")

    # --- Session Management ---
    def save_session(self, mode, ssid):
        data = {"mode": mode, "ssid": ssid}
        try:
            with open(STATE_FILE, "w") as f: json.dump(data, f)
            os.chmod(STATE_FILE, 0o600)
            print(f"\n[Session Saved] State written to {STATE_FILE}")
        except: pass

    def load_session(self):
        if not os.path.exists(STATE_FILE): return None
        try:
            with open(STATE_FILE, "r") as f: return json.load(f)
        except: return None

    def clear_session(self):
        if os.path.exists(STATE_FILE): os.remove(STATE_FILE)

    def is_container_running(self):
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def get_container_ip(self, iface="wlan0"):
        try:
            out = self.run_command(f"{self.exec_cmd} 'ip -4 addr show {iface}'", check=False)
            if out:
                match = re.search(r"inet\s+([0-9.]+)/", out)
                if match: return match.group(1)
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
            print("[2/5] Installing tools (Includes Bridge, Avahi & TC)...")
            self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw iptables hostapd dnsmasq iproute2 iproute2-tc bridge-utils avahi avahi-tools dbus")
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

        self.run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")

        try:
            self.run_command(f"iw phy {phy} set netns {ctr_pid}")
        except Exception as e:
            print(f"\n[ERROR] Failed to move {phy}. Possible causes:")
            print(" - The interface is in use (kill wpa_supplicant on host?)")
            raise e

        time.sleep(1)
        # Rename logic inside container
        try:
            iw_out = self.run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            found_iface = None
            if iw_out:
                for line in iw_out.split('\n'):
                    if "Interface" in line:
                        found_iface = line.split()[-1]; break
            if found_iface and found_iface != "wlan0":
                self.run_command(f"{self.exec_cmd} 'ip link set {found_iface} name wlan0'")
        except Exception as e: print(f"      Warning during rename: {e}")
        return ctr_pid

    # --- Optimization Methods ---
    def enable_aqm(self):
        """Enables FQ_CoDel to reduce bufferbloat."""
        print("      [Optimization] Enabling FQ_CoDel AQM...")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan0 root fq_codel 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev {VETH_CTR} root fq_codel 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev br0 root fq_codel 2>/dev/null || true'")

    def optimize_wifi(self):
        """Disables Power Save for lower latency."""
        print("      [Optimization] Disabling WiFi Power Save...")
        self.run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 addrgenmode none' 2>/dev/null || true")

    # --- Mode: AP (Host) ---
    def setup_ap_mode_bridged(self, ssid, password, channel, ctr_pid):
        print(f"[4/5] Configuring Transparent Bridge (Host <-> AP)...")

        # Enforce 5 GHz / AX
        print(f"      [Config] Enforcing 5GHz + 802.11ax + 20MHz Width for minimal interference.")

        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")

        self.run_command(f"{self.exec_cmd} 'ip link add name br0 type bridge'")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip link set br0 up'")
        self.run_command(f"{self.exec_cmd} 'brctl addif br0 {VETH_CTR}'")

        self.run_command(f"{self.exec_cmd} 'sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'iptables -P FORWARD ACCEPT'")

        self.run_command(f"ip link set {VETH_HOST} up")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev br0'")

        nm_cmd = f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {AP_HOST_IP}/24 connection.zone trusted"
        self.run_command(nm_cmd)
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

        self.enable_host_internet_sharing(VETH_HOST)

        print(f"      Starting AP '{ssid}' on Channel {channel} (5GHz AX)...")

        # 802.11ax Config (20MHz force)
        hostapd_conf = f"""interface=wlan0
bridge=br0
ssid={ssid}
country_code=US
hw_mode=a
channel={channel}
wmm_enabled=1

# WiFi 4 (N)
ieee80211n=1

# WiFi 5 (AC)
ieee80211ac=1
vht_oper_chwidth=0
vht_capab=

# WiFi 6 (AX)
ieee80211ax=1
he_oper_chwidth=0

# Security
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""

        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")

        self.optimize_wifi()

        try:
            self.run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")
        except subprocess.CalledProcessError as e:
            print(f"\n[HOSTAPD ERROR] Failed to start AP.")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            print("\n[NOTE] If this fails:")
            print("1. Your card might not support 802.11ax. (It will try to fall back if supported, or fail).")
            print("2. Ensure your regulatory domain allows the selected 5GHz channel.")
            raise e

        self.enable_aqm()

        dnsmasq_conf = f"""interface=br0
dhcp-range={AP_DHCP_RANGE}
dhcp-option=3,{AP_HOST_IP}
dhcp-option=6,8.8.8.8"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

    # --- Mode: Client (Guest) ---
    def setup_client_mode_with_discovery(self, ssid, password, ctr_pid):
        print(f"[4/5] Connecting to '{ssid}' (Client Mode)...")

        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {IP_CTR_NAT}/24 dev {VETH_CTR}'")

        self.run_command(f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {IP_HOST_NAT}/24 gw4 {IP_CTR_NAT} connection.zone trusted")
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
        self.optimize_wifi()

        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf'")
        self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        # NAT & Forwarding
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST_NAT}'")

        self.enable_aqm()

        print("      Starting mDNS/Avahi Reflector...")
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

def get_reproduce_command(mode, ssid, password, channel=165):
    """Generates the command string to reproduce this setup."""
    cmd_path = os.path.abspath(sys.argv[0])
    base = f"sudo {cmd_path} --mode {mode} --ssid '{ssid}' --password '{password}'"
    if mode == 'ap':
        base += f" --channel {channel}"
    return base

def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="WiFi Container Bridge (Performance Mode)")
    parser.add_argument("--mode", choices=['ap', 'client'], help="Mode: 'ap' (Host WiFi) or 'client' (Join WiFi)")
    parser.add_argument("--ssid", help="SSID name")
    parser.add_argument("--password", help="WiFi Password")
    parser.add_argument("--channel", type=int, default=165, help="WiFi Channel (Default: 165 for 5GHz)")
    parser.add_argument("--clean", action='store_true', help="Cleanup existing containers and exit")

    args = parser.parse_args()

    vpn = ContainerNetwork()
    vpn.check_root()

    if args.clean:
        vpn.shutdown_on_exit = True
        vpn.cleanup()
        return

    # --- Mode Selection (Interactive vs CLI) ---
    ssid = args.ssid
    password = args.password
    mode = args.mode
    channel = args.channel
    interactive = False

    if not mode or not ssid or not password:
        interactive = True

    try:
        # --- Clean start ---
        if vpn.is_container_running():
            print("[!] Container is running.")
            if interactive:
                saved = vpn.load_session()
                if saved: print(f"    Active: {saved.get('mode')} - {saved.get('ssid')}")
                opt = input("    (S)top, (D)etach, or (I)gnore? ").strip().lower()
                if opt == 's': vpn.clear_session(); vpn.shutdown_on_exit = True; vpn.cleanup(); sys.exit(0)
                elif opt == 'd': vpn.shutdown_on_exit = False; return
            else:
                print("    Restarting due to CLI arguments...")
                vpn.shutdown_on_exit = True
                vpn.cleanup()

        if interactive:
            print("\n" + "="*40)
            print("  WIFI CONTAINER (PERFORMANCE MODE)")
            print("="*40)
            print("1. Client Mode (Join WiFi)")
            print("2. AP Mode (Create WiFi)")

            sel = input("Select Mode (1/2): ").strip()
            if sel == '1':
                mode = 'client'
                nets = vpn.scan_wifi()
                print("\nAvailable Networks:")
                for i, n in enumerate(nets): print(f"{i+1}: {n}")
                n_sel = input("Select #: ")
                try: ssid = nets[int(n_sel)-1]
                except: ssid = input("Enter SSID: ")
                password = input(f"Password for {ssid}: ")
            elif sel == '2':
                mode = 'ap'
                ssid = input("Enter SSID for New AP: ")
                password = input("Enter Password: ")

                print("\nChannel Selection (5GHz Only):")
                print("  165 = 5 GHz High (Recommended, minimal interference) [Default]")
                print("  36  = 5 GHz Low (Use if client can't see 165)")
                # Removed 2.4 GHz as requested
                ch_in = input("Channel [165]: ").strip()
                if not ch_in:
                    channel = 165
                elif ch_in.isdigit():
                    channel = int(ch_in)
                else:
                    channel = 165
            else:
                print("Invalid."); sys.exit(1)

        # --- Execution ---
        vpn.initialize_container()
        ctr_pid = vpn.move_wifi_card()

        if mode == 'client':
            vpn.setup_client_mode_with_discovery(ssid, password, ctr_pid)
            print(f"\n[CONNECTED] IP: {vpn.get_container_ip()}")
        elif mode == 'ap':
            vpn.setup_ap_mode_bridged(ssid, password, channel, ctr_pid)
            print(f"\n[CREATED] AP '{ssid}' on Channel {channel} (5GHz AX)")

        # --- Reproduce Command ---
        repro_cmd = get_reproduce_command(mode, ssid, password, channel)
        print("\n" + "*"*60)
        print(" TO RE-RUN THIS SETUP AUTOMATICALLY, USE:")
        print(f" {repro_cmd}")
        print("*"*60)

        # --- Loop ---
        if interactive:
            print("\nSession Active. Type 'bg' to detach, 'stop' to end.")
            while True:
                user_in = input("> ").strip().lower()
                if user_in == 'bg':
                    vpn.save_session(mode, ssid)
                    vpn.shutdown_on_exit = False
                    break
                elif user_in == 'stop':
                    vpn.clear_session()
                    break
        else:
            print("\n[Running in Headless Mode]. Press Ctrl+C to stop.")
            def handler(signum, frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGINT, handler)
            signal.signal(signal.SIGTERM, handler)
            signal.pause()

    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        vpn.cleanup()

if __name__ == "__main__":
    main()
