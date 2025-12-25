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
import shutil

# --- Configuration ---
CONTAINER_NAME = "wifi-bridge"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "wifi-bridge-ready"
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"
STATE_FILE = "wifi_session.json"

# --- Network Config ---
ROUTER_LAN_IP = "192.168.50.1"
DHCP_RANGE = "192.168.50.10,192.168.50.100,12h"
HOST_LAN_IP = "192.168.50.2"

# Client Mode Internal Network
CLIENT_GATEWAY_IP = "10.13.13.1"
CLIENT_HOST_IP = "10.13.13.2"

class ContainerNetwork:
    def __init__(self):
        self.wifi_interface = self.get_active_wifi_interface()
        self.eth_interface = self.get_host_upstream_interface()
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"
        self.shutdown_on_exit = True
        self.moved_eth = False

    def run_command(self, cmd, shell=False, check=True, input=None, timeout=None):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, input=input, timeout=timeout
            )
            if not check and result.returncode != 0:
                return None
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            if check: raise Exception(f"Command timed out: {cmd}")
            return None
        except subprocess.CalledProcessError as e:
            if check: raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    # --- Hardware Utils ---
    def get_host_upstream_interface(self):
        try:
            out = self.run_command("ip route get 8.8.8.8", check=False)
            if out:
                match = re.search(r"dev\s+(\S+)", out)
                if match: return match.group(1)
        except: pass
        return None

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

    # --- Container Lifecycle ---
    def initialize_container(self):
        print("\n[1/5] Initializing Container...")
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        use_image = CUSTOM_IMAGE if self.run_command(f"podman images -q {CUSTOM_IMAGE}", check=False) else BASE_IMAGE

        print("      [Performance] Applying Real-Time Priority Mode...")

        # CRITICAL FIX: Re-added --sysctl net.ipv4.ip_forward=1
        podman_run = (
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=none "
            "--sysctl net.ipv4.ip_forward=1 "  # <--- THIS IS REQUIRED FOR ROUTING
            f"{use_image} sleep infinity"
        )

        self.run_command(podman_run)

        try:
            ctr_pid = self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
            # Real-Time FIFO Scheduler
            self.run_command(f"chrt -f -p 99 {ctr_pid}")
            print("      [Performance] Real-Time FIFO Scheduler: ENABLED")
        except:
            print("      [Performance] Failed to set RT Scheduler.")

        if use_image == BASE_IMAGE:
            print("[2/5] Installing tools (Includes Bridge, Avahi & TC)...")
            self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw iptables hostapd dnsmasq iproute2 iproute2-tc bridge-utils avahi avahi-tools dbus dhcpcd")
            print(f"      Caching image to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        else:
            print("[2/5] Using Cached Tools.")

    # --- Interface Moving Logic ---
    def move_wifi_card(self):
        print(f"[3/5] Moving WiFi ({self.wifi_interface}) to container...")
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

    def move_ethernet_card(self, ctr_pid):
        if not self.eth_interface:
            print("      [WARNING] No active Ethernet found to move!")
            return False

        print(f"      [Router Mode] Moving Ethernet ({self.eth_interface}) to container...")
        self.run_command(f"nmcli device disconnect {self.eth_interface}", check=False)
        time.sleep(1)

        try:
            self.run_command(f"ip link set {self.eth_interface} netns {ctr_pid}")
            self.moved_eth = True
        except Exception as e:
            print(f"      [ERROR] Failed to move Ethernet: {e}")
            return False

        print("      [Router Mode] Clearing default routes...")
        self.run_command(f"{self.exec_cmd} 'ip route flush default'", check=False)

        print(f"      [Router Mode] Bringing up WAN inside container...")
        self.run_command(f"{self.exec_cmd} 'ip link set {self.eth_interface} up'")
        time.sleep(2)

        # Check Carrier
        carrier = self.run_command(f"{self.exec_cmd} 'cat /sys/class/net/{self.eth_interface}/carrier'", check=False)
        if carrier != "1":
             print(f"      [WARNING] Cable seems unplugged? (Carrier: {carrier})")

        print(f"      [Router Mode] Requesting WAN IP (via udhcpc)...")
        dhcp_cmd = f"{self.exec_cmd} 'udhcpc -i {self.eth_interface} -n -q -f -t 5'"

        try:
            res = subprocess.run(shlex.split(dhcp_cmd), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        except subprocess.CalledProcessError as e:
            print(f"      [DHCP FAIL] Code: {e.returncode}")
            print(f"      [DHCP LOG] {e.stdout}")
        except subprocess.TimeoutExpired:
            print("      [DHCP FAIL] Timed out waiting for IP.")

        wan_ip = self.get_container_ip(self.eth_interface)
        print(f"      [Router Mode] WAN IP Acquired: {wan_ip}")

        routes = self.run_command(f"{self.exec_cmd} 'ip route show default'", check=False)
        if not routes or "default" not in routes:
             print("      [CRITICAL WARNING] No Default Gateway obtained! Retrying DHCP...")
             self.run_command(f"{self.exec_cmd} 'udhcpc -i {self.eth_interface} -n -q -f -t 3'", check=False)

        return True

    def run_diagnostics(self):
        print("\n" + "="*40)
        print("  DIAGNOSTICS")
        print("="*40)

        print("1. Container WAN Access (Ping 8.8.8.8)...")
        try:
            if self.run_command(f"{self.exec_cmd} 'ping -c 2 -W 2 8.8.8.8'", check=False, timeout=5):
                print("   [PASS] Container has Internet.")
            else:
                print("   [FAIL] Container cannot reach Internet.")
        except: print("   [FAIL] Error executing ping.")

        print("2. Host <-> Container Link (Ping 192.168.50.1 or 10.13.13.1)...")
        try:
            res1 = self.run_command(f"ping -c 2 -W 2 {ROUTER_LAN_IP}", check=False, timeout=5)
            res2 = self.run_command(f"ping -c 2 -W 2 {CLIENT_GATEWAY_IP}", check=False, timeout=5)
            if res1 or res2:
                print("   [PASS] Host can reach Container.")
            else:
                print("   [FAIL] Host cannot reach Container (Check veth-host).")
        except: print("   [FAIL] Error executing ping.")

        print("3. Host Internet Access (Ping 8.8.8.8)...")
        try:
            if self.run_command("ping -c 2 -W 2 8.8.8.8", check=False, timeout=5):
                print("   [PASS] Host has IP connectivity.")
            else:
                print("   [FAIL] Host cannot reach Internet (Routing Issue).")
        except: print("   [FAIL] Error executing ping.")

        print("4. Host DNS Resolution (Ping google.com)...")
        try:
            if self.run_command("ping -c 2 -W 2 google.com", check=False, timeout=5):
                print("   [PASS] Host DNS is working.")
            else:
                print("   [FAIL] Host DNS failed (Resolution Error).")
        except: print("   [FAIL] Error executing ping.")

        print("="*40 + "\n")


    # --- Optimization Methods ---
    def enable_aqm(self):
        print("      [Optimization] Enabling FQ_CoDel AQM...")
        self.run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan0 root fq_codel 2>/dev/null || true'")
        if self.moved_eth and self.eth_interface:
            self.run_command(f"{self.exec_cmd} 'tc qdisc add dev {self.eth_interface} root fq_codel 2>/dev/null || true'")

    def optimize_wifi(self):
        print("      [Optimization] Disabling WiFi Power Save...")
        self.run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 addrgenmode none' 2>/dev/null || true")

    # --- Mode: AP (Router Mode - Exclusive Hardware) ---
    def setup_ap_mode_router(self, ssid, password, channel, ctr_pid):
        print(f"[4/5] Configuring Container as Dedicated Router...")

        # 1. Move Ethernet to Container (WAN)
        has_wan = self.move_ethernet_card(ctr_pid)
        wan_iface = self.eth_interface if has_wan else "eth0"

        # 2. Setup LAN Bridge (WiFi + Veth for Host)
        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")

        self.run_command(f"{self.exec_cmd} 'ip link add name br0 type bridge'")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip link set br0 up'")
        self.run_command(f"{self.exec_cmd} 'brctl addif br0 {VETH_CTR}'")

        # 3. Gateway IP
        self.run_command(f"{self.exec_cmd} 'ip addr add {ROUTER_LAN_IP}/24 dev br0'")

        # 4. Host Connectivity
        print("      [Host] Connecting Host to Container LAN...")
        self.run_command(f"ip link set {VETH_HOST} up")

        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)

        nm_cmd = (f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} "
                  f"ip4 {HOST_LAN_IP}/24 gw4 {ROUTER_LAN_IP} connection.zone trusted "
                  f"ipv4.route-metric 20 ipv4.dns '8.8.8.8' ipv4.ignore-auto-dns yes")

        self.run_command(nm_cmd)
        self.run_command(f"nmcli connection up {NM_CONN_NAME}")

        # 5. NAT
        if has_wan:
            print(f"      [Routing] Enabling NAT: br0 (LAN) -> {wan_iface} (WAN)...")
            self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE'")
            self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i br0 -o {wan_iface} -j ACCEPT'")
            self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {wan_iface} -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT'")

        print(f"      Starting AP '{ssid}' on Channel {channel} (5GHz AX)...")

        hostapd_conf = f"""interface=wlan0
bridge=br0
ssid={ssid}
country_code=US
hw_mode=a
channel={channel}
wmm_enabled=1
ieee80211n=1
ieee80211ac=1
vht_oper_chwidth=0
vht_capab=
ieee80211ax=1
he_oper_chwidth=0
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
            raise e

        self.enable_aqm()

        dnsmasq_conf = f"""interface=br0
dhcp-range={DHCP_RANGE}
dhcp-option=3,{ROUTER_LAN_IP}
dhcp-option=6,8.8.8.8"""
        self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self.run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

        self.run_diagnostics()

    # --- Mode: Client (Guest) ---
    def setup_client_mode_with_discovery(self, ssid, password, ctr_pid):
        print(f"[4/5] Connecting to '{ssid}' (Client Mode)...")

        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {CLIENT_GATEWAY_IP}/24 dev {VETH_CTR}'")

        self.run_command(f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {CLIENT_HOST_IP}/24 gw4 {CLIENT_GATEWAY_IP} connection.zone trusted")
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

        # --- NAT & PORT FORWARDING (Crucial for USBIP) ---
        print("      [Routing] Configuring NAT and USBIP Forwarding...")

        # 1. Masquerade Outbound (Standard Internet)
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

        # 2. Forwarding (Allow Host -> WiFi)
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")

        # 3. [NEW] Port Forwarding for USBIP (Incoming 3240 -> Host)
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 3240 -j DNAT --to-destination {CLIENT_HOST_IP}:3240'")
        self.run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -p tcp --dport 3240 -j ACCEPT'")

        self.enable_aqm()

        self.run_command(f"{self.exec_cmd} 'dbus-uuidgen > /var/lib/dbus/machine-id'", check=False)
        self.run_command(f"{self.exec_cmd} 'mkdir -p /var/run/dbus'", check=False)
        self.run_command(f"{self.exec_cmd} 'dbus-daemon --system --fork'")
        self.run_command(f"{self.exec_cmd} 'avahi-daemon -D'")

        self.run_diagnostics()

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

        print("Restoring Interfaces to Host...")
        time.sleep(2)
        try:
            iface = self.get_active_wifi_interface()
            self.run_command(f"nmcli device connect {iface}", check=False)
        except: pass

        try:
            eth = self.eth_interface if self.eth_interface else "eno1"
            self.run_command(f"nmcli device connect {eth}", check=False)
        except: pass

def get_reproduce_command(mode, ssid, password, channel=165):
    script_path = os.path.abspath(sys.argv[0])
    base = f"sudo {sys.executable} {script_path} --mode {mode} --ssid '{ssid}' --password '{password}'"
    if mode == 'ap':
        base += f" --channel {channel}"
    return base

def main():
    parser = argparse.ArgumentParser(description="WiFi Container Bridge (Router Mode)")
    parser.add_argument("--mode", choices=['ap', 'client'], help="Mode: 'ap' (Router) or 'client' (Join WiFi)")
    parser.add_argument("--ssid", help="SSID name")
    parser.add_argument("--password", help="WiFi Password")
    parser.add_argument("--channel", type=int, default=165, help="WiFi Channel")
    parser.add_argument("--clean", action='store_true', help="Cleanup existing containers and exit")
    args = parser.parse_args()

    vpn = ContainerNetwork()
    vpn.check_root()

    if args.clean:
        vpn.shutdown_on_exit = True
        vpn.cleanup()
        return

    ssid = args.ssid
    password = args.password
    mode = args.mode
    channel = args.channel
    interactive = (not mode or not ssid or not password)

    try:
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
            print("\n" + "="*40 + "\n  WIFI CONTAINER (ROUTER MODE)\n" + "="*40)
            print("1. Client Mode (Join WiFi)")
            print("2. AP Mode (Router: WiFi + Ethernet in Container)")
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
                print("  165 = 5 GHz High (Default)")
                print("  36  = 5 GHz Low")
                ch_in = input("Channel [165]: ").strip()
                channel = int(ch_in) if ch_in.isdigit() else 165
            else: sys.exit(1)

        vpn.initialize_container()
        ctr_pid = vpn.move_wifi_card()

        if mode == 'client':
            vpn.setup_client_mode_with_discovery(ssid, password, ctr_pid)
            print(f"\n[CONNECTED] IP: {vpn.get_container_ip()}")
        elif mode == 'ap':
            # This will move Ethernet into container and set up Host as a client
            vpn.setup_ap_mode_router(ssid, password, channel, ctr_pid)
            print(f"\n[ROUTER ACTIVE] AP '{ssid}' Created.")
            print("Host is now connected to Container for Internet.")

        print("\n" + "*"*60)
        print(" TO RE-RUN THIS SETUP AUTOMATICALLY, USE:")
        print(f" {get_reproduce_command(mode, ssid, password, channel)}")
        print("*"*60)

        if sys.stdin.isatty():
            print("\nSession Active. Type 'bg' to detach, 'stop' to end.")
            while True:
                user_in = input("> ").strip().lower()
                if user_in == 'bg': vpn.save_session(mode, ssid); vpn.shutdown_on_exit = False; break
                elif user_in == 'stop': vpn.clear_session(); break
        else:
            print("\n[Running in Background/Headless]. Press Ctrl+C to stop.")
            def handler(signum, frame): raise KeyboardInterrupt
            signal.signal(signal.SIGINT, handler)
            signal.signal(signal.SIGTERM, handler)
            signal.pause()

    except KeyboardInterrupt: print("\nStopping...")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        vpn.cleanup()

if __name__ == "__main__":
    main()
