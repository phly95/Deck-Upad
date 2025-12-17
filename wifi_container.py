#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import shlex
import traceback
import json

# --- Configuration ---
CONTAINER_NAME = "vpn-test"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "vpn-ap-ready"
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"
STATE_FILE = "wifi_session.json"

# IPs for the Virtual Cable
IP_CTR = "10.13.13.1"
IP_HOST = "10.13.13.2"
SUBNET_CIDR = "24"

# AP Configuration
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
            if check: raise e
            return None

    def check_root(self):
        if os.geteuid() != 0:
            print("Error: This script must be run as root (sudo).")
            sys.exit(1)

    # --- Session Management ---
    def save_session(self, mode, ssid, password, net_config=None):
        """Saves current config AND the full network state."""
        data = {
            "mode": mode,
            "ssid": ssid,
            "password": password,
            "net_config": net_config
        }
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(data, f)
            os.chmod(STATE_FILE, 0o600)
            if net_config:
                print(f"\n[Session Saved] State (IP: {net_config.get('ip')}) written to {STATE_FILE}")
            else:
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
            if "hostapd" in ps: return "AP Mode"
            if "wpa_supplicant" in ps: return "Client Mode"
        except: pass
        return None

    def get_current_network_state(self):
        """Scrapes IP, CIDR, and Gateway from inside the container."""
        config = {"ip": None, "cidr": "24", "gateway": None}
        try:
            # Get IP and CIDR
            # Output format ex: "    inet 192.168.1.105/24 scope global wlan0"
            ip_line = self.run_command(f"{self.exec_cmd} 'ip -4 addr show wlan0 | grep inet'")
            if ip_line:
                parts = ip_line.split()
                if len(parts) >= 2:
                    cidr_full = parts[1] # 192.168.1.105/24
                    if '/' in cidr_full:
                        config['ip'], config['cidr'] = cidr_full.split('/')
                    else:
                        config['ip'] = cidr_full

            # Get Gateway
            # Output format ex: "default via 192.168.1.1 dev wlan0"
            route_line = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0 | grep default'")
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
                    self.run_command(f"podman exec {CONTAINER_NAME} apk add --no-cache wpa_supplicant iw iptables hostapd dnsmasq iproute2")
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
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

    def optimize_wifi(self):
        print("      Optimizing WiFi Latency (Power Save OFF)...")
        self.run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        # Prevent MAC randomization if supported
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 addrgenmode none' 2>/dev/null || true")

    def setup_client_mode(self, ssid, password, static_config=None):
        print(f"[4/6] Connecting to '{ssid}' (Client Mode)...")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.optimize_wifi()

        psk_cmd = f"wpa_passphrase \"{ssid}\" \"{password}\" > /etc/wpa_supplicant.conf"
        self.run_command(f"{self.exec_cmd} '{psk_cmd}'")
        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf -s'")

        # --- IP ALLOCATION STRATEGY ---
        gateway_ip = "172.16.16.16" # Fallback dummy

        if static_config and static_config.get('ip'):
            print(f"      [RESUME] Taking IP by force: {static_config['ip']}")
            try:
                # 1. Force IP Add
                cidr = static_config.get('cidr', '24')
                ip_cmd = f"ip addr add {static_config['ip']}/{cidr} dev wlan0"
                self.run_command(f"{self.exec_cmd} '{ip_cmd}'")

                # 2. Force Route Add
                gw = static_config.get('gateway')
                if gw:
                    print(f"      [RESUME] Restoring Gateway: {gw}")
                    self.run_command(f"{self.exec_cmd} 'ip route add default via {gw} dev wlan0'")
                    gateway_ip = gw
                else:
                    # Fallback if we somehow lost the gateway
                    print("      [WARN] No saved gateway. Attempting DHCP for route only...")
                    self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")
            except Exception as e:
                print(f"      [ERROR] Static Force Failed: {e}. Falling back to DHCP.")
                self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")
        else:
            print("      Requesting dynamic IP (DHCP)...")
            self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

            # Gateway Detection (Only needed if we used DHCP)
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

        # Ensure default route is strictly via wlan0 inside container
        self.run_command(f"{self.exec_cmd} 'ip route del default 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip route add default via {gateway_ip} dev wlan0 2>/dev/null || true'")

        print("      Enabling DMZ...")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def setup_ap_mode(self, ssid, password):
        print(f"[4/6] Starting Hotspot '{ssid}' (AP Mode)...")
        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {AP_GATEWAY_IP}/24 dev wlan0'")
        self.optimize_wifi()

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
        print("      Enabling DMZ...")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 67 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j ACCEPT'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def show_status(self, mode):
        # We try to read network state, but if we are in resume loop, we might have it in memory
        lan_ip = "Unknown"
        state = self.get_current_network_state()
        if state: lan_ip = state['ip']

        print("\n" + "="*40)
        print(f"   CONNECTION ESTABLISHED ({mode})")
        print("="*40)
        print(f"YOUR WIFI IP:         {lan_ip}")
        print(f"INTERNAL VETH IP:     {IP_HOST}")
        print("-" * 40)
        if mode == "AP Mode":
            print(f"You are the HOST. Clients: 192.168.50.10 - 50")
        else:
            print(f"You are a CLIENT. Host IP: 192.168.50.1")
        print("="*40)
        print(" [Enter] or 'stop' : Full Cleanup & Exit")
        print(" 'pause'           : Save Session (IP+SSID), Cleanup & Exit")
        print(" 'bg'              : Detach (Run in Background)")
        print("="*40)

def main():
    vpn = ContainerVPN()
    vpn.check_root()
    try:
        # --- RESUME ATTACH (Already Running) ---
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

        saved_session = vpn.load_session()
        use_saved = False

        if saved_session:
            print(f"\n[?] PAUSED SESSION FOUND: {saved_session['mode']}")
            print(f"    SSID: {saved_session['ssid']}")
            nc = saved_session.get('net_config')
            if nc:
                print(f"    IP:   {nc.get('ip')} (Gateway: {nc.get('gateway')})")

            choice = input("    Resume this session? (Y/n): ").strip().lower()
            if choice != 'n':
                use_saved = True
                ssid = saved_session['ssid']
                password = saved_session['password']
                net_config = saved_session.get('net_config')
                mode_code = '1' if saved_session['mode'] == 'Client Mode' else '2'
            else:
                vpn.clear_session()

        # --- MANUAL SETUP ---
        if not use_saved:
            print(f"Detected WiFi: {vpn.wifi_interface}")
            print("\nSelect Mode:\n1. Client (Join)\n2. Host (Create AP)")
            while True:
                c = input("Choice (1/2): ")
                if c in ['1','2']:
                    mode_code = c
                    break

            if mode_code == '1':
                nets = vpn.scan_wifi()
                print("\nNetworks:")
                for i, n in enumerate(nets): print(f"{i+1}: {n}")
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
        else:
            active_mode_str = "AP Mode"
            vpn.setup_ap_mode(ssid, password)
            vpn.setup_veth_link(ctr_pid, is_client_mode=False)

        vpn.show_status(active_mode_str)

        # --- INPUT LOOP ---
        user_in = input().strip().lower()

        if user_in == 'bg':
            vpn.shutdown_on_exit = False
        elif user_in == 'pause':
            # Grab Full Network Config before destroying container
            nc = vpn.get_current_network_state()
            vpn.save_session(active_mode_str, ssid, password, net_config=nc)
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
