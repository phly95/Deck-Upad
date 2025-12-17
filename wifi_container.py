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
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"

# IPs for the Virtual Cable
IP_CTR = "10.13.13.1"
IP_HOST = "10.13.13.2"
SUBNET_CIDR = "24"

# AP Configuration
AP_GATEWAY_IP = "192.168.50.1"
AP_DHCP_RANGE = "192.168.50.10,192.168.50.50,12h"

# Host-Side Session Persistence (Clears on Reboot)
HOST_SESSION_FILE = "/var/run/wifi_container_session.conf"

class ContainerVPN:
    def __init__(self):
        self.wifi_interface = self.get_active_wifi_interface()
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"
        self.shutdown_on_exit = True
        self.is_pausing = False

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

    # --- Session Management (Host Side) ---
    def save_session_host(self, mode, ssid, password):
        """Saves session to Host /var/run so we can survive container death."""
        content = f"{mode}\n{ssid}\n{password}\n{self.wifi_interface}"
        try:
            with open(HOST_SESSION_FILE, "w") as f:
                f.write(content)
            os.chmod(HOST_SESSION_FILE, 0o600)
        except Exception as e:
            print(f"Warning: Could not save session: {e}")

    def load_session_host(self):
        if not os.path.exists(HOST_SESSION_FILE):
            return None
        try:
            with open(HOST_SESSION_FILE, "r") as f:
                lines = f.read().splitlines()
            if len(lines) >= 3:
                return lines
        except: pass
        return None

    def clear_session_host(self):
        if os.path.exists(HOST_SESSION_FILE):
            os.remove(HOST_SESSION_FILE)

    def is_container_running(self):
        res = self.run_command(f"podman ps -q -f name={CONTAINER_NAME}", check=False)
        return bool(res)

    def get_container_pid(self):
        try:
            return self.run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
        except: return None

    # --- WiFi Utils ---
    def get_active_wifi_interface(self):
        try:
            output = self.run_command("nmcli -t -f DEVICE,TYPE,STATE device")
            for line in output.split('\n'):
                if ":wifi:" in line: return line.split(':')[0]
        except: pass
        try:
            output = self.run_command("iw dev | grep Interface", shell=True)
            if output: return output.split()[-1]
        except: pass
        return "wlp9s0" # Fallback

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

    # --- ACTION HANDLERS ---
    def trigger_pause(self):
        print("\n[PAUSING SESSION]")
        self.is_pausing = True
        self.shutdown_on_exit = True
        sys.exit(0)

    def trigger_bg(self):
        print("\n[BACKGROUND MODE] Detaching script.")
        self.shutdown_on_exit = False
        sys.exit(0)

    def force_restore_host_wifi(self):
        print("Restoring Host WiFi...")
        self.run_command("rfkill unblock wifi", check=False)
        time.sleep(1)

        target_iface = self.wifi_interface
        # Check if name changed back
        try:
            out = self.run_command("iw dev | grep Interface", shell=True)
            if out: target_iface = out.split()[-1]
        except: pass

        self.run_command(f"ip link set {target_iface} up", check=False)
        self.run_command(f"nmcli device set {target_iface} managed yes", check=False)
        self.run_command(f"nmcli device connect {target_iface}", check=False)

    def cleanup(self):
        if not self.shutdown_on_exit:
            return

        print("\n\n--- Cleaning Up ---")
        self.run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self.run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self.run_command(f"ip link delete {VETH_HOST}", check=False)

        print("Stopping container (Releasing WiFi Card)...")
        self.run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        self.force_restore_host_wifi()

        if self.is_pausing:
            print(f"Session saved to {HOST_SESSION_FILE}")
            print("Run script again to RESUME.")
        else:
            print("Session cleared.")
            self.clear_session_host()

    # --- SETUP LOGIC ---
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
                        time.sleep(5)
                    else: raise
            print(f"      Caching image to '{CUSTOM_IMAGE}'...")
            self.run_command(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        else:
            print("[2/6] Using Cached Tools (Offline Ready).")

    def move_wifi_card(self):
        print(f"[3/6] Moving {self.wifi_interface} to container...")
        self.run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self.get_container_pid()
        self.run_command(f"iw phy phy0 set netns {ctr_pid}")
        return ctr_pid

    def setup_veth_link(self, ctr_pid, is_client_mode):
        print(f"[5/6] Creating High-Speed Veth Link...")
        self.run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self.run_command(f"ip link set {VETH_HOST} txqueuelen 1000")
        self.run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self.run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self.run_command(f"{self.exec_cmd} 'ip addr add {IP_CTR}/{SUBNET_CIDR} dev {VETH_CTR}'")

        nm_cmd = f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {IP_HOST}/{SUBNET_CIDR}"
        if is_client_mode:
            nm_cmd += f" gw4 {IP_CTR}"

        self.run_command(nm_cmd)

        metric = "50" if is_client_mode else "600"
        self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.route-metric {metric}")
        if is_client_mode: self.run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.dns '8.8.8.8'")

        self.run_command(f"nmcli connection up {NM_CONN_NAME}")
        self.run_command(f"ip route add 192.168.50.0/24 via {IP_CTR} dev {VETH_HOST}", check=False)
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")

    def optimize_wifi(self):
        self.run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")

    def setup_client_mode(self, ssid, password):
        print(f"[4/6] Connecting to '{ssid}' (Client Mode)...")
        self.save_session_host("client", ssid, password)

        self.run_command(f"{self.exec_cmd} 'iw phy phy0 interface add wlan0 type managed 2>/dev/null || true'")
        self.run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self.optimize_wifi()

        # --- SAFE CONFIG GENERATION ---
        # We calculate the config in Python to avoid shell injection issues with special chars
        try:
            # Generate config block using wpa_passphrase locally via python wrapper
            safe_cmd = f"wpa_passphrase {shlex.quote(ssid)} {shlex.quote(password)}"
            block = self.run_command(f"{self.exec_cmd} '{safe_cmd}'")

            header = "ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\nnetwork={\n"
            full_conf = header + block[block.find("network={") + 9:] # clean append

            # Write to file safely
            self.run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wpa_supplicant.conf'", shell=True, input=full_conf)
        except Exception as e:
            print(f"Error generating config: {e}")
            sys.exit(1)

        self.run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf -s'")

        # --- WAIT FOR CONNECTION (FIX FOR DHCP) ---
        print("      Waiting for association...")
        connected = False
        for i in range(40):
            status = self.run_command(f"{self.exec_cmd} 'wpa_cli -i wlan0 status'")
            state = "UNKNOWN"
            if status:
                for line in status.split('\n'):
                    if line.startswith("wpa_state="):
                        state = line.split('=')[1]
                        break

            sys.stdout.write(f"\r      Status: {state} ({i}s)   ")
            sys.stdout.flush()

            if state == "COMPLETED":
                print("\n      [OK] Associated!")
                connected = True
                break
            time.sleep(1)

        if not connected:
            print("\n      [WARNING] Connection timed out. Password might be wrong.")

        print("      Requesting IP (DHCP)...")
        self.run_command(f"{self.exec_cmd} 'udhcpc -i wlan0'")

        # Gateway Fix
        gateway_ip = "192.168.1.1"
        try:
            out = self.run_command(f"{self.exec_cmd} 'ip route show dev wlan0'")
            for line in out.split('\n'):
                if 'src' in line:
                    parts = line.split()
                    subnet = parts[0].split('.')
                    gateway_ip = f"{subnet[0]}.{subnet[1]}.{subnet[2]}.1"
                    break
        except: pass

        self.run_command(f"{self.exec_cmd} 'ip route del default || true'")
        self.run_command(f"{self.exec_cmd} 'ip route add default via {gateway_ip} dev wlan0'")
        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def setup_ap_mode(self, ssid, password):
        print(f"[4/6] Starting Hotspot '{ssid}'...")
        self.save_session_host("ap", ssid, password)

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

        self.run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -j DNAT --to-destination {IP_HOST}'")

    def show_status(self, mode):
        lan_ip = "Unknown"
        try: lan_ip = self.run_command(f"{self.exec_cmd} 'ip -4 addr show wlan0 | grep inet | awk \"{{print \\$2}}\"'").split('/')[0]
        except: pass

        print("\n" + "="*40)
        print(f"   CONNECTION ESTABLISHED ({mode})")
        print("="*40)
        print(f"YOUR WIFI IP:         {lan_ip}")
        print(f"INTERNAL VETH IP:     {IP_HOST}")
        print("-" * 40)
        print(" 1. Press ENTER to Stop and Cleanup (Session Cleared).")
        print(" 2. Type 'bg' to Detach (Run in Background).")
        print(" 3. Type 'pause' to Pause (Give Wifi back to OS, Save Session).")
        print("="*40)

        val = input().strip().lower()
        if val == 'bg': self.trigger_bg()
        elif val == 'pause': self.trigger_pause()

def main():
    vpn = ContainerVPN()
    vpn.check_root()
    try:
        saved = vpn.load_session_host()
        if saved:
            mode, ssid, pw = saved[0], saved[1], saved[2]
            print(f"\n[!] Found saved session ({mode}). Resuming automatically...")

            if vpn.is_container_running():
                vpn.run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

            vpn.initialize_container()
            ctr_pid = vpn.move_wifi_card()

            if mode == 'client':
                vpn.setup_client_mode(ssid, pw)
                vpn.setup_veth_link(ctr_pid, is_client_mode=True)
                vpn.show_status("Client Mode")
            else:
                vpn.setup_ap_mode(ssid, pw)
                vpn.setup_veth_link(ctr_pid, is_client_mode=False)
                vpn.show_status("AP Mode")
            return

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
                    ssid = nets[int(sel)-1]
                    break
                elif sel: ssid = sel; break
        else:
            ssid = input("Enter new SSID: ")

        pw = input(f"Password for {ssid}: ")

        vpn.initialize_container()
        ctr_pid = vpn.move_wifi_card()

        if c == '1':
            vpn.setup_client_mode(ssid, pw)
            vpn.setup_veth_link(ctr_pid, is_client_mode=True)
            vpn.show_status("Client Mode")
        else:
            vpn.setup_ap_mode(ssid, pw)
            vpn.setup_veth_link(ctr_pid, is_client_mode=False)
            vpn.show_status("AP Mode")

    except KeyboardInterrupt: print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
    finally: vpn.cleanup()

if __name__ == "__main__":
    main()
