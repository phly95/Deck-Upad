import subprocess
import time
import sys
import os
import shlex
import re
import shutil
import json

# --- Configuration Constants ---
CONTAINER_NAME = "wifi-bridge"
BASE_IMAGE = "alpine:latest"
CUSTOM_IMAGE = "wifi-bridge-ready"

# Host Mode Network Config
NM_CONN_NAME = "veth-host-conn"
VETH_HOST = "veth-host"
VETH_CTR = "veth-ctr"

ROUTER_LAN_IP = "192.168.50.1"
DHCP_RANGE = "192.168.50.10,192.168.50.100,12h"
HOST_LAN_IP = "192.168.50.2"

# Client Mode Network Config
CLIENT_GATEWAY_IP = "10.13.13.1"
CLIENT_HOST_IP = "10.13.13.2"

# Ports to forward (UDP/TCP)
FWD_PORT_RANGE = "2000:65535"

class WifiManager:
    def __init__(self):
        self.wifi_interface = self._get_active_wifi_interface()
        self.eth_interface = self._get_host_upstream_interface()

        if self.eth_interface == self.wifi_interface:
            self.eth_interface = None

        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"
        self.moved_eth = False
        self.check_root()

    def check_root(self):
        if os.geteuid() != 0:
            raise PermissionError("WifiManager must be run as root (sudo).")

    def ensure_image_exists(self):
        """
        Ensures the Alpine image with wifi tools exists.
        """
        if self._run_command(f"podman images -q {CUSTOM_IMAGE}", check=False):
            return

        print(f"[WifiManager] Image '{CUSTOM_IMAGE}' not found. Building from '{BASE_IMAGE}'...")
        builder_name = f"{CONTAINER_NAME}-builder"
        self._run_command(f"podman rm -f {builder_name}", check=False)
        self._run_command(f"podman run -d --name {builder_name} {BASE_IMAGE} sleep infinity")

        try:
            # Install tools
            pkgs = "wpa_supplicant iw iptables hostapd dnsmasq iproute2 iproute2-tc bridge-utils avahi avahi-tools dbus dhcpcd util-linux"
            print("   Installing dependencies (this may take a moment)...")
            self._run_command(f"podman exec {builder_name} apk add --no-cache {pkgs}")

            print(f"   Committing to {CUSTOM_IMAGE}...")
            self._run_command(f"podman commit {builder_name} {CUSTOM_IMAGE}")
        except Exception as e:
            print(f"[ERROR] Build failed: {e}")
            self._run_command(f"podman stop {builder_name}", check=False)
            raise e
        finally:
            self._run_command(f"podman rm -f {builder_name}", check=False)

    # --- Public API ---

    def start_host_mode(self, ssid, password, channel=165, wifi_mode="ax", country="US"):
        print(f"[WifiManager] Starting HOST mode (AP: {ssid}, Ch: {channel}, Region: {country})...")
        self._initialize_container()

        # 1. Move WiFi Card to Container
        ctr_pid = self._move_wifi_card()

        # 2. Setup AP Logic
        self._setup_ap_logic(ssid, password, channel, ctr_pid, wifi_mode, country)
        print("[WifiManager] Host Mode Ready.")

    def start_client_mode(self, ssid, password, country="US"):
        print(f"[WifiManager] Starting CLIENT mode (Connecting to: {ssid}, Region: {country})...")
        self._initialize_container()

        # 1. Move WiFi Card to Container
        ctr_pid = self._move_wifi_card()

        # 2. Setup Client Logic
        self._setup_client_logic(ssid, password, ctr_pid, country)
        print("[WifiManager] Client Mode Ready.")

    def cleanup(self):
        print("[WifiManager] Cleaning up...")
        self._run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self._run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self._run_command(f"ip link delete {VETH_HOST}", check=False)

        if shutil.which("firewall-cmd"):
            try:
                self._run_command(f"firewall-cmd --remove-port={FWD_PORT_RANGE}/udp", check=False)
                self._run_command(f"firewall-cmd --remove-port={FWD_PORT_RANGE}/tcp", check=False)
            except: pass

        self._run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # Attempt to restore interfaces
        time.sleep(1)
        try:
            iface = self._get_active_wifi_interface() or "wlan0"
            self._run_command(f"nmcli device connect {iface}", check=False)
        except: pass

        if self.eth_interface:
            try:
                self._run_command(f"nmcli device connect {self.eth_interface}", check=False)
            except: pass

    # --- Internal Helpers ---

    def _run_command(self, cmd, shell=False, check=True, input=None, timeout=None):
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, input=input, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            if check:
                print(f"Command failed: {cmd}\nStdout: {e.stdout}\nStderr: {e.stderr}")
                raise e
            return None

    def _get_host_upstream_interface(self):
        try:
            out = self._run_command("ip route get 8.8.8.8", check=False)
            if out:
                match = re.search(r"dev\s+(\S+)", out)
                if match: return match.group(1)
        except: pass
        return None

    def _get_active_wifi_interface(self):
        try:
            output = self._run_command("nmcli -t -f DEVICE,TYPE,STATE device", check=False)
            if output:
                for line in output.split('\n'):
                    if ":wifi:" in line: return line.split(':')[0]
            output = self._run_command("iw dev | grep Interface", shell=True, check=False)
            if output: return output.split()[-1]
        except: pass
        return "wlan0"

    def _initialize_container(self):
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        # 1. Build Image if missing
        self.ensure_image_exists()

        # 2. Start Runtime Container
        print(f"[WifiManager] Starting container '{CONTAINER_NAME}'...")
        podman_run = (
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--net=none "
            "--sysctl net.ipv4.ip_forward=1 "
            f"{CUSTOM_IMAGE} sleep infinity"
        )
        self._run_command(podman_run)

        try:
            ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
            self._run_command(f"chrt -f -p 99 {ctr_pid}", check=False)
        except: pass

    def _move_wifi_card(self):
        phy = "phy0"
        try:
            out = self._run_command(f"iw dev {self.wifi_interface} info", check=False)
            if out:
                m = re.search(r"wiphy\s+(\d+)", out)
                if m: phy = f"phy{m.group(1)}"
        except: pass

        self._run_command(f"nmcli device disconnect {self.wifi_interface}", check=False)
        ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")

        try:
            self._run_command(f"iw phy {phy} set netns {ctr_pid}")
        except Exception as e:
            raise Exception(f"Failed to move {phy} to container. Is wpa_supplicant holding it? {e}")

        time.sleep(1)
        try:
            iw_out = self._run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            found_iface = None
            if iw_out:
                for line in iw_out.split('\n'):
                    if "Interface" in line:
                        found_iface = line.split()[-1]; break
            if found_iface and found_iface != "wlan0":
                self._run_command(f"{self.exec_cmd} 'ip link set {found_iface} name wlan0'")
        except: pass
        return ctr_pid

    def _open_host_ports(self):
        if shutil.which("firewall-cmd"):
            try:
                self._run_command(f"firewall-cmd --zone=trusted --add-interface={VETH_HOST}", check=False)
                self._run_command(f"firewall-cmd --zone=trusted --add-port={FWD_PORT_RANGE}/udp", check=False)
                self._run_command(f"firewall-cmd --zone=trusted --add-port={FWD_PORT_RANGE}/tcp", check=False)
                self._run_command(f"firewall-cmd --add-port={FWD_PORT_RANGE}/udp", check=False)
                self._run_command(f"firewall-cmd --add-port={FWD_PORT_RANGE}/tcp", check=False)
            except: pass
        elif shutil.which("ufw"):
            try:
                self._run_command(f"ufw allow in on {VETH_HOST}", check=False)
                self._run_command(f"ufw allow out on {VETH_HOST}", check=False)
                self._run_command(f"ufw allow from 192.168.50.0/24", check=False)
                self._run_command(f"ufw allow from 10.13.13.0/24", check=False)
            except: pass

    # --- Mode Specific Logic ---

    def _setup_ap_logic(self, ssid, password, channel, ctr_pid, wifi_mode="ax", country="US"):
        has_wan = self._move_ethernet_card(ctr_pid)
        wan_iface = self.eth_interface if has_wan else "eth0"

        # Apply Region
        self._run_command(f"{self.exec_cmd} 'iw reg set {country}'", check=False)

        # Setup VETH
        self._run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self._run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self._run_command(f"{self.exec_cmd} 'ip link add name br0 type bridge'")
        self._run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self._run_command(f"{self.exec_cmd} 'ip link set br0 up'")
        self._run_command(f"{self.exec_cmd} 'brctl addif br0 {VETH_CTR}'")
        self._run_command(f"{self.exec_cmd} 'ip addr add {ROUTER_LAN_IP}/24 dev br0'")

        # Connect Host to Bridge using NetworkManager for correct routing
        self._run_command(f"ip link set {VETH_HOST} up")
        self._run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)

        gw_arg = f"gw4 {ROUTER_LAN_IP}" if has_wan else ""
        dns_arg = "ipv4.dns '8.8.8.8'" if has_wan else ""

        nm_cmd = (f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} "
                  f"ip4 {HOST_LAN_IP}/24 {gw_arg} connection.zone trusted "
                  f"ipv4.route-metric 20 {dns_arg} ipv4.ignore-auto-dns yes")

        self._run_command(nm_cmd)
        self._run_command(f"nmcli connection up {NM_CONN_NAME}")

        self._open_host_ports()

        # NAT / Routing
        if has_wan:
            self._run_command(f"{self.exec_cmd} 'sysctl -w net.ipv4.ip_forward=1'")
            self._run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE'")
            self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i br0 -o {wan_iface} -j ACCEPT'")
            self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {wan_iface} -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT'")

        self._run_command(f"{self.exec_cmd} 'iptables -P FORWARD ACCEPT'", check=False)

        # Hostapd Config
        is_5ghz = int(channel) > 14
        hw_mode = "a" if is_5ghz else "g"

        enable_ac = 0
        enable_ax = 0

        if is_5ghz:
            if wifi_mode in ["ac", "ax"]: enable_ac = 1
            if wifi_mode == "ax": enable_ax = 1

        hostapd_conf = f"""interface=wlan0
bridge=br0
ssid={ssid}
country_code={country}
hw_mode={hw_mode}
channel={channel}
wmm_enabled=1
ieee80211n=1
ieee80211ac={enable_ac}
ieee80211ax={enable_ax}
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP"""

        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/hostapd/hostapd.conf'", shell=True, input=hostapd_conf)

        self._run_command(f"{self.exec_cmd} 'rfkill unblock all'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self._run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        self._run_command(f"{self.exec_cmd} 'hostapd -B /etc/hostapd/hostapd.conf'")
        self._run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan0 root fq_codel 2>/dev/null || true'")

        # DNS/DHCP
        dnsmasq_conf = f"""interface=br0
dhcp-range={DHCP_RANGE}
dhcp-option=3,{ROUTER_LAN_IP}
dhcp-option=6,8.8.8.8"""
        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self._run_command(f"{self.exec_cmd} 'dnsmasq -C /etc/dnsmasq.conf'")

    def _setup_client_logic(self, ssid, password, ctr_pid, country="US"):
        self._run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self._run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self._run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self._run_command(f"{self.exec_cmd} 'ip addr add {CLIENT_GATEWAY_IP}/24 dev {VETH_CTR}'")

        self._run_command(f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {CLIENT_HOST_IP}/24 gw4 {CLIENT_GATEWAY_IP} connection.zone trusted")
        self._run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.dns '8.8.8.8'")
        self._run_command(f"nmcli connection up {NM_CONN_NAME}")

        # Apply Region
        self._run_command(f"{self.exec_cmd} 'iw reg set {country}'", check=False)

        wpa_conf = f"""ctrl_interface=/var/run/wpa_supplicant
update_config=1
country={country}
network={{
    ssid="{ssid}"
    psk="{password}"
}}
"""
        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /etc/wpa_supplicant.conf'", shell=True, input=wpa_conf)
        self._run_command(f"{self.exec_cmd} 'rfkill unblock all'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self._run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")

        self._run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf'")

        for _ in range(15):
            status = self._run_command(f"{self.exec_cmd} 'wpa_cli status'", check=False)
            if status and "wpa_state=COMPLETED" in status: break
            time.sleep(1)

        self._run_command(f"{self.exec_cmd} 'ip route flush default'", check=False)

        # Critical: Fail if DHCP fails so main script stops
        try:
            self._run_command(f"{self.exec_cmd} 'udhcpc -i wlan0 -n -q -f -t 5'")
        except subprocess.CalledProcessError:
            raise Exception("DHCP Request failed. Is the Host (Deck-Upad PC) running?")

        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")
        self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")
        self._run_command(f"{self.exec_cmd} 'iptables -P FORWARD ACCEPT'", check=False)

        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport {FWD_PORT_RANGE} -j DNAT --to-destination {CLIENT_HOST_IP}'")
        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport {FWD_PORT_RANGE} -j DNAT --to-destination {CLIENT_HOST_IP}'")

        self._run_command(f"{self.exec_cmd} 'dbus-uuidgen > /var/lib/dbus/machine-id'", check=False)
        self._run_command(f"{self.exec_cmd} 'mkdir -p /var/run/dbus'", check=False)
        self._run_command(f"{self.exec_cmd} 'dbus-daemon --system --fork'")
        self._run_command(f"{self.exec_cmd} 'avahi-daemon -D'")

    def _move_ethernet_card(self, ctr_pid):
        if not self.eth_interface: return False

        self._run_command(f"nmcli device disconnect {self.eth_interface}", check=False)
        time.sleep(1)
        try:
            self._run_command(f"ip link set {self.eth_interface} netns {ctr_pid}")
            self.moved_eth = True
        except: return False

        self._run_command(f"{self.exec_cmd} 'ip route flush default'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set {self.eth_interface} up'")
        time.sleep(2)
        try:
            subprocess.run(shlex.split(f"{self.exec_cmd} 'udhcpc -i {self.eth_interface} -n -q -f -t 5'"),
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except: pass
        return True
