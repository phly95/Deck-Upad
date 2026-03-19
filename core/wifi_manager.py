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
        self.exec_cmd = f"podman exec {CONTAINER_NAME} /bin/sh -c"
        self.check_root()

    def check_root(self):
        if os.geteuid() != 0:
            raise PermissionError("WifiManager must be run as root (sudo).")

    def ensure_image_exists(self):
        if self._run_command(f"podman images -q {CUSTOM_IMAGE}", check=False):
            return

        print(f"[WifiManager] Image '{CUSTOM_IMAGE}' not found. Building from '{BASE_IMAGE}'...")
        builder_name = f"{CONTAINER_NAME}-builder"
        self._run_command(f"podman rm -f {builder_name}", check=False)
        self._run_command(f"podman run -d --net=host --name {builder_name} {BASE_IMAGE} sleep infinity")

        try:
            pkgs = "wpa_supplicant iw iptables hostapd dnsmasq iproute2 iproute2-tc bridge-utils avahi avahi-tools dbus dhcpcd util-linux"
            print("   Installing dependencies (this may take a moment)...")
            self._run_command(f"podman exec {builder_name} apk add --no-cache {pkgs}")
            self._run_command(f"podman commit {builder_name} {CUSTOM_IMAGE}")
        except Exception as e:
            print(f"[ERROR] Build failed: {e}")
            self._run_command(f"podman stop {builder_name}", check=False)
            raise e
        finally:
            self._run_command(f"podman rm -f {builder_name}", check=False)

    # --- Public API ---

    def start_host_mode(self, ssid, password, channel=165, wifi_mode="ax", country="US",
                        p2p_iface=None, internet_iface="none", internet_ssid=None, internet_pass=None,
                        bootstrap_ssid=None, bootstrap_pass=None):

        # 1. Determine Interfaces
        wifi_interface = p2p_iface if p2p_iface else self._get_active_wifi_interface()
        print(f"[WifiManager] Starting HOST mode on {wifi_interface} (AP: {ssid}, Region: {country})...")

        # Handle bootstrap-host mode: connect to WiFi on HOST to unlock regulatory domain BEFORE moving to container
        if country.lower() == "bootstrap-host" and bootstrap_ssid:
            print(f"[WifiManager] Bootstrap mode (host): Connecting to {bootstrap_ssid} on host to unlock channels...")
            self._bootstrap_regulatory_unlock(wifi_interface, bootstrap_ssid, bootstrap_pass)
            country = "inherit"

        self._initialize_container()

        # Handle bootstrap-container mode: single container exploit
        # If active, we SKIP the normal _move_wifi_card below, because the bootstrap handles moving it.
        if country.lower() == "bootstrap-container" and bootstrap_ssid:
            print(f"[WifiManager] Bootstrap mode (container exploit): Connecting to {bootstrap_ssid}...")
            self._bootstrap_regulatory_unlock_container(wifi_interface, bootstrap_ssid, bootstrap_pass)
            ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
            country = "inherit"
        else:
            # 2. Normal Mode: Move P2P Interface to Container directly
            ctr_pid = self._move_wifi_card(wifi_interface, "wlan0", country)

        # 3. Handle Internet Interface
        has_wan = False
        wan_iface = "eth0" # Default name inside if wired

        if internet_iface and internet_iface.lower() != "none":
            print(f"[WifiManager] Configuring Internet via {internet_iface}...")

            is_wifi_wan = self._is_interface_wifi(internet_iface)

            if is_wifi_wan:
                # Upstream WiFi Logic
                wan_iface = "wlan1" # Rename to wlan1 inside
                self._move_wifi_card(internet_iface, wan_iface, country)
                self._connect_upstream_wifi(wan_iface, internet_ssid, internet_pass, country)
                has_wan = True
            else:
                # Wired/Ethernet Logic
                has_wan = self._move_ethernet_card(internet_iface, ctr_pid)
                wan_iface = internet_iface

        # 4. Setup AP & Routing
        self._setup_ap_logic(ssid, password, channel, ctr_pid, wifi_mode, country, has_wan, wan_iface)
        print("[WifiManager] Host Mode Ready.")

    def start_client_mode(self, ssid, password, country="US"):
        print(f"[WifiManager] Starting CLIENT mode (Connecting to: {ssid}, Region: {country})...")
        wifi_interface = self._get_active_wifi_interface()

        self._initialize_container()
        ctr_pid = self._move_wifi_card(wifi_interface, "wlan0", country)
        self._setup_client_logic(ssid, password, ctr_pid, country)
        print("[WifiManager] Client Mode Ready.")

    def cleanup(self):
        print("[WifiManager] Cleaning up...")
        self._run_command(f"nmcli connection down {NM_CONN_NAME}", check=False)
        self._run_command(f"nmcli connection delete {NM_CONN_NAME}", check=False)
        self._run_command(f"ip link delete {VETH_HOST}", check=False)

        if shutil.which("firewall-cmd"):
            try: self._run_command(f"firewall-cmd --zone=trusted --remove-interface={VETH_HOST}", check=False)
            except: pass

        self._run_command(f"podman stop -t 0 {CONTAINER_NAME}", check=False)
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)

        time.sleep(1)
        # Attempt to restore NM on common interfaces
        try:
            self._run_command("nmcli device connect wlan0", check=False)
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

    def _is_interface_wifi(self, iface):
        return os.path.exists(f"/sys/class/net/{iface}/wireless")

    def _initialize_container(self):
        self._run_command(f"podman rm -f {CONTAINER_NAME}", check=False)
        self.ensure_image_exists()
        print(f"[WifiManager] Starting container '{CONTAINER_NAME}'...")

        podman_run = (
            f"podman run -d --name {CONTAINER_NAME} --replace "
            "--privileged "
            "--security-opt label=disable "
            "--net=none "
            "--sysctl net.ipv4.ip_forward=1 "
            "--tmpfs /tmp "
            "--tmpfs /run "
            f"{CUSTOM_IMAGE} sleep infinity"
        )
        self._run_command(podman_run)
        try:
            ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")
            self._run_command(f"chrt -f -p 99 {ctr_pid}", check=False)
        except: pass

    def _move_wifi_card(self, host_iface, container_name, country=None):
        phy = "phy0"
        try:
            out = self._run_command(f"iw dev {host_iface} info", check=False)
            if out:
                m = re.search(r"wiphy\s+(\d+)", out)
                if m: phy = f"phy{m.group(1)}"
        except: pass

        if country and country.lower() not in["inherit", "bootstrap", "bootstrap-host", "bootstrap-container", "none", ""]:
            print(f"[WifiManager] Setting regulatory domain to {country} on host...")
            self._run_command(f"iw reg set {country}")
            time.sleep(0.5)

        self._run_command(f"nmcli device disconnect {host_iface}", check=False)
        ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")

        try:
            self._run_command(f"iw phy {phy} set netns {ctr_pid}")
        except Exception as e:
            raise Exception(f"Failed to move {phy} ({host_iface}) to container. Is NM/wpa_supplicant holding it? {e}")

        time.sleep(1)
        # Rename inside container
        try:
            iw_out = self._run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            current_name = None
            if iw_out:
                sections = iw_out.split("phy#")
                for sec in sections:
                    if sec.startswith(phy.replace("phy", "")):
                        m = re.search(r"Interface\s+(\S+)", sec)
                        if m: current_name = m.group(1)

            if current_name and current_name != container_name:
                 self._run_command(f"{self.exec_cmd} 'ip link set {current_name} name {container_name}'")

            self._run_command(f"{self.exec_cmd} 'ip link set {container_name} up'")
        except: pass
        return ctr_pid

    def _bootstrap_regulatory_unlock(self, iface_name, ssid, password):
        try:
            self._run_command(f"nmcli device disconnect {iface_name}", check=False)
            time.sleep(1)

            print(f"[WifiManager] Connecting to {ssid} on host...")
            connect_cmd = f"nmcli device wifi connect '{ssid}'"
            if password:
                connect_cmd += f" password '{password}'"
            connect_cmd += f" ifname {iface_name}"

            result = self._run_command(connect_cmd, check=False)
            if result is None:
                print(f"[WifiManager] Warning: Could not connect to bootstrap network")
                return

            print(f"[WifiManager] Connected! Waiting for regulatory unlock...")
            time.sleep(3)

            iw_out = self._run_command(f"iw list | grep -E '5180.*MHz.*\\[36\\]'", check=False)
            if iw_out and "no IR" not in iw_out.lower():
                print(f"[WifiManager] Channel 36 appears unlocked on host!")
            else:
                print(f"[WifiManager] Channel 36 still has restrictions, but continuing anyway...")

            print(f"[WifiManager] Disconnecting from bootstrap network (keeping regulatory state)...")
            self._run_command(f"nmcli connection down '{ssid}'", check=False)
            time.sleep(0.5)
            print(f"[WifiManager] Bootstrap complete. Moving interface to container...")

        except Exception as e:
            print(f"[WifiManager] Bootstrap failed (continuing anyway): {e}")

    def _bootstrap_regulatory_unlock_container(self, host_iface, ssid, password):
        """
        Bootstrap workaround using the MAIN CONTAINER but exploiting namespace hops:
        1. Move WiFi PHY to main container
        2. Connect to WiFi (unlocks channels)
        3. Yank PHY out to Host OS (freezes unlocked state)
        4. Push PHY back into main container
        """
        try:
            print(f"[WifiManager] Bootstrap mode (single-container exploit): Preparing...")

            # 0. Disconnect from Host OS NetworkManager
            self._run_command(f"nmcli device disconnect {host_iface}", check=False)
            time.sleep(1)

            # 1. Get PHY name from host before we start
            phy = "phy0"
            try:
                out = self._run_command(f"iw dev {host_iface} info", check=False)
                if out:
                    m = re.search(r"wiphy\s+(\d+)", out)
                    if m:
                        phy = f"phy{m.group(1)}"
            except: pass

            print(f"[WifiManager] Using Host PHY: {phy}")

            # Get main container PID (already created by _initialize_container)
            ctr_pid = self._run_command(f"podman inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}")

            # 2. Move PHY to main container
            print(f"[WifiManager] Moving {phy} to main container...")
            self._run_command(f"iw phy {phy} set netns {ctr_pid}")
            time.sleep(1)

            # RENAME interface to wlan0 inside container
            iw_out = self._run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            if iw_out:
                m = re.search(r"Interface\s+(\S+)", iw_out)
                if m:
                    current_name = m.group(1)
                    if current_name != "wlan0":
                        self._run_command(f"{self.exec_cmd} 'ip link set {current_name} name wlan0'")

            # 3. Configure and connect in container
            print(f"[WifiManager] Configuring WiFi in container...")
            self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'", check=False)
            time.sleep(1)

            wpa_conf = f"""ctrl_interface=/tmp/wpa_supplicant
update_config=1
network={{
    ssid="{ssid}"
    {f'psk="{password}"' if password else 'key_mgmt=NONE'}
}}
"""
            self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /tmp/wpa_bootstrap.conf'", shell=True, input=wpa_conf)

            print(f"[WifiManager] Connecting to {ssid} in container...")
            self._run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /tmp/wpa_bootstrap.conf'")

            # Wait for connection
            connected = False
            for i in range(15):
                status = self._run_command(f"{self.exec_cmd} 'wpa_cli -p /tmp/wpa_supplicant -i wlan0 status'", check=False)
                if status and "wpa_state=COMPLETED" in status:
                    connected = True
                    print(f"[WifiManager] Connected to {ssid}!")
                    break
                time.sleep(1)

            if not connected:
                print(f"[WifiManager] Warning: Could not confirm connection to {ssid}")
            else:
                print(f"[WifiManager] Waiting for regulatory unlock...")
                time.sleep(3)

                iw_out = self._run_command(f"{self.exec_cmd} 'iw list | grep -E \"5180.*MHz.*\\[36\\]\"'", check=False)
                if iw_out and "no IR" not in iw_out.lower():
                    print(f"[WifiManager] Channel 36 unlocked in container!")

            # 4. FREEZE STATE: Yank PHY back to Host
            print(f"[WifiManager] Yanking PHY back to host to freeze regulatory state...")

            # Find the exact PHY index inside the container right now
            ctr_phy_idx = None
            iw_ctr = self._run_command(f"{self.exec_cmd} 'iw dev wlan0 info'", check=False)
            if iw_ctr:
                m = re.search(r"wiphy\s+(\d+)", iw_ctr)
                if m:
                    ctr_phy_idx = m.group(1)

            if not ctr_phy_idx:
                raise Exception("Could not determine PHY index inside container for extraction!")

            # Yank it out using nsenter! (Executes on Host, but points into container's network namespace)
            # CRITICAL: We use phy#{idx} instead of phy{idx} because nsenter -n doesn't share mount namespaces,
            # which breaks iw's sysfs name lookups. phy#{idx} uses direct netlink IDs and bypasses sysfs!
            self._run_command(f"nsenter -t {ctr_pid} -n iw phy#{ctr_phy_idx} set netns 1")
            time.sleep(1)

            # 5. FIND NEW PHY ON HOST
            new_host_phy = None
            iw_host_out = self._run_command("iw phy", check=False)
            if iw_host_out:
                matches = re.findall(r"Wiphy\s+phy(\d+)", iw_host_out)
                if matches:
                    new_host_phy = f"phy{max(int(m) for m in matches)}"

            if not new_host_phy:
                raise Exception("Could not find PHY on host after yanking!")

            print(f"[WifiManager] Found PHY on host as {new_host_phy}. Pushing back to container...")

            # 6. PUSH BACK TO CONTAINER
            self._run_command(f"iw phy {new_host_phy} set netns {ctr_pid}")
            time.sleep(1)

            # 7. RENAME TO wlan0 AND BRING UP inside container
            iw_main = self._run_command(f"{self.exec_cmd} 'iw dev'", check=False)
            if iw_main:
                m = re.search(r"Interface\s+(\S+)", iw_main)
                if m:
                    current_name = m.group(1)
                    if current_name != "wlan0":
                        self._run_command(f"{self.exec_cmd} 'ip link set {current_name} name wlan0'")

            self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'", check=False)
            print(f"[WifiManager] Bootstrap complete. Channels should remain unlocked.")

        except Exception as e:
            print(f"[WifiManager] Bootstrap failed: {e}")
            raise

    def _connect_upstream_wifi(self, iface_name, ssid, password, country):
        print(f"[WifiManager] Connecting {iface_name} to upstream WiFi: {ssid}...")
        self._run_command(f"{self.exec_cmd} 'iw reg set {country}'", check=False)

        wpa_conf = f"""ctrl_interface=/tmp/wpa_supplicant
update_config=1
country={country}
network={{
    ssid="{ssid}"
    psk="{password}"
}}
"""
        conf_path = f"/tmp/wpa_supplicant_{iface_name}.conf"
        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > {conf_path}'", shell=True, input=wpa_conf)

        self._run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i {iface_name} -c {conf_path}'")

        for _ in range(15):
            status = self._run_command(f"{self.exec_cmd} 'wpa_cli -p /tmp/wpa_supplicant -i {iface_name} status'", check=False)
            if status and "wpa_state=COMPLETED" in status: break
            time.sleep(1)

        try:
            self._run_command(f"{self.exec_cmd} 'udhcpc -i {iface_name} -n -q -f -t 10'")
        except:
            print("[WifiManager] Warning: Upstream DHCP failed.")

    def _open_host_ports(self):
        if shutil.which("firewall-cmd"):
            print("[WifiManager] Opening Ports (Firewalld)...")
            try:
                self._run_command(f"firewall-cmd --zone=trusted --add-interface={VETH_HOST}", check=False)
                self._run_command(f"firewall-cmd --zone=trusted --add-port={FWD_PORT_RANGE}/udp", check=False)
                self._run_command(f"firewall-cmd --zone=trusted --add-port={FWD_PORT_RANGE}/tcp", check=False)
            except: pass
        elif shutil.which("ufw"):
            print("[WifiManager] Opening Ports (UFW)...")
            try:
                self._run_command(f"ufw allow in on {VETH_HOST}", check=False)
                self._run_command(f"ufw allow out on {VETH_HOST}", check=False)
                self._run_command(f"ufw allow from 192.168.50.0/24", check=False)
            except: pass

    # --- Mode Specific Logic ---

    def _setup_ap_logic(self, ssid, password, channel, ctr_pid, wifi_mode, country, has_wan, wan_iface):
        if country and country.lower() not in["inherit", "bootstrap", "bootstrap-host", "bootstrap-container", "none", ""]:
            print(f"[WifiManager] Setting regulatory domain to {country}...")
            self._run_command(f"{self.exec_cmd} 'iw reg set {country}'")
            time.sleep(1)

            reg_info = self._run_command(f"{self.exec_cmd} 'iw reg get'", check=False)
            if reg_info and f"country {country}" in reg_info:
                print(f"[WifiManager] Regulatory domain set: {reg_info.split('country')[1].split(':')[0].strip()}")
            else:
                print(f"[WifiManager] Warning: Could not verify regulatory domain")
        else:
            print(f"[WifiManager] Using inherited regulatory domain from host")
            reg_info = self._run_command(f"{self.exec_cmd} 'iw reg get'", check=False)
            if reg_info:
                country_line =[line for line in reg_info.split('\n') if 'country' in line]
                if country_line:
                    print(f"[WifiManager] Current: {country_line[0].strip()}")

        self._run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self._run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self._run_command(f"{self.exec_cmd} 'ip link add name br0 type bridge'")
        self._run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self._run_command(f"{self.exec_cmd} 'ip link set br0 up'")
        self._run_command(f"{self.exec_cmd} 'brctl addif br0 {VETH_CTR}'")
        self._run_command(f"{self.exec_cmd} 'ip addr add {ROUTER_LAN_IP}/24 dev br0'")

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

        if has_wan:
            self._run_command(f"{self.exec_cmd} 'sysctl -w net.ipv4.ip_forward=1'")
            self._run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE'")
            self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i br0 -o {wan_iface} -j ACCEPT'")
            self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {wan_iface} -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT'")

        self._run_command(f"{self.exec_cmd} 'iptables -P FORWARD ACCEPT'", check=False)

        is_5ghz = int(channel) > 14
        hw_mode = "a" if is_5ghz else "g"
        enable_ac = 1 if is_5ghz and wifi_mode in["ac", "ax"] else 0
        enable_ax = 1 if is_5ghz and wifi_mode == "ax" else 0

        if country.lower() in["inherit", "bootstrap", "bootstrap-host", "bootstrap-container", "none", ""]:
            country_line = "# country_code not set (inheriting from host)"
        else:
            country_line = f"country_code={country}"

        hostapd_conf = f"""interface=wlan0
bridge=br0
ssid={ssid}
{country_line}
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

        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /tmp/hostapd.conf'", shell=True, input=hostapd_conf)
        self._run_command(f"{self.exec_cmd} 'rfkill unblock all'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self._run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")

        try:
            self._run_command(f"{self.exec_cmd} 'hostapd -B /tmp/hostapd.conf'")
        except Exception as e:
            error_str = str(e)
            if any(x in error_str for x in["not allowed for AP mode", "not found from the channel list",
                                            "Hardware does not support configured channel",
                                            "Could not select hw_mode and channel", "AP-DISABLED"]):
                print(f"\n[CRITICAL] Channel {channel} is not supported by your WiFi card for AP mode.")
                print(f"[CRITICAL] Debug - checking available channels in container:")
                channels = self._run_command(f"{self.exec_cmd} 'iw list | grep MHz'", check=False)
                if channels:
                    for line in channels.split('\n')[:20]:
                        if line.strip():
                            print(f"  {line.strip()}")
                print(f"\n[CRITICAL] The regulatory domain inside the container may differ from the host.")
                print(f"[CRITICAL] Try channel 1, 6, or 11 (2.4GHz) which usually have best compatibility.")
                raise Exception(f"Channel {channel} not supported for AP mode. Try a different channel.")
            raise
        self._run_command(f"{self.exec_cmd} 'tc qdisc add dev wlan0 root fq_codel 2>/dev/null || true'")

        dnsmasq_conf = f"""interface=br0
dhcp-range={DHCP_RANGE}
dhcp-option=3,{ROUTER_LAN_IP}
dhcp-option=6,8.8.8.8"""
        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /tmp/dnsmasq.conf'", shell=True, input=dnsmasq_conf)
        self._run_command(f"{self.exec_cmd} 'dnsmasq -C /tmp/dnsmasq.conf'")

    def _setup_client_logic(self, ssid, password, ctr_pid, country="US"):
        self._run_command(f"ip link add {VETH_HOST} type veth peer name {VETH_CTR}")
        self._run_command(f"ip link set {VETH_CTR} netns {ctr_pid}")
        self._run_command(f"{self.exec_cmd} 'ip link set {VETH_CTR} up'")
        self._run_command(f"{self.exec_cmd} 'ip addr add {CLIENT_GATEWAY_IP}/24 dev {VETH_CTR}'")

        self._run_command(f"nmcli connection add type ethernet ifname {VETH_HOST} con-name {NM_CONN_NAME} ip4 {CLIENT_HOST_IP}/24 gw4 {CLIENT_GATEWAY_IP} connection.zone trusted")
        self._run_command(f"nmcli connection modify {NM_CONN_NAME} ipv4.dns '8.8.8.8'")
        self._run_command(f"nmcli connection up {NM_CONN_NAME}")

        if country and country.lower() not in["inherit", "bootstrap", "bootstrap-host", "bootstrap-container", "none", ""]:
            self._run_command(f"{self.exec_cmd} 'iw reg set {country}'", check=False)

        wpa_country = country if country and country.lower() not in["inherit", "bootstrap", "bootstrap-host", "bootstrap-container", "none", ""] else ""
        wpa_conf = f"""ctrl_interface=/tmp/wpa_supplicant
update_config=1
country={wpa_country}
network={{
    ssid="{ssid}"
    psk="{password}"
}}
"""
        self._run_command(f"podman exec -i {CONTAINER_NAME} sh -c 'cat > /tmp/wpa_supplicant.conf'", shell=True, input=wpa_conf)
        self._run_command(f"{self.exec_cmd} 'rfkill unblock all'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set wlan0 up'")
        self._run_command(f"{self.exec_cmd} 'iw dev wlan0 set power_save off'")
        self._run_command(f"{self.exec_cmd} 'wpa_supplicant -B -i wlan0 -c /tmp/wpa_supplicant.conf'")

        for _ in range(15):
            status = self._run_command(f"{self.exec_cmd} 'wpa_cli -p /tmp/wpa_supplicant status'", check=False)
            if status and "wpa_state=COMPLETED" in status: break
            time.sleep(1)

        self._run_command(f"{self.exec_cmd} 'ip route flush default'", check=False)
        try:
            self._run_command(f"{self.exec_cmd} 'udhcpc -i wlan0 -n -q -f -t 5'")
        except: pass

        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE'")
        self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i {VETH_CTR} -o wlan0 -j ACCEPT'")
        self._run_command(f"{self.exec_cmd} 'iptables -A FORWARD -i wlan0 -o {VETH_CTR} -m state --state RELATED,ESTABLISHED -j ACCEPT'")
        self._run_command(f"{self.exec_cmd} 'iptables -P FORWARD ACCEPT'", check=False)

        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport {FWD_PORT_RANGE} -j DNAT --to-destination {CLIENT_HOST_IP}'")
        self._run_command(f"{self.exec_cmd} 'iptables -t nat -A PREROUTING -i wlan0 -p udp --dport {FWD_PORT_RANGE} -j DNAT --to-destination {CLIENT_HOST_IP}'")

        self._run_command(f"{self.exec_cmd} 'dbus-uuidgen > /tmp/machine-id'", check=False)
        self._run_command(f"{self.exec_cmd} 'mkdir -p /var/lib/dbus'", check=False)
        self._run_command(f"{self.exec_cmd} 'ln -sf /tmp/machine-id /var/lib/dbus/machine-id'", check=False)
        self._run_command(f"{self.exec_cmd} 'mkdir -p /var/run/dbus'", check=False)

        self._run_command(f"{self.exec_cmd} 'dbus-daemon --system --fork'")
        self._run_command(f"{self.exec_cmd} 'avahi-daemon -D'")

    def _move_ethernet_card(self, host_iface, ctr_pid):
        self._run_command(f"nmcli device disconnect {host_iface}", check=False)
        time.sleep(1)
        try:
            self._run_command(f"ip link set {host_iface} netns {ctr_pid}")
        except: return False

        self._run_command(f"{self.exec_cmd} 'ip route flush default'", check=False)
        self._run_command(f"{self.exec_cmd} 'ip link set {host_iface} up'")
        time.sleep(2)
        try:
            subprocess.run(shlex.split(f"{self.exec_cmd} 'udhcpc -i {host_iface} -n -q -f -t 5'"),
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except: pass
        return True
