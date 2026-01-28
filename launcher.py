#!/usr/bin/env python3
import sys
import os
import subprocess
import threading
import json
import signal
import socket
import time
import importlib.util
from core.video_sender_manager import VideoSenderManager

# --- DEPENDENCY CHECK & AUTO-INSTALL ---
def check_and_install_deps():
    required = ["glfw", "OpenGL"]
    missing = []
    for pkg in required:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)
            if pkg == "OpenGL": pkg = "PyOpenGL"

    if missing:
        print(f"[Launcher] Missing dependencies: {missing}. Installing...")
        pip_packages = []
        for m in missing:
            if m == "OpenGL": pip_packages.append("PyOpenGL")
            else: pip_packages.append(m)
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user"] + pip_packages)
            print("[Launcher] Dependencies installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[Launcher] Failed to install dependencies: {e}")

check_and_install_deps()

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Pango', '1.0')
from gi.repository import Gtk, GLib, Pango, Gdk

CONFIG_FILE = os.path.expanduser("~/.deck_upad_config.json")
REC_IMAGE = "localhost/stream-receiver-final"
REC_BASE = "registry.fedoraproject.org/fedora:39"

class DeckUpadLauncher(Gtk.Window):
    def __init__(self):
        super().__init__(title="Deck-Upad Control Panel")
        self.set_default_size(900, 850) # Increased height
        self.set_border_width(10)

        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)

        self.process = None
        self.test_receiver_proc = None
        self.test_sender_proc = None
        self.test_input_proc = None
        self.test_container_name = "deck-upad-test-rec"
        self.cached_sudo_pw = ""
        self.sender_mgr = VideoSenderManager()
        self.config = self.load_config()
        self.interfaces = self.get_network_interfaces()

        # --- UI LAYOUT ---
        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        # Header
        header = Gtk.Label()
        header.set_markup("<span size='xx-large' weight='bold' foreground='#3A9FED'>Deck-Upad</span>")
        main_vbox.pack_start(header, False, False, 5)

        # Controls Grid
        grid = Gtk.Grid()
        grid.set_column_spacing(20)
        grid.set_row_spacing(10)
        grid.set_halign(Gtk.Align.CENTER)
        main_vbox.pack_start(grid, False, False, 10)

        # Row 0: Role
        grid.attach(Gtk.Label(label="Device Role:"), 0, 0, 1, 1)
        role_box = Gtk.Box(spacing=10)
        self.rb_client = Gtk.RadioButton.new_with_label_from_widget(None, "Client (Steam Deck)")
        self.rb_host = Gtk.RadioButton.new_with_label_from_widget(self.rb_client, "Host (PC)")
        role_box.pack_start(self.rb_client, False, False, 0)
        role_box.pack_start(self.rb_host, False, False, 0)
        grid.attach(role_box, 1, 0, 2, 1)

        # Row 1: P2P Interface Selection
        grid.attach(Gtk.Label(label="P2P WiFi Interface:"), 0, 1, 1, 1)
        self.combo_p2p = Gtk.ComboBoxText()
        for iface in self.interfaces['wifi']:
            self.combo_p2p.append(iface, iface)

        # Default to first wifi found or config
        def_p2p = self.config.get("p2p_iface")
        if def_p2p and def_p2p in self.interfaces['wifi']:
            self.combo_p2p.set_active_id(def_p2p)
        elif self.interfaces['wifi']:
            self.combo_p2p.set_active(0)

        grid.attach(self.combo_p2p, 1, 1, 2, 1)

        # Row 2: Internet Interface Selection
        grid.attach(Gtk.Label(label="Internet Interface:\n(Must not be same as P2P)\n(Phone's USB Tethering works)\n(No need on client)"), 0, 2, 1, 1)
        self.combo_net = Gtk.ComboBoxText()
        self.combo_net.append("none", "No Internet")

        # Add all interfaces (Ethernet + WiFi)
        for iface in self.interfaces['all']:
            desc = f"{iface} (WiFi)" if iface in self.interfaces['wifi'] else f"{iface} (Ethernet)"
            self.combo_net.append(iface, desc)

        def_net = self.config.get("internet_iface", "none")
        self.combo_net.set_active_id(def_net)
        self.combo_net.connect("changed", self.on_internet_iface_changed)
        grid.attach(self.combo_net, 1, 2, 2, 1)

        # Row 3: Host/P2P SSID
        grid.attach(Gtk.Label(label="P2P SSID (Host):"), 0, 3, 1, 1)
        self.entry_ssid = Gtk.Entry()
        self.entry_ssid.set_text(self.config.get("ssid", "DeckUpad"))
        grid.attach(self.entry_ssid, 1, 3, 2, 1)

        # Row 4: Host/P2P Password
        grid.attach(Gtk.Label(label="P2P Password:"), 0, 4, 1, 1)
        self.entry_pass = Gtk.Entry()
        self.entry_pass.set_text(self.config.get("password", "DeckUpad123"))
        grid.attach(self.entry_pass, 1, 4, 2, 1)

        # --- Internet WiFi Credentials (Revealer) ---
        self.net_wifi_revealer = Gtk.Revealer()
        self.net_wifi_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)

        net_grid = Gtk.Grid()
        net_grid.set_column_spacing(20)
        net_grid.set_row_spacing(10)

        net_grid.attach(Gtk.Label(label="Internet SSID:"), 0, 0, 1, 1)
        self.entry_net_ssid = Gtk.Entry()
        self.entry_net_ssid.set_text(self.config.get("internet_ssid", ""))
        net_grid.attach(self.entry_net_ssid, 1, 0, 2, 1)

        net_grid.attach(Gtk.Label(label="Internet Password:"), 0, 1, 1, 1)
        self.entry_net_pass = Gtk.Entry()
        self.entry_net_pass.set_visibility(False)
        self.entry_net_pass.set_text(self.config.get("internet_pass", ""))
        net_grid.attach(self.entry_net_pass, 1, 1, 2, 1)

        self.net_wifi_revealer.add(net_grid)
        # We attach the revealer to the main grid, spanning columns
        grid.attach(self.net_wifi_revealer, 0, 5, 3, 1)

        # Trigger initial visibility check
        self.on_internet_iface_changed(self.combo_net)

        # Row 6: WiFi Mode
        grid.attach(Gtk.Label(label="P2P Standard:"), 0, 6, 1, 1)
        self.combo_mode = Gtk.ComboBoxText()
        self.combo_mode.append("ax", "AX (WiFi 6)")
        self.combo_mode.append("ac", "AC (WiFi 5)")
        self.combo_mode.append("n", "N (Legacy)")
        self.combo_mode.set_active_id(self.config.get("wifi_mode", "ax"))
        grid.attach(self.combo_mode, 1, 6, 2, 1)

        # Row 7: WiFi Channel
        grid.attach(Gtk.Label(label="P2P Channel:"), 0, 7, 1, 1)
        adj = Gtk.Adjustment(value=165, lower=1, upper=177, step_increment=1, page_increment=10, page_size=0)
        self.spin_channel = Gtk.SpinButton(adjustment=adj)
        self.spin_channel.set_numeric(True)
        self.spin_channel.set_value(int(self.config.get("channel", 165)))
        grid.attach(self.spin_channel, 1, 7, 2, 1)

        # Row 8: WiFi Country
        grid.attach(Gtk.Label(label="WiFi Region:"), 0, 8, 1, 1)
        self.combo_country = Gtk.ComboBoxText()
        self.combo_country.set_entry_text_column(0)
        countries = [("US", "United States"), ("GB", "United Kingdom"), ("DE", "Germany"), ("JP", "Japan"), ("CA", "Canada"), ("AU", "Australia"), ("FR", "France"), ("KR", "South Korea"), ("CN", "China"), ("BR", "Brazil")]
        for code, name in countries:
            self.combo_country.append(code, f"{code} - {name}")
        self.combo_country.set_active_id(self.config.get("country", "US"))
        grid.attach(self.combo_country, 1, 8, 2, 1)

        # Row 9: Inverse Topology
        grid.attach(Gtk.Label(label="Inverse Topology:"), 0, 9, 1, 1)
        self.chk_inverse = Gtk.CheckButton(label="Deck hosts WiFi (AP), PC connects to Deck")
        self.chk_inverse.set_tooltip_text("If checked: Client Agent creates Hotspot, Host Daemon connects to it.")
        self.chk_inverse.set_active(self.config.get("inverse_topology", False))
        grid.attach(self.chk_inverse, 1, 9, 2, 1)

        # Row 10: Sudo Password
        grid.attach(Gtk.Label(label="Sudo Password:"), 0, 10, 1, 1)
        self.entry_sudo = Gtk.Entry()
        self.entry_sudo.set_visibility(False)
        self.entry_sudo.set_invisible_char("•")
        self.entry_sudo.set_text(self.config.get("sudo_pass", ""))
        grid.attach(self.entry_sudo, 1, 10, 1, 1)

        self.chk_save_sudo = Gtk.CheckButton(label="Save")
        self.chk_save_sudo.set_active(bool(self.config.get("sudo_pass", "")))
        grid.attach(self.chk_save_sudo, 2, 10, 1, 1)

        if self.config.get("role") == "host": self.rb_host.set_active(True)

        # 3. Buttons
        btn_box = Gtk.Box(spacing=20)
        btn_box.set_halign(Gtk.Align.CENTER)
        main_vbox.pack_start(btn_box, False, False, 10)

        self.btn_start = Gtk.Button(label="Start Service")
        self.btn_start.get_style_context().add_class("suggested-action")
        self.btn_start.set_size_request(150, 50)
        self.btn_start.connect("clicked", self.on_start)
        btn_box.pack_start(self.btn_start, False, False, 0)

        test_box = Gtk.Box(spacing=10)
        self.btn_test_sim = Gtk.Button(label="Test Video\n(Simulation)")
        self.btn_test_sim.set_size_request(120, 50)
        self.btn_test_sim.connect("clicked", lambda w: self.on_test_video(simulated=True))
        test_box.pack_start(self.btn_test_sim, False, False, 0)

        self.btn_test_emu = Gtk.Button(label="Test Video\n(Emulator)")
        self.btn_test_emu.set_size_request(120, 50)
        self.btn_test_emu.connect("clicked", lambda w: self.on_test_video(simulated=False))
        test_box.pack_start(self.btn_test_emu, False, False, 0)
        btn_box.pack_start(test_box, False, False, 0)

        self.btn_clean = Gtk.Button(label="Force Cleanup")
        self.btn_clean.set_size_request(150, 50)
        self.btn_clean.connect("clicked", self.on_cleanup)
        btn_box.pack_start(self.btn_clean, False, False, 0)

        self.btn_stop = Gtk.Button(label="Stop Service")
        self.btn_stop.get_style_context().add_class("destructive-action")
        self.btn_stop.set_size_request(150, 50)
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect("clicked", self.on_stop)
        btn_box.pack_start(self.btn_stop, False, False, 0)

        # 4. Logs
        log_frame = Gtk.Frame(label="System Logs")
        main_vbox.pack_start(log_frame, True, True, 0)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)
        log_frame.add(scrolled)
        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_monospace(True)
        self.log_view.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.1, 0.1, 0.1, 1))
        self.log_view.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0.9, 0, 1))
        scrolled.add(self.log_view)
        self.log_buffer = self.log_view.get_buffer()
        self.log_mark = self.log_buffer.create_mark("end", self.log_buffer.get_end_iter(), False)

        self.connect("destroy", self.on_close)
        self.show_all()

    def get_network_interfaces(self):
        """Detects network interfaces and categorizes them."""
        wifi = []
        all_ifaces = []
        try:
            # Get list of interfaces
            ifaces = os.listdir('/sys/class/net')
            for iface in ifaces:
                if iface == 'lo' or iface.startswith('veth') or iface.startswith('docker') or iface.startswith('podman'):
                    continue

                all_ifaces.append(iface)
                # Check if wireless
                if os.path.isdir(f"/sys/class/net/{iface}/wireless"):
                    wifi.append(iface)
                else:
                    # Fallback check using iw
                    try:
                        subprocess.check_call(['iw', 'dev', iface, 'info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if iface not in wifi: wifi.append(iface)
                    except: pass
        except Exception as e:
            print(f"Error detecting interfaces: {e}")

        return {'all': sorted(all_ifaces), 'wifi': sorted(wifi)}

    def on_internet_iface_changed(self, combo):
        active_id = combo.get_active_id()
        if active_id and active_id != "none" and active_id in self.interfaces['wifi']:
            self.net_wifi_revealer.set_reveal_child(True)
        else:
            self.net_wifi_revealer.set_reveal_child(False)

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f: return json.load(f)
        except: pass
        return {}

    def save_config(self):
        role = "host" if self.rb_host.get_active() else "client"
        sudo_pass = self.entry_sudo.get_text() if self.chk_save_sudo.get_active() else ""
        country = self.combo_country.get_active_id() or "US"

        data = {
            "role": role,
            "p2p_iface": self.combo_p2p.get_active_id(),
            "internet_iface": self.combo_net.get_active_id(),
            "ssid": self.entry_ssid.get_text(),
            "password": self.entry_pass.get_text(),
            "internet_ssid": self.entry_net_ssid.get_text(),
            "internet_pass": self.entry_net_pass.get_text(),
            "wifi_mode": self.combo_mode.get_active_id(),
            "channel": int(self.spin_channel.get_value()),
            "country": country,
            "sudo_pass": sudo_pass,
            "inverse_topology": self.chk_inverse.get_active()
        }
        try:
            with open(CONFIG_FILE, 'w') as f: json.dump(data, f)
        except: pass

    def append_log(self, text):
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text)
        self.log_view.scroll_to_mark(self.log_mark, 0.0, True, 0.0, 1.0)

    def _ensure_flatpak_runtime(self):
        """Checks and installs Flatpak GNOME SDK for the Test Mode."""
        runtime_ref = "org.gnome.Sdk/x86_64/45"
        try:
            res = subprocess.run(["flatpak", "list", "--runtime", "--columns=application,branch,arch"], stdout=subprocess.PIPE, text=True)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    if "org.gnome.Sdk" in parts[0] and "45" in parts[1] and "x86_64" in parts[2]:
                        return True
        except: pass

        GLib.idle_add(self.append_log, f"Installing GNOME SDK... (This may take a minute)\n")
        try:
            subprocess.run(["flatpak", "remote-add", "--if-not-exists", "--user", "flathub", "https://flathub.org/repo/flathub.flatpakrepo"], check=True)
            subprocess.run(["flatpak", "install", "--user", "--or-update", "-y", "flathub", runtime_ref], check=True)
            GLib.idle_add(self.append_log, f"SDK installed successfully.\n")
            return True
        except Exception as e:
            GLib.idle_add(self.append_log, f"Failed to install SDK: {e}\n")
            return False

    def _robust_podman_rm(self, container_name):
        res = subprocess.run(["podman", "rm", "-f", container_name], stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
        if res.returncode != 0:
            err = res.stderr.decode()
            if "migrate" in err or "invalid internal status" in err:
                GLib.idle_add(self.append_log, "   [Fixing] Podman state repair triggered...\n")
                subprocess.run(["podman", "system", "migrate"], stderr=subprocess.DEVNULL)
                subprocess.run(["podman", "rm", "-f", container_name], stderr=subprocess.DEVNULL)

    def ensure_receiver_image_exists(self):
        res = subprocess.run(["podman", "images", "-q", REC_IMAGE], stdout=subprocess.PIPE, text=True)
        if res.stdout.strip(): return True
        GLib.idle_add(self.append_log, f"Building Receiver Image '{REC_IMAGE}'... (This takes a minute)\n")
        builder = "stream-receiver-builder"
        try:
            self._robust_podman_rm(builder)
            subprocess.run(["podman", "run", "-d", "--name", builder, REC_BASE, "sleep", "infinity"], check=True)
            GLib.idle_add(self.append_log, "   Installing GStreamer dependencies...\n")
            subprocess.run(["podman", "exec", builder, "dnf", "install", "-y", "--nogpgcheck",
                "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"], check=True)
            pkgs = ["python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
                    "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
                    "gstreamer1-libav", "gstreamer1-plugins-bad-free",
                    "mesa-dri-drivers", "libwayland-client", "python3"]
            subprocess.run(["podman", "exec", builder, "dnf", "install", "-y"] + pkgs, check=True)
            GLib.idle_add(self.append_log, "   Committing image...\n")
            subprocess.run(["podman", "commit", builder, REC_IMAGE], check=True)
            return True
        except Exception as e:
            GLib.idle_add(self.append_log, f"Build Failed: {e}\n")
            return False
        finally:
            self._robust_podman_rm(builder)

    def on_test_video(self, simulated=True):
        self.save_config()
        self.cached_sudo_pw = self.entry_sudo.get_text()
        mode_str = "SIMULATION" if simulated else "EMULATOR INTEGRATION"
        self.append_log(f"\n--- STARTING VIDEO TEST ({mode_str}) ---\n")
        self.btn_test_sim.set_sensitive(False)
        self.btn_test_emu.set_sensitive(False)
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        threading.Thread(target=self._run_test_sequence, args=(simulated,), daemon=True).start()

    def _run_test_sequence(self, simulated):
        if not self._ensure_flatpak_runtime(): return
        try: subprocess.run(["xhost", "+"], stderr=subprocess.DEVNULL)
        except: pass
        GLib.idle_add(self.append_log, "Starting Input Server (Sudo)...\n")
        try:
            self.test_input_proc = subprocess.Popen(["sudo", "-S", "python3", "core/input_server.py"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            if self.cached_sudo_pw:
                try: self.test_input_proc.stdin.write(self.cached_sudo_pw + "\n"); self.test_input_proc.stdin.flush()
                except OSError: pass
            threading.Thread(target=self._monitor_pipe, args=(self.test_input_proc, "[IN]"), daemon=True).start()
        except Exception as e: GLib.idle_add(self.append_log, f"Input Server Failed: {e}\n")

        script_path = os.path.abspath("core/video_receiver.py")
        runtime_ref = "org.gnome.Sdk/x86_64/45"
        cmd = ["flatpak", "run", "--command=python3", "--filesystem=host", "--share=network", "--device=all",
            "--socket=x11", "--socket=wayland", runtime_ref, script_path, "--windowed", "--host-ip", "127.0.0.1"]
        GLib.idle_add(self.append_log, f"Launching Receiver (Flatpak wrapper)...\n")
        try:
            self.test_receiver_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            threading.Thread(target=self._monitor_pipe, args=(self.test_receiver_proc, "[RX]"), daemon=True).start()
        except Exception as e: GLib.idle_add(self.append_log, f"Flatpak launch failed: {e}\n"); return
        time.sleep(3)
        self._start_test_sender(simulated)

    def _start_test_sender(self, simulated):
        GLib.idle_add(self.append_log, "Preparing Sender Container...\n")
        try: self.sender_mgr.ensure_image_exists()
        except Exception as e: GLib.idle_add(self.append_log, f"Sender Build Failed: {e}\n"); return
        if simulated: GLib.idle_add(self.append_log, "Mode: Test Pattern\n")
        else: GLib.idle_add(self.append_log, "Mode: Emulator Capture\n>>> LAUNCH AZAHAR NOW <<<\n")
        try:
            self.test_sender_proc = self.sender_mgr.start("127.0.0.1", test_mode=simulated)
            threading.Thread(target=self._monitor_sender_output, args=(self.test_sender_proc,), daemon=True).start()
            if simulated: time.sleep(1); self._send_udp_signal()
        except Exception as e: GLib.idle_add(self.append_log, f"Sender failed: {e}\n")

    def _send_udp_signal(self):
        GLib.idle_add(self.append_log, "Sending START_VIDEO signal...\n")
        try: s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"START_VIDEO", ("127.0.0.1", 5003))
        except: pass

    def _monitor_pipe(self, proc, prefix):
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None: break
            if line: GLib.idle_add(self.append_log, f"{prefix} {line}")

    def _monitor_sender_output(self, proc):
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None: break
            msg = line.strip()
            if msg:
                GLib.idle_add(self.append_log, f"[TX] {msg}\n")
                if msg == "VIDEO_STARTING": self._send_udp_signal()

    def on_start(self, widget):
        try: subprocess.run(["xhost", "+"], stderr=subprocess.DEVNULL)
        except: pass

        self.save_config()
        self.cached_sudo_pw = self.entry_sudo.get_text()
        self.btn_start.set_sensitive(False)
        self.btn_test_sim.set_sensitive(False)
        self.btn_test_emu.set_sensitive(False)
        self.btn_clean.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        # Disable inputs
        for w in [self.entry_ssid, self.entry_pass, self.spin_channel, self.combo_mode,
                  self.combo_country, self.combo_p2p, self.combo_net, self.entry_net_ssid, self.entry_net_pass, self.chk_inverse]:
            w.set_sensitive(False)

        role = "host" if self.rb_host.get_active() else "client"
        ssid = self.entry_ssid.get_text()
        pw = self.entry_pass.get_text()
        wifi_mode = self.combo_mode.get_active_id()
        channel = str(int(self.spin_channel.get_value()))
        country = self.combo_country.get_active_id() or "US"
        sudo_pw = self.entry_sudo.get_text()
        is_inverse = self.chk_inverse.get_active()

        # New Arguments
        p2p_iface = self.combo_p2p.get_active_id()
        internet_iface = self.combo_net.get_active_id()
        internet_ssid = self.entry_net_ssid.get_text()
        internet_pass = self.entry_net_pass.get_text()

        script_path = os.path.abspath("deck_upad.py")

        cmd = [
            "sudo", "-S",
            "python3", "-u", script_path,
            "--role", role,
            "--ssid", ssid,
            "--password", pw,
            "--wifi-mode", wifi_mode,
            "--channel", channel,
            "--country", country,
            "--p2p-iface", p2p_iface,
            "--internet-iface", internet_iface
        ]

        if internet_iface and internet_iface != "none":
            cmd.extend(["--internet-ssid", internet_ssid])
            cmd.extend(["--internet-pass", internet_pass])

        if is_inverse:
            cmd.append("--inverse")

        topo = "INVERSE" if is_inverse else "STANDARD"
        self.append_log(f"--- STARTING {role.upper()} MODE ({topo} TOPOLOGY) ---\n")
        self._run_process(cmd, sudo_pw)

    def on_cleanup(self, widget):
        self.save_config()
        self.cached_sudo_pw = self.entry_sudo.get_text()
        self.btn_start.set_sensitive(False)
        self.btn_test_sim.set_sensitive(False)
        self.btn_test_emu.set_sensitive(False)
        self.btn_clean.set_sensitive(False)

        sudo_pw = self.entry_sudo.get_text()
        script_path = os.path.abspath("deck_upad.py")

        cmd = ["sudo", "-S", "python3", "-u", script_path, "--cleanup-only"]
        self.append_log(f"--- STARTING SYSTEM CLEANUP ---\n")
        self._run_process(cmd, sudo_pw)

    def _run_process(self, cmd, sudo_pw):
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            if sudo_pw:
                try:
                    self.process.stdin.write(sudo_pw + "\n")
                    self.process.stdin.flush()
                except OSError: pass

            t = threading.Thread(target=self.monitor_process, daemon=True)
            t.start()
        except Exception as e:
            self.append_log(f"Failed to launch: {e}\n")
            self.process_finished()

    def monitor_process(self):
        while True:
            line = self.process.stdout.readline()
            if not line and self.process.poll() is not None: break
            if line: GLib.idle_add(self.append_log, line)
        GLib.idle_add(self.process_finished)

    def process_finished(self):
        self.append_log("\n--- PROCESS FINISHED ---\n")
        self.btn_start.set_sensitive(True)
        self.btn_test_sim.set_sensitive(True)
        self.btn_test_emu.set_sensitive(True)
        self.btn_clean.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        # Re-enable inputs
        for w in [self.entry_ssid, self.entry_pass, self.spin_channel, self.combo_mode,
                  self.combo_country, self.combo_p2p, self.combo_net, self.entry_net_ssid, self.entry_net_pass, self.chk_inverse]:
            w.set_sensitive(True)
        self.process = None

    def on_stop(self, widget):
        if self.test_input_proc:
            self.append_log("Stopping Input Server...\n")
            try:
                cmd = ["sudo", "-S", "pkill", "-f", "core/input_server.py"]
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
                if self.cached_sudo_pw: proc.communicate(input=(self.cached_sudo_pw + "\n").encode())
            except: pass
            self.test_input_proc = None

        if self.test_receiver_proc:
            self.append_log("Stopping Test Receiver...\n")
            self._robust_podman_rm(self.test_container_name)
            self.test_receiver_proc = None

        if self.test_sender_proc:
            self.append_log("Stopping Test Sender...\n")
            self.sender_mgr.stop()
            self.test_sender_proc = None

        if self.process:
            self.append_log("\nStopping Service...\n")
            try: self.process.terminate()
            except: pass
            def force_kill_if_needed():
                import time; time.sleep(1)
                if self.process and self.process.poll() is None:
                    cmd = ["sudo", "-S", "pkill", "-f", "deck_upad.py"]
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    if self.cached_sudo_pw: proc.communicate(input=(self.cached_sudo_pw + "\n").encode())
            threading.Thread(target=force_kill_if_needed, daemon=True).start()

    def on_close(self, widget):
        self.on_stop(None)
        Gtk.main_quit()

if __name__ == "__main__":
    win = DeckUpadLauncher()
    Gtk.main()
