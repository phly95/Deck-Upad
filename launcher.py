#!/usr/bin/env python3
import sys
import os
import gi
import subprocess
import threading
import json
import signal

gi.require_version('Gtk', '3.0')
gi.require_version('Pango', '1.0')
from gi.repository import Gtk, GLib, Pango, Gdk

# Configuration File to save user preferences
CONFIG_FILE = os.path.expanduser("~/.deck_upad_config.json")

class DeckUpadLauncher(Gtk.Window):
    def __init__(self):
        super().__init__(title="Deck-Upad Control Panel")
        self.set_default_size(900, 700)
        self.set_border_width(10)

        # Dark Theme Hint
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)

        self.process = None
        self.config = self.load_config()

        # --- UI LAYOUT ---
        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(main_vbox)

        # 1. Header
        header = Gtk.Label()
        header.set_markup("<span size='xx-large' weight='bold' foreground='#3A9FED'>Deck-Upad</span>")
        main_vbox.pack_start(header, False, False, 5)

        # 2. Controls Grid
        grid = Gtk.Grid()
        grid.set_column_spacing(20)
        grid.set_row_spacing(10)
        grid.set_halign(Gtk.Align.CENTER)
        main_vbox.pack_start(grid, False, False, 10)

        # Row 0: Role Selection
        grid.attach(Gtk.Label(label="Device Role:"), 0, 0, 1, 1)
        role_box = Gtk.Box(spacing=10)
        self.rb_client = Gtk.RadioButton.new_with_label_from_widget(None, "Client (Steam Deck)")
        self.rb_host = Gtk.RadioButton.new_with_label_from_widget(self.rb_client, "Host (PC)")
        role_box.pack_start(self.rb_client, False, False, 0)
        role_box.pack_start(self.rb_host, False, False, 0)
        grid.attach(role_box, 1, 0, 2, 1)

        # Row 1: SSID
        grid.attach(Gtk.Label(label="WiFi SSID:"), 0, 1, 1, 1)
        self.entry_ssid = Gtk.Entry()
        self.entry_ssid.set_text(self.config.get("ssid", "DeckUpad"))
        grid.attach(self.entry_ssid, 1, 1, 2, 1)

        # Row 2: WiFi Password
        grid.attach(Gtk.Label(label="WiFi Password:"), 0, 2, 1, 1)
        self.entry_pass = Gtk.Entry()
        self.entry_pass.set_text(self.config.get("password", "DeckUpad123"))
        grid.attach(self.entry_pass, 1, 2, 2, 1)

        # Row 3: WiFi Mode
        grid.attach(Gtk.Label(label="WiFi Standard:"), 0, 3, 1, 1)
        self.combo_mode = Gtk.ComboBoxText()
        self.combo_mode.append("ax", "AX (WiFi 6 - Recommended)")
        self.combo_mode.append("ac", "AC (WiFi 5)")
        self.combo_mode.append("n", "N (Legacy)")
        self.combo_mode.set_active_id(self.config.get("wifi_mode", "ax"))
        grid.attach(self.combo_mode, 1, 3, 2, 1)

        # Row 4: WiFi Channel
        grid.attach(Gtk.Label(label="WiFi Channel:"), 0, 4, 1, 1)
        adj = Gtk.Adjustment(value=165, lower=1, upper=177, step_increment=1, page_increment=10, page_size=0)
        self.spin_channel = Gtk.SpinButton(adjustment=adj)
        self.spin_channel.set_numeric(True)
        self.spin_channel.set_value(int(self.config.get("channel", 165)))
        grid.attach(self.spin_channel, 1, 4, 2, 1)

        # Row 5: WiFi Country
        grid.attach(Gtk.Label(label="WiFi Country:"), 0, 5, 1, 1)
        self.combo_country = Gtk.ComboBoxText()
        self.combo_country.set_entry_text_column(0)
        countries = [("US", "United States"), ("GB", "United Kingdom"), ("DE", "Germany"), ("JP", "Japan"), ("CA", "Canada"), ("AU", "Australia"), ("FR", "France"), ("KR", "South Korea"), ("CN", "China"), ("BR", "Brazil")]
        for code, name in countries:
            self.combo_country.append(code, f"{code} - {name}")

        default_country = self.config.get("country", "US")
        self.combo_country.set_active_id(default_country)
        grid.attach(self.combo_country, 1, 5, 2, 1)

        # Row 6: Sudo Password
        grid.attach(Gtk.Label(label="Sudo Password:"), 0, 6, 1, 1)
        self.entry_sudo = Gtk.Entry()
        self.entry_sudo.set_visibility(False)
        self.entry_sudo.set_invisible_char("•")
        self.entry_sudo.set_text(self.config.get("sudo_pass", ""))
        grid.attach(self.entry_sudo, 1, 6, 1, 1)

        self.chk_save_sudo = Gtk.CheckButton(label="Save Sudo Password")
        self.chk_save_sudo.set_active(bool(self.config.get("sudo_pass", "")))
        grid.attach(self.chk_save_sudo, 2, 6, 1, 1)

        if self.config.get("role") == "host": self.rb_host.set_active(True)

        # 3. Action Buttons
        btn_box = Gtk.Box(spacing=20)
        btn_box.set_halign(Gtk.Align.CENTER)
        main_vbox.pack_start(btn_box, False, False, 10)

        self.btn_start = Gtk.Button(label="Start Service")
        self.btn_start.get_style_context().add_class("suggested-action")
        self.btn_start.set_size_request(150, 50)
        self.btn_start.connect("clicked", self.on_start)
        btn_box.pack_start(self.btn_start, False, False, 0)

        self.btn_stop = Gtk.Button(label="Stop Service")
        self.btn_stop.get_style_context().add_class("destructive-action")
        self.btn_stop.set_size_request(150, 50)
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect("clicked", self.on_stop)
        btn_box.pack_start(self.btn_stop, False, False, 0)

        # 4. Logs Area
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
            "ssid": self.entry_ssid.get_text(),
            "password": self.entry_pass.get_text(),
            "wifi_mode": self.combo_mode.get_active_id(),
            "channel": int(self.spin_channel.get_value()),
            "country": country,
            "sudo_pass": sudo_pass
        }
        try:
            with open(CONFIG_FILE, 'w') as f: json.dump(data, f)
        except: pass

    def append_log(self, text):
        end_iter = self.log_buffer.get_end_iter()
        self.log_buffer.insert(end_iter, text)
        self.log_view.scroll_to_mark(self.log_mark, 0.0, True, 0.0, 1.0)

    def on_start(self, widget):
        self.save_config()
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.entry_ssid.set_sensitive(False)
        self.entry_pass.set_sensitive(False)
        self.spin_channel.set_sensitive(False)
        self.combo_mode.set_sensitive(False)
        self.combo_country.set_sensitive(False)

        role = "host" if self.rb_host.get_active() else "client"
        ssid = self.entry_ssid.get_text()
        pw = self.entry_pass.get_text()
        wifi_mode = self.combo_mode.get_active_id()
        channel = str(int(self.spin_channel.get_value()))
        country = self.combo_country.get_active_id() or "US"
        sudo_pw = self.entry_sudo.get_text()

        script_path = os.path.abspath("deck_upad.py")

        cmd = [
            "sudo", "-S",
            "python3", "-u", script_path,
            "--role", role,
            "--ssid", ssid,
            "--password", pw,
            "--wifi-mode", wifi_mode,
            "--channel", channel,
            "--country", country
        ]

        self.append_log(f"--- STARTING {role.upper()} MODE ---\n")

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
            self.on_stop(None)

    def monitor_process(self):
        while True:
            line = self.process.stdout.readline()
            if not line and self.process.poll() is not None: break
            if line: GLib.idle_add(self.append_log, line)
        GLib.idle_add(self.process_finished)

    def process_finished(self):
        self.append_log("\n--- SERVICE STOPPED ---\n")
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.entry_ssid.set_sensitive(True)
        self.entry_pass.set_sensitive(True)
        self.spin_channel.set_sensitive(True)
        self.combo_mode.set_sensitive(True)
        self.combo_country.set_sensitive(True)
        self.process = None

    def on_stop(self, widget):
        if self.process:
            self.append_log("\nStopping...\n")
            try: self.process.terminate()
            except: pass

            def force_kill_if_needed():
                import time
                time.sleep(1)
                if self.process and self.process.poll() is None:
                    subprocess.run(["sudo", "pkill", "-f", "deck_upad.py"], stderr=subprocess.DEVNULL)
            threading.Thread(target=force_kill_if_needed, daemon=True).start()

    def on_close(self, widget):
        self.on_stop(None)
        Gtk.main_quit()

if __name__ == "__main__":
    win = DeckUpadLauncher()
    Gtk.main()
