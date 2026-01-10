import socket
import time
import sys
import threading
import subprocess
import os

sys.path.append(".")
from core.wifi_manager import WifiManager, HOST_LAN_IP
from core.usbip_manager import UsbIpManager

class HostService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.running = True

        self.server_socket = None
        self.client_conn = None

        self.video_proc = None

    def start(self, ssid, password, channel=165, wifi_mode="ax"):
        # ... (Pre-flight and Infrastructure Start logic is unchanged) ...
        print("="*50)
        print("   DECK-UPAD HOST DAEMON")
        print("="*50)

        # 1. Start WiFi
        print(f"[Host] Initializing WiFi Bridge (SSID: {ssid})...")
        try:
            self.wifi.start_host_mode(ssid=ssid, password=password, channel=channel, wifi_mode=wifi_mode)
        except Exception as e:
            print(f"[CRITICAL] WiFi Failed: {e}")
            self.stop()
            sys.exit(1)

        # 2. Start USBIP
        try:
            self.usbip.start_receiver_mode()
        except Exception as e:
            print(f"[CRITICAL] USBIP Receiver Failed: {e}")
            self.stop()
            sys.exit(1)

        print(f"[Host] Infrastructure Ready. IP: {HOST_LAN_IP}")
        self.run_server()

    def run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST_LAN_IP, 5555))
            self.server_socket.listen(1)
        except OSError:
            self.stop(); return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                client_ip = addr[0]

                if self.client_conn:
                    try: self.client_conn.close()
                    except: pass
                    self._stop_video_process()

                print(f"\n[>>> CONNECTION] Deck Connected from: {client_ip}")
                self.client_conn = conn

                data = conn.recv(1024).decode().strip()
                if data.startswith("HELLO_FROM_DECK"):
                    conn.send(b"ACK_AUTHORIZED")

                    # 1. Start Video Sender (As User)
                    self._start_video_process(client_ip)

                    # 2. Attach USB
                    if "|BUS_ID:" in data:
                        bus_id = data.split("|BUS_ID:")[1]
                        threading.Thread(target=self.usbip.connect_device, args=(client_ip, bus_id)).start()

                else:
                    conn.close()
                    self.client_conn = None

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"[Host] Error: {e}")

    def _get_user_env(self):
        """Constructs environment for the subprocess to run as the sudo user."""
        sudo_user = os.environ.get('SUDO_USER')
        if not sudo_user:
            return os.environ.copy() # Fallback if not run with sudo

        env = os.environ.copy()

        # We need to ensure XDG_RUNTIME_DIR and DISPLAY/WAYLAND_DISPLAY are set
        # Usually 'sudo' preserves some, but 'sudo -u' wipes them.
        # We try to trust the current env (if user used sudo -E) or fallback.

        # Note: Ideally, you'd find the user's UID and construct /run/user/UID
        try:
            import pwd
            pw = pwd.getpwnam(sudo_user)
            env['USER'] = sudo_user
            env['LOGNAME'] = sudo_user
            env['HOME'] = pw.pw_dir
            env['UID'] = str(pw.pw_uid)

            # Crucial for Wayland/Pipewire
            if 'XDG_RUNTIME_DIR' not in env:
                env['XDG_RUNTIME_DIR'] = f"/run/user/{pw.pw_uid}"
        except: pass

        return env

    def _start_video_process(self, target_ip):
        self._stop_video_process()

        sudo_user = os.environ.get('SUDO_USER')
        cmd = ["python3", "core/video_sender.py", target_ip]

        if sudo_user:
            # Run as the original user
            cmd = ["sudo", "-u", sudo_user, "-E", "python3", "core/video_sender.py", target_ip]

        print(f"[Host] Launching Video Sender as user: {sudo_user or 'root'}")

        # Launch subprocess and pipe stdout so we can read status messages
        self.video_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merge stderr to see errors
            env=self._get_user_env(),
            text=True,
            bufsize=1 # Line buffered
        )

        # Start monitoring thread
        threading.Thread(target=self._monitor_video_output, args=(self.video_proc,), daemon=True).start()

    def _monitor_video_output(self, proc):
        """Reads stdout from the video sender process."""
        while self.running and proc.poll() is None:
            line = proc.stdout.readline()
            if not line: break

            msg = line.strip()
            # print(f"[VideoLog] {msg}") # Optional debug

            if msg == "VIDEO_STARTING":
                print("[Host] Signal: Video Starting -> Notifying Deck")
                if self.client_conn:
                    try: self.client_conn.send(b"CMD_START_VIDEO")
                    except: pass
            elif msg == "VIDEO_STOPPED":
                print("[Host] Signal: Video Stopped -> Notifying Deck")
                if self.client_conn:
                    try: self.client_conn.send(b"CMD_STOP_VIDEO")
                    except: pass
            elif "CRASH" in msg:
                 print(f"[Host] Video Sender Error: {msg}")

    def _stop_video_process(self):
        if self.video_proc:
            print("[Host] Stopping Video Process...")
            self.video_proc.terminate()
            self.video_proc.wait()
            self.video_proc = None

    def stop(self):
        self.running = False
        if self.client_conn:
            try: self.client_conn.send(b"CMD_SHUTDOWN"); self.client_conn.close()
            except: pass
        self._stop_video_process()
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        self.usbip.cleanup()
        self.wifi.cleanup()
        print("[Host] Stopped.")
