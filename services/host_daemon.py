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

    def start(self, ssid, password, channel=165, wifi_mode="ax", country="US"):
        print("="*50)
        print("   DECK-UPAD HOST DAEMON")
        print("="*50)

        # 1. PRE-FLIGHT CHECKS
        print("[Host] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            sys.exit(1)

        # 2. START INFRASTRUCTURE
        print(f"[Host] Initializing WiFi Bridge (SSID: {ssid})...")
        try:
            self.wifi.start_host_mode(ssid=ssid, password=password, channel=channel, wifi_mode=wifi_mode, country=country)
        except Exception as e:
            print(f"[CRITICAL] WiFi Failed: {e}")
            self.stop()
            sys.exit(1)

        try:
            self.usbip.start_receiver_mode()
        except Exception as e:
            print(f"[CRITICAL] USBIP Receiver Failed: {e}")
            self.stop()
            sys.exit(1)

        print(f"[Host] Infrastructure Ready. IP: {HOST_LAN_IP}")
        self.run_server()

    def run_server(self):
        attempts = 0
        bound = False

        while not bound and attempts < 10:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((HOST_LAN_IP, 5555))
                self.server_socket.listen(1)
                bound = True
                print(f"[Host] Listening for Deck on {HOST_LAN_IP}:5555...")
            except OSError as e:
                print(f"[Host] Bind failed (Attempt {attempts+1}/10): {e}")
                time.sleep(1)
                attempts += 1

        if not bound:
            print("[CRITICAL] Could not bind to network interface.")
            self.stop()
            return

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
                    self._start_video_process(client_ip)

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
                print(f"[Host] Loop Error: {e}")

    def _get_user_env(self):
        sudo_user = os.environ.get('SUDO_USER')
        if not sudo_user: return os.environ.copy()

        env = os.environ.copy()
        try:
            import pwd
            pw = pwd.getpwnam(sudo_user)
            env['USER'] = sudo_user
            env['LOGNAME'] = sudo_user
            env['HOME'] = pw.pw_dir
            env['UID'] = str(pw.pw_uid)
            if 'XDG_RUNTIME_DIR' not in env:
                env['XDG_RUNTIME_DIR'] = f"/run/user/{pw.pw_uid}"
        except: pass
        return env

    def _start_video_process(self, target_ip):
        self._stop_video_process()

        sudo_user = os.environ.get('SUDO_USER')
        cmd = ["python3", "core/video_sender.py", target_ip]
        if sudo_user:
            cmd = ["sudo", "-u", sudo_user, "-E", "python3", "core/video_sender.py", target_ip]

        print(f"[Host] Launching Video Sender as user: {sudo_user or 'root'}")

        self.video_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=self._get_user_env(),
            text=True,
            bufsize=1
        )

        threading.Thread(target=self._monitor_video_output, args=(self.video_proc,), daemon=True).start()

    def _monitor_video_output(self, proc):
        while self.running and proc.poll() is None:
            line = proc.stdout.readline()
            if not line: break

            msg = line.strip()
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
