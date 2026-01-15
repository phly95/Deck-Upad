import socket
import time
import sys
import subprocess
import os
import shlex

sys.path.append(".")
from core.wifi_manager import WifiManager
from core.usbip_manager import UsbIpManager

TARGET_HOST_IP = "192.168.50.2"
TARGET_PORT = 5555
GUI_CONTROL_PORT = 5003

# Image Config
REC_CONTAINER = "stream-receiver"
REC_IMAGE = "localhost/stream-receiver-final"
REC_BASE = "registry.fedoraproject.org/fedora:39"

class ClientService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.bus_id = None
        self.host_socket = None
        self.receiver_proc = None
        self.sudo_user = os.environ.get('SUDO_USER') or "deck" # Fallback to 'deck' if detecting fails

    def _ensure_flatpak_runtime(self):
        # GNOME SDK 45 + FFmpeg 23.08
        runtime = "org.gnome.Sdk/x86_64/45"
        ffmpeg = "org.freedesktop.Platform.ffmpeg-full/x86_64/23.08"

        print(f"[Client] Checking for Flatpak Runtime & Codecs...")

        # Check Logic
        missing = []
        for ref in [runtime, ffmpeg]:
            try:
                subprocess.run(["sudo", "-u", self.sudo_user, "flatpak", "info", ref],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                missing.append(ref)

        if not missing:
            print("   >> Components found.")
            return

        print(f"[Client] Installing missing components: {missing}")

        try:
            # Ensure Flathub
            subprocess.run(
                ["sudo", "-u", self.sudo_user, "flatpak", "remote-add", "--if-not-exists", "--user", "flathub", "https://flathub.org/repo/flathub.flatpakrepo"],
                check=True, stderr=subprocess.DEVNULL
            )

            # Install
            for ref in missing:
                subprocess.run(
                    ["sudo", "-u", self.sudo_user, "flatpak", "install", "--user", "-y", "flathub", ref],
                    check=True
                )
            print("   >> Installation Complete.")
        except subprocess.CalledProcessError as e:
            print(f"[CRITICAL] Failed to install dependencies via Flatpak: {e}")
            sys.exit(1)

    def start(self, ssid, password, country="US"):
        print("="*50)
        print("   DECK-UPAD CLIENT AGENT (NATIVE FLATPAK)")
        print("="*50)

        # 1. PRE-FLIGHT CHECKS
        print("[Client] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
            # NEW: Check for Flatpak Runtime
            self._ensure_flatpak_runtime()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight failed: {e}")
            sys.exit(1)

        # 2. START HARDWARE
        print(f"[Client] Configuring WiFi Container for {ssid}...")
        try:
            self.wifi.start_client_mode(ssid=ssid, password=password, country=country)
        except Exception as e:
            print(f"[CRITICAL] WiFi Setup Failed: {e}")
            self.stop()
            sys.exit(1)

        print("[Client] Setting up Controller Input...")
        try:
            self.bus_id = self.usbip.start_sender_mode()
            if not self.bus_id:
                print("[WARNING] Could not find Steam Deck Controller! Input will not work.")
            else:
                print(f"[Client] Controller ready on Bus {self.bus_id}")
        except Exception as e:
            print(f"[ERROR] USBIP Init Failed: {e}")

        # 3. START GUI OVERLAY
        print("[Client] Launching Native Video Receiver...")
        self._launch_native_receiver()

        # 4. CONNECT TO HOST
        self.host_socket = self._establish_handshake()

        # 5. RUNTIME LOOP
        if self.host_socket:
            self._monitor_lifecycle()

    def _launch_native_receiver(self):
        # Kill old instances
        subprocess.run(["pkill", "-f", "core/video_receiver.py"], stderr=subprocess.DEVNULL)

        script_path = os.path.abspath("core/video_receiver.py")

        print(f"[Client] Launching Receiver via Flatpak wrapper...")

        cmd = [
            "sudo", "-u", self.sudo_user,
            "flatpak", "run",
            "--command=python3",
            "--filesystem=host",
            "--share=network",
            "--device=all",
            "--socket=x11",
            "--socket=wayland",
            "org.gnome.Sdk//45",
            script_path,
            "--host-ip", TARGET_HOST_IP,
            "--fullscreen"
        ]

        try:
            self.receiver_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
            print(f"[Client] Receiver PID: {self.receiver_proc.pid}")
        except Exception as e:
            print(f"[Client] Failed to launch GUI: {e}")

        time.sleep(2)

    def _establish_handshake(self):
        print(f"[Client] Connecting to Host ({TARGET_HOST_IP})...")
        payload = "HELLO_FROM_DECK"
        if self.bus_id:
            payload += f"|BUS_ID:{self.bus_id}"

        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((TARGET_HOST_IP, TARGET_PORT))
                s.send(payload.encode())
                resp = s.recv(1024).decode()
                if "ACK_AUTHORIZED" in resp:
                    print("   >> Session Established!")
                    self._send_gui_command("STATUS:Connected. Ready.")
                    s.settimeout(None)
                    return s
                else: s.close()
            except (socket.timeout, ConnectionRefusedError, OSError):
                time.sleep(2)
            except KeyboardInterrupt:
                self.stop()
                return None

    def _monitor_lifecycle(self):
        print("[Client] Monitoring Host connection... (Ctrl+C to stop)")
        try:
            while True:
                data = self.host_socket.recv(1024)
                if not data: break
                msgs = data.decode().strip().split('\n')
                for msg in msgs:
                    if msg == "CMD_SHUTDOWN": return
                    elif msg == "CMD_START_VIDEO": self._send_gui_command("START_VIDEO")
                    elif msg == "CMD_STOP_VIDEO": self._send_gui_command("STOP_VIDEO")
                    elif msg.startswith("CMD_RES_UPDATE:"):
                        res = msg.split(":")[1]
                        self._send_gui_command(f"RES_UPDATE:{res}")
        except: pass
        finally: self.stop()

    def _send_gui_command(self, cmd):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cmd.encode(), ("127.0.0.1", GUI_CONTROL_PORT))
        except: pass

    def stop(self):
        print("\n[Client] Stopping...")
        if self.host_socket:
            try: self.host_socket.close()
            except: pass

        if self.receiver_proc:
            self.receiver_proc.terminate()
            try: self.receiver_proc.wait(timeout=1)
            except: self.receiver_proc.kill()

        subprocess.run(["pkill", "-f", "core/video_receiver.py"], stderr=subprocess.DEVNULL)

        if self.bus_id:
            self.usbip.release_device(self.bus_id)

        self.usbip.cleanup()
        self.wifi.cleanup()
        sys.exit(0)
