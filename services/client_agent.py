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

    def ensure_receiver_image_exists(self):
        """
        Ensures the GStreamer Receiver image is built.
        MUST run before WiFi is moved to container.
        """
        # Check if exists
        res = subprocess.run(["podman", "images", "-q", REC_IMAGE], stdout=subprocess.PIPE, text=True)
        if res.stdout.strip():
            return

        print(f"[Client] Building Receiver Image '{REC_IMAGE}' (Internet Required)...")
        builder = f"{REC_CONTAINER}-builder"

        try:
            subprocess.run(["podman", "rm", "-f", builder], stderr=subprocess.DEVNULL)
            subprocess.run(["podman", "run", "-d", "--name", builder, REC_BASE, "sleep", "infinity"], check=True)

            # Install GStreamer Deps
            print("   Installing GStreamer dependencies...")

            # 1. RPM Fusion (For H.264)
            subprocess.run(["podman", "exec", builder, "dnf", "install", "-y", "--nogpgcheck",
                "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"], check=True)

            # 2. Packages
            pkgs = [
                "python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
                "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
                "gstreamer1-libav", "gstreamer1-plugins-bad-free",
                "mesa-dri-drivers", "libwayland-client", "python3"
            ]
            subprocess.run(["podman", "exec", builder, "dnf", "install", "-y"] + pkgs, check=True)

            # 3. Commit
            print(f"   Committing to {REC_IMAGE}...")
            subprocess.run(["podman", "commit", builder, REC_IMAGE], check=True)

        except subprocess.CalledProcessError as e:
            print(f"[CRITICAL] Failed to build receiver image: {e}")
            subprocess.run(["podman", "stop", builder], stderr=subprocess.DEVNULL)
            raise e
        finally:
            subprocess.run(["podman", "rm", "-f", builder], stderr=subprocess.DEVNULL)


    def start(self, ssid, password):
        print("="*50)
        print("   DECK-UPAD CLIENT AGENT")
        print("="*50)

        # --- 1. PRE-FLIGHT CHECK ---
        print("[Client] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
            self.ensure_receiver_image_exists() # <--- NEW: Build this while online
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            print("Ensure you have an active internet connection before starting.")
            sys.exit(1)

        # --- 2. START HARDWARE ---
        print(f"[Client] Configuring WiFi Container for {ssid}...")
        try:
            self.wifi.start_client_mode(ssid=ssid, password=password)
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

        # --- 3. START GUI OVERLAY ---
        print("[Client] Launching Video Receiver GUI...")
        self._launch_receiver_container()

        # --- 4. CONNECT TO HOST ---
        self.host_socket = self._establish_handshake()

        # --- 5. RUNTIME LOOP ---
        if self.host_socket:
            self._monitor_lifecycle()

    def _launch_receiver_container(self):
        # Stop existing if any
        subprocess.run(["podman", "rm", "-f", self.gui_container_name], stderr=subprocess.DEVNULL)

        # Map the local script into the container
        script_path = os.path.abspath("core/video_receiver.py")

        cmd = (
            f"podman run -d --replace --name {self.gui_container_name} "
            f"--net=host "
            f"--privileged "
            f"-v /tmp/.X11-unix:/tmp/.X11-unix "
            f"-v /run/user/{os.getuid()}:/run/user/{os.getuid()} "
            f"-e DISPLAY={os.environ.get('DISPLAY', ':0')} "
            f"-v {script_path}:/app/main.py "
            f"{REC_IMAGE} "
            f"python3 /app/main.py"
        )

        subprocess.run(shlex.split(cmd), stdout=subprocess.DEVNULL)
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
        subprocess.run(["podman", "stop", "-t", "0", self.gui_container_name], stderr=subprocess.DEVNULL)
        self.usbip.cleanup()
        self.wifi.cleanup()
        sys.exit(0)
