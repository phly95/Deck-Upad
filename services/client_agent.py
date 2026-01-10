import socket
import time
import sys
import subprocess
import os
import shlex

# Adjust path to find core modules
sys.path.append(".")

from core.wifi_manager import WifiManager
from core.usbip_manager import UsbIpManager

TARGET_HOST_IP = "192.168.50.2"
TARGET_PORT = 5555
GUI_CONTROL_PORT = 5003

class ClientService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.bus_id = None
        self.host_socket = None
        self.gui_container_name = "stream-receiver"

    def start(self, ssid, password):
        print("="*50)
        print("   DECK-UPAD CLIENT AGENT")
        print("="*50)

        # --- 1. PRE-FLIGHT CHECK ---
        print("[Client] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
            # We assume the receiver image is built/pulled separately or exists locally
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

        # We assume 'localhost/stream-receiver-final' exists.
        # If not, you might need a build step here similar to wifi/usbip.
        # For now, we assume standard Fedora image + python dependencies installed.
        # A simple fallback is using the 'usbip-ready-v9' image if it has python-gobject/gtk installed.

        cmd = (
            f"podman run -d --replace --name {self.gui_container_name} "
            f"--net=host "  # Critical: Must share net to receive UDP video
            f"--privileged "
            f"-v /tmp/.X11-unix:/tmp/.X11-unix "
            f"-v /run/user/{os.getuid()}:/run/user/{os.getuid()} " # Wayland/PulseAudio sockets
            f"-e DISPLAY={os.environ.get('DISPLAY', ':0')} "
            f"-v {script_path}:/app/main.py "
            f"localhost/stream-receiver-final "
            f"python3 /app/main.py"
        )

        # Note: If image is missing, this will fail silently in background.
        # Ideally, we'd check `podman images` here too.
        subprocess.run(shlex.split(cmd), stdout=subprocess.DEVNULL)
        time.sleep(2) # Give GUI time to appear

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

                print(f"   >> Sending Hello...")
                s.send(payload.encode())

                resp = s.recv(1024).decode()
                print(f"   >> Host Replied: {resp}")

                if "ACK_AUTHORIZED" in resp:
                    print("   >> Session Established!")
                    # Send initial status to GUI
                    self._send_gui_command("STATUS:Connected. Ready.")
                    return s
                else:
                    s.close()

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
                if not data:
                    print("\n[DISCONNECT] Host closed connection.")
                    self._send_gui_command("STATUS:Host Disconnected.")
                    break

                # Handle Commands (Joined by null/newline if multiple arrive at once)
                msgs = data.decode().strip().split('\n')
                for msg in msgs:
                    if not msg: continue
                    print(f"[Client] Recv Command: {msg}")

                    if msg == "CMD_SHUTDOWN":
                        print("\n[STOP] Received Shutdown Command.")
                        return
                    elif msg == "CMD_START_VIDEO":
                        self._send_gui_command("START_VIDEO")
                    elif msg == "CMD_STOP_VIDEO":
                        self._send_gui_command("STOP_VIDEO")

        except (ConnectionResetError, OSError):
            print("\n[DISCONNECT] Connection lost.")
            self._send_gui_command("STATUS:Connection Lost.")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _send_gui_command(self, cmd):
        """Sends UDP command to the local GUI container"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cmd.encode(), ("127.0.0.1", GUI_CONTROL_PORT))
        except Exception as e:
            print(f"[Client] Failed to contact GUI: {e}")

    def stop(self):
        print("\n[Client] Stopping...")
        if self.host_socket:
            try: self.host_socket.close()
            except: pass

        # Kill GUI
        subprocess.run(["podman", "stop", "-t", "0", self.gui_container_name],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self.usbip.cleanup()
        self.wifi.cleanup()
        sys.exit(0)
