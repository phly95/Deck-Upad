import socket
import time
import sys
from core.wifi_manager import WifiManager
from core.usbip_manager import UsbIpManager

TARGET_HOST_IP = "192.168.50.2"
TARGET_PORT = 5555

class ClientService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.bus_id = None
        self.host_socket = None

    def start(self, ssid, password):
        # --- PRE-FLIGHT CHECK ---
        print("[ClientService] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            print("Ensure you have an active internet connection before starting.")
            sys.exit(1)

        # 1. WiFi Setup
        print(f"[ClientService] Configuring WiFi Container for {ssid}...")
        try:
            self.wifi.start_client_mode(ssid=ssid, password=password)
        except Exception as e:
            print(f"[CRITICAL] WiFi Setup Failed: {e}")
            self.stop()
            sys.exit(1)

        # 2. USBIP Setup
        print("[ClientService] Setting up Controller Input...")
        try:
            self.bus_id = self.usbip.start_sender_mode()
            if not self.bus_id:
                print("[WARNING] Could not find Steam Deck Controller! Input will not work.")
            else:
                print(f"[ClientService] Controller ready on Bus {self.bus_id}")
        except Exception as e:
            print(f"[ERROR] USBIP Init Failed: {e}")

        # 3. Handshake & Monitor
        self.host_socket = self._establish_handshake()

        if self.host_socket:
            self._monitor_lifecycle()

    def _establish_handshake(self):
        print(f"[ClientService] Connecting to Host ({TARGET_HOST_IP})...")
        attempts = 0

        payload = "HELLO_FROM_DECK"
        if self.bus_id:
            payload += f"|BUS_ID:{self.bus_id}"

        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10) # Longer timeout for active connection
                s.connect((TARGET_HOST_IP, TARGET_PORT))

                print(f"   >> Sending: {payload}")
                s.send(payload.encode())

                resp = s.recv(1024).decode()
                print(f"\n[SUCCESS] Host Replied: {resp}")

                if "ACK_AUTHORIZED" in resp:
                    print("   >> Session Established! Input should be active.")
                    # Return the open socket to keep alive
                    return s
                else:
                    s.close()

            except (socket.timeout, ConnectionRefusedError, OSError):
                time.sleep(2)
                attempts += 1
                if attempts % 5 == 0: print("   .. waiting for Host ..")
            except KeyboardInterrupt:
                self.stop()
                return None

    def _monitor_lifecycle(self):
        print("[ClientService] Monitoring Host connection... (Ctrl+C to stop)")
        try:
            while True:
                # Blocking read waiting for Shutdown signal or disconnect
                data = self.host_socket.recv(1024)

                if not data:
                    print("\n[DISCONNECT] Host closed connection unexpectedly.")
                    break

                msg = data.decode().strip()
                if msg == "CMD_SHUTDOWN":
                    print("\n[STOP] Received Shutdown Command from Host.")
                    break

        except (ConnectionResetError, OSError):
            print("\n[DISCONNECT] Connection lost.")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        print("\n[ClientService] Stopping...")
        if self.host_socket:
            try: self.host_socket.close()
            except: pass
        self.usbip.cleanup()
        self.wifi.cleanup()
        sys.exit(0)
