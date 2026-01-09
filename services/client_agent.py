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

    def start(self, ssid, password):
        # --- PRE-FLIGHT CHECK ---
        print("[ClientService] Performing Pre-Flight Checks...")
        try:
            # Build images while we still have Host Internet
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            print("Ensure you have an active internet connection before starting.")
            sys.exit(1)

        # 1. WiFi Setup (Host Internet Dies Here)
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

        # 3. Handshake
        self._handshake_loop()

    def _handshake_loop(self):
        print(f"[ClientService] Connecting to Host ({TARGET_HOST_IP})...")
        connected = False
        attempts = 0

        payload = "HELLO_FROM_DECK"
        if self.bus_id:
            payload += f"|BUS_ID:{self.bus_id}"

        while not connected:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET_HOST_IP, TARGET_PORT))

                print(f"   >> Sending: {payload}")
                s.send(payload.encode())

                resp = s.recv(1024).decode()
                print(f"\n[SUCCESS] Host Replied: {resp}")

                if "ACK_AUTHORIZED" in resp:
                    print("   >> Session Established! Input should be active.")
                    connected = True

                s.close()

            except (socket.timeout, ConnectionRefusedError, OSError):
                time.sleep(2)
                attempts += 1
                if attempts % 5 == 0: print("   .. waiting for Host ..")

        # Keep alive
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[ClientService] Stopping...")
        self.usbip.cleanup()
        self.wifi.cleanup()
