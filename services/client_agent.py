import socket
import time
import sys
from core.wifi_manager import WifiManager

# The Host IP is constant because the Host Container acts as the Router (192.168.50.1)
# which bridges to the Host Machine (192.168.50.2)
TARGET_HOST_IP = "192.168.50.2"
TARGET_PORT = 5555

class ClientService:
    def __init__(self):
        self.wifi = WifiManager()

    def start(self, ssid, password):
        print(f"[ClientService] Configuring WiFi Container for {ssid}...")
        try:
            self.wifi.start_client_mode(ssid=ssid, password=password)
        except Exception as e:
            print(f"[CRITICAL] WiFi Setup Failed: {e}")
            self.wifi.cleanup()
            sys.exit(1)

        print(f"[ClientService] Connected. Attempting handshake with Host ({TARGET_HOST_IP})...")

        connected = False
        attempts = 0

        while not connected and attempts < 30:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET_HOST_IP, TARGET_PORT))

                print("   >> Sending HELLO packet...")
                s.send(b"HELLO_FROM_DECK")

                resp = s.recv(1024).decode()
                print(f"\n[SUCCESS] Host Replied: {resp}")

                if resp == "ACK_AUTHORIZED":
                    print("   >> Handshake Verified!")
                    connected = True

                s.close()

            except (socket.timeout, ConnectionRefusedError, OSError):
                print(f"   .. Pinging Host (Attempt {attempts+1}/30)...")
                time.sleep(2)
                attempts += 1

        if not connected:
            print("\n[FAIL] Could not reach Host. Check Firewall?")

        # Keep alive for testing so we don't kill the connection immediately
        print("\n[ClientService] Session Active. Press Ctrl+C to exit.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[ClientService] Stopping...")
        self.wifi.cleanup()
