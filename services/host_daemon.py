import socket
import time
import sys
import threading
from core.wifi_manager import WifiManager, HOST_LAN_IP

class HostService:
    def __init__(self):
        self.wifi = WifiManager()
        self.running = True
        self.server_socket = None

    # UPDATED: Accept wifi_mode
    def start(self, ssid, password, channel=165, wifi_mode="ax"):
        print(f"[HostService] Initializing WiFi Bridge (SSID: {ssid}, Ch: {channel}, Mode: {wifi_mode})...")
        try:
            # Pass it along
            self.wifi.start_host_mode(ssid=ssid, password=password, channel=channel, wifi_mode=wifi_mode)
        except Exception as e:
            print(f"[CRITICAL] Failed to start WiFi: {e}")
            self.stop()
            sys.exit(1)

        print(f"[HostService] Network Ready. Host IP: {HOST_LAN_IP}")
        print("[HostService] Waiting for Deck connection...")
        self.run_server()

    def run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST_LAN_IP, 5555))
            self.server_socket.listen(1)
        except OSError as e:
            print(f"[Error] Could not bind to {HOST_LAN_IP}:5555. {e}")
            self.stop()
            return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                print(f"\n[>>> CONNECTION DETECTED] From: {addr}")

                data = conn.recv(1024).decode().strip()
                print(f"      Payload: {data}")

                if data == "HELLO_FROM_DECK":
                    response = "ACK_AUTHORIZED"
                    print("      Status: Authorized. Sending ACK.")
                else:
                    response = "ACK_UNKNOWN"
                    print("      Status: Unknown Client.")

                conn.send(response.encode())
                conn.close()
                print("[HostService] Connection closed. Listening for next...")

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"Socket Error: {e}")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.wifi.cleanup()
        print("[HostService] Stopped.")
