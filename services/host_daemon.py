import socket
import time
import sys
import threading
from core.wifi_manager import WifiManager, HOST_LAN_IP
from core.usbip_manager import UsbIpManager

class HostService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.running = True
        self.server_socket = None

    def start(self, ssid, password, channel=165, wifi_mode="ax"):
        # 1. Start WiFi
        print(f"[HostService] Initializing WiFi Bridge...")
        try:
            self.wifi.start_host_mode(ssid=ssid, password=password, channel=channel, wifi_mode=wifi_mode)
        except Exception as e:
            print(f"[CRITICAL] WiFi Failed: {e}")
            self.stop()
            sys.exit(1)

        # 2. Start USBIP Receiver
        try:
            self.usbip.start_receiver_mode()
        except Exception as e:
            print(f"[CRITICAL] USBIP Receiver Failed: {e}")
            self.stop()
            sys.exit(1)

        print(f"[HostService] Ready. Host IP: {HOST_LAN_IP}")
        self.run_server()

    def run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST_LAN_IP, 5555))
            self.server_socket.listen(1)
        except OSError as e:
            print(f"[Error] Bind failed: {e}")
            self.stop()
            return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                client_ip = addr[0]
                print(f"\n[>>> CONNECTION] From: {client_ip}")

                data = conn.recv(1024).decode().strip()
                print(f"      Payload: {data}")

                response = "ACK_UNKNOWN"

                if data.startswith("HELLO_FROM_DECK"):
                    response = "ACK_AUTHORIZED"

                    # Parse USB Bus ID
                    if "|BUS_ID:" in data:
                        bus_id = data.split("|BUS_ID:")[1]
                        print(f"      Deck requested input attach: Bus {bus_id}")

                        # Run attach in background so we don't block the socket reply
                        threading.Thread(target=self.usbip.connect_device, args=(client_ip, bus_id)).start()
                    else:
                        print("      No controller info provided.")

                conn.send(response.encode())
                conn.close()

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"Socket Error: {e}")

    def stop(self):
        self.running = False
        if self.server_socket: self.server_socket.close()
        self.usbip.cleanup()
        self.wifi.cleanup()
        print("[HostService] Stopped.")
