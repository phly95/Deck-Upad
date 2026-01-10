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
        self.client_conn = None # Keep track of the active client

    def start(self, ssid, password, channel=165, wifi_mode="ax"):
        # --- PRE-FLIGHT CHECK ---
        print("[HostService] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            sys.exit(1)

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
                # If we already have a client, we don't strictly need to accept more
                # (unless supporting multiple controllers), but we keep listening to reject or log.
                conn, addr = self.server_socket.accept()
                client_ip = addr[0]

                # If we already have a client, close the old one or reject the new one?
                # For this setup, we'll assume the new one is a re-connect and replace the old.
                if self.client_conn:
                    try: self.client_conn.close()
                    except: pass

                print(f"\n[>>> CONNECTION] From: {client_ip}")
                self.client_conn = conn # Store the connection

                data = conn.recv(1024).decode().strip()
                print(f"      Payload: {data}")

                response = "ACK_UNKNOWN"

                if data.startswith("HELLO_FROM_DECK"):
                    response = "ACK_AUTHORIZED"

                    if "|BUS_ID:" in data:
                        bus_id = data.split("|BUS_ID:")[1]
                        print(f"      Deck requested input attach: Bus {bus_id}")
                        threading.Thread(target=self.usbip.connect_device, args=(client_ip, bus_id)).start()
                    else:
                        print("      No controller info provided.")

                    # Send ACK
                    conn.send(response.encode())

                    # IMPORTANT: Do NOT close conn here. We keep it alive to monitor lifecycle.
                    print("      Session Active. Monitoring for disconnect...")

                else:
                    conn.send(response.encode())
                    conn.close() # Close unknown connections immediately

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"Socket Loop Error: {e}")

    def stop(self):
        self.running = False

        # 1. Notify Client
        if self.client_conn:
            try:
                print("[HostService] Sending Shutdown Signal to Client...")
                self.client_conn.send(b"CMD_SHUTDOWN")
                self.client_conn.close()
            except: pass
            self.client_conn = None

        # 2. Cleanup Server
        if self.server_socket:
            try: self.server_socket.close()
            except: pass

        # 3. Cleanup Containers
        self.usbip.cleanup()
        self.wifi.cleanup()
        print("[HostService] Stopped.")
