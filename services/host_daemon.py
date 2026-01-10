import socket
import time
import sys
import threading
import multiprocessing
import queue

# Adjust path to find core modules
sys.path.append(".")

from core.wifi_manager import WifiManager, HOST_LAN_IP
from core.usbip_manager import UsbIpManager
from core.video_sender import run_sender_process

class HostService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.running = True

        # Networking
        self.server_socket = None
        self.client_conn = None

        # Video Subprocess Management
        self.video_proc = None
        self.video_queue = multiprocessing.Queue()
        self.video_monitor_thread = None

    def start(self, ssid, password, channel=165, wifi_mode="ax"):
        print("="*50)
        print("   DECK-UPAD HOST DAEMON")
        print("="*50)

        # --- 1. PRE-FLIGHT CHECKS ---
        print("[Host] Performing Pre-Flight Checks...")
        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            sys.exit(1)

        # --- 2. START INFRASTRUCTURE ---
        # A. WiFi
        print(f"[Host] Initializing WiFi Bridge (SSID: {ssid})...")
        try:
            self.wifi.start_host_mode(ssid=ssid, password=password, channel=channel, wifi_mode=wifi_mode)
        except Exception as e:
            print(f"[CRITICAL] WiFi Failed: {e}")
            self.stop()
            sys.exit(1)

        # B. USBIP
        try:
            self.usbip.start_receiver_mode()
        except Exception as e:
            print(f"[CRITICAL] USBIP Receiver Failed: {e}")
            self.stop()
            sys.exit(1)

        print(f"[Host] Infrastructure Ready. IP: {HOST_LAN_IP}")

        # --- 3. START VIDEO MONITOR ---
        # This thread watches the queue from the VideoSender process
        self.video_monitor_thread = threading.Thread(target=self._monitor_video_status, daemon=True)
        self.video_monitor_thread.start()

        # --- 4. RUN SERVER LOOP ---
        self.run_server()

    def run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST_LAN_IP, 5555))
            self.server_socket.listen(1)
            print(f"[Host] Listening for Deck on port 5555...")
        except OSError as e:
            print(f"[Error] Bind failed: {e}")
            self.stop()
            return

        while self.running:
            try:
                # Accept new connection
                conn, addr = self.server_socket.accept()
                client_ip = addr[0]

                # Cleanup previous client if exists
                if self.client_conn:
                    print("[Host] New connection replacing old client.")
                    try: self.client_conn.close()
                    except: pass
                    self._stop_video_process()

                print(f"\n[>>> CONNECTION] Deck Connected from: {client_ip}")
                self.client_conn = conn

                # Handshake
                data = conn.recv(1024).decode().strip()
                print(f"      Payload: {data}")

                if data.startswith("HELLO_FROM_DECK"):
                    conn.send(b"ACK_AUTHORIZED")

                    # 1. Start Video Sender Process for this specific IP
                    print(f"      Spinning up Video Sender for {client_ip}...")
                    self._start_video_process(client_ip)

                    # 2. Attach USB Controller if requested
                    if "|BUS_ID:" in data:
                        bus_id = data.split("|BUS_ID:")[1]
                        print(f"      Attaching Controller: Bus {bus_id}")
                        threading.Thread(target=self.usbip.connect_device, args=(client_ip, bus_id)).start()
                    else:
                        print("      No controller info provided.")

                    print("      Session Active. Monitoring for disconnect...")

                else:
                    print("      Unauthorized Client. Closing.")
                    conn.send(b"ACK_UNKNOWN")
                    conn.close()
                    self.client_conn = None

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"[Host] Loop Error: {e}")

    def _start_video_process(self, target_ip):
        self._stop_video_process() # Ensure clean state
        # Launch the standalone VideoSender in a separate process
        # It communicates back to us via self.video_queue
        self.video_proc = multiprocessing.Process(
            target=run_sender_process,
            args=(target_ip, self.video_queue)
        )
        self.video_proc.start()

    def _stop_video_process(self):
        if self.video_proc and self.video_proc.is_alive():
            print("[Host] Stopping Video Process...")
            self.video_proc.terminate()
            self.video_proc.join()
        self.video_proc = None

    def _monitor_video_status(self):
        """
        Runs in a thread. Reads messages from VideoSender and forwards to Deck.
        """
        while self.running:
            try:
                # Blocking get with timeout to allow checking self.running
                msg = self.video_queue.get(timeout=1)

                if self.client_conn:
                    if msg == "VIDEO_STARTING":
                        print("[Host] Signal: Video Starting -> Notifying Deck")
                        try: self.client_conn.send(b"CMD_START_VIDEO")
                        except: pass
                    elif msg == "VIDEO_STOPPED":
                        print("[Host] Signal: Video Stopped -> Notifying Deck")
                        try: self.client_conn.send(b"CMD_STOP_VIDEO")
                        except: pass
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Host] Monitor Error: {e}")

    def stop(self):
        print("\n[Host] Shutting down...")
        self.running = False

        # 1. Notify Client
        if self.client_conn:
            try:
                print("[Host] Sending Shutdown Signal to Client...")
                self.client_conn.send(b"CMD_SHUTDOWN")
                self.client_conn.close()
            except: pass
            self.client_conn = None

        # 2. Kill Video
        self._stop_video_process()

        # 3. Cleanup Server
        if self.server_socket:
            try: self.server_socket.close()
            except: pass

        # 4. Cleanup Hardware Containers
        self.usbip.cleanup()
        self.wifi.cleanup()
        print("[Host] Stopped.")
