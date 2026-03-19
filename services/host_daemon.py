import socket
import time
import sys
import threading
import subprocess
import os

sys.path.append(".")
from core.wifi_manager import WifiManager, HOST_LAN_IP
from core.usbip_manager import UsbIpManager
from core.input_server import InputServer
from core.video_sender_manager import VideoSenderManager

class HostService:
    def __init__(self):
        self.wifi = WifiManager()
        self.usbip = UsbIpManager()
        self.video_mgr = VideoSenderManager()
        self.input_server = InputServer()
        self.running = True
        self.server_socket = None
        self.client_conn = None
        self.video_proc = None

    def start(self, ssid, password, channel=165, wifi_mode="ax", country="US",
              p2p_iface=None, internet_iface="none", internet_ssid=None, internet_pass=None,
              bootstrap_ssid=None, bootstrap_pass=None):
        print("="*50)
        print("   DECK-UPAD HOST DAEMON (CONTAINERIZED)")
        print("="*50)

        print("[Host] Performing Pre-Flight Checks...")

        # Validate that P2P and Internet interfaces are not the same
        if p2p_iface and internet_iface and internet_iface.lower() != "none":
            if p2p_iface == internet_iface:
                print(f"[CRITICAL] Configuration Error: P2P interface ({p2p_iface}) and Internet interface ({internet_iface}) cannot be the same.")
                print("[CRITICAL] Please select different interfaces, or set Internet Interface to 'none' if you don't need internet sharing.")
                sys.exit(1)

        try:
            self.wifi.ensure_image_exists()
            self.usbip.ensure_image_exists()
            self.video_mgr.ensure_image_exists()
        except Exception as e:
            print(f"[CRITICAL] Pre-flight build failed: {e}")
            sys.exit(1)

        print(f"[Host] Initializing WiFi Bridge (SSID: {ssid})...")
        try:
            # Pass new explicit interface configuration
            self.wifi.start_host_mode(
                ssid=ssid,
                password=password,
                channel=channel,
                wifi_mode=wifi_mode,
                country=country,
                p2p_iface=p2p_iface,
                internet_iface=internet_iface,
                internet_ssid=internet_ssid,
                internet_pass=internet_pass,
                bootstrap_ssid=bootstrap_ssid,
                bootstrap_pass=bootstrap_pass
            )
        except Exception as e:
            print(f"[CRITICAL] WiFi Failed: {e}")
            self.stop()
            sys.exit(1)

        try:
            self.usbip.start_receiver_mode()
        except Exception as e:
            print(f"[CRITICAL] USBIP Receiver Failed: {e}")
            self.stop()
            sys.exit(1)

        print(f"[Host] Infrastructure Ready. IP: {HOST_LAN_IP}")

        self.input_server.start()
        self.run_server()

    def run_server(self):
        attempts = 0
        bound = False
        while not bound and attempts < 10:
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((HOST_LAN_IP, 5555))
                self.server_socket.listen(1)
                bound = True
                print(f"[Host] Listening for Deck on {HOST_LAN_IP}:5555...")
            except OSError as e:
                print(f"[Host] Bind failed (Attempt {attempts+1}/10): {e}")
                time.sleep(1)
                attempts += 1

        if not bound:
            print("[CRITICAL] Could not bind to network interface.")
            self.stop()
            return

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                client_ip = addr[0]

                if self.client_conn:
                    try: self.client_conn.close()
                    except: pass
                    self._stop_video_process()

                print(f"\n[>>> CONNECTION] Deck Connected from: {client_ip}")
                self.client_conn = conn

                data = conn.recv(1024).decode().strip()
                if data.startswith("HELLO_FROM_DECK"):
                    conn.send(b"ACK_AUTHORIZED")
                    self._start_video_process(client_ip)

                    if "|BUS_ID:" in data:
                        bus_id = data.split("|BUS_ID:")[1]
                        threading.Thread(target=self.usbip.connect_device, args=(client_ip, bus_id)).start()
                else:
                    conn.close()
                    self.client_conn = None

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"[Host] Loop Error: {e}")

    def _start_video_process(self, target_ip):
        self._stop_video_process()
        print(f"[Host] Launching Video Sender Container...")
        self.video_proc = self.video_mgr.start(target_ip)
        threading.Thread(target=self._monitor_video_output, args=(self.video_proc,), daemon=True).start()

    def _monitor_video_output(self, proc):
        while self.running and proc.poll() is None:
            line = proc.stdout.readline()
            if not line: break

            msg = line.strip()
            print(f"[VideoLog] {msg}")

            if msg.startswith("HOST_RES:"):
                try:
                    parts = msg.split(":")[1].split("x")
                    self.input_server.host_w = int(parts[0])
                    self.input_server.host_h = int(parts[1])
                except: pass

            elif msg.startswith("STREAM_RES:"):
                try:
                    parts = msg.split(":")[1].split("x")
                    w, h = int(parts[0]), int(parts[1])
                    self.input_server.update_stream_dimensions(w, h)
                    if self.client_conn:
                        self.client_conn.send(f"CMD_RES_UPDATE:{w}x{h}".encode())
                except: pass

            elif msg == "VIDEO_STARTING":
                if self.client_conn:
                    try: self.client_conn.send(b"CMD_START_VIDEO")
                    except: pass
            elif msg == "VIDEO_STOPPED":
                if self.client_conn:
                    try: self.client_conn.send(b"CMD_STOP_VIDEO")
                    except: pass

    def _stop_video_process(self):
        if self.video_proc:
            print("[Host] Stopping Video Process...")
            self.video_mgr.stop()
            self.video_proc = None

    def stop(self):
        self.running = False
        if self.input_server: self.input_server.stop()
        if self.client_conn:
            try: self.client_conn.send(b"CMD_SHUTDOWN"); self.client_conn.close()
            except: pass
        self._stop_video_process()
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        self.usbip.cleanup()
        self.wifi.cleanup()
        print("[Host] Stopped.")
