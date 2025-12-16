import sys
import threading
import socket
import json
import uuid
import time
import math
import subprocess
import os
import signal
import gi
import evdev
from evdev import UInput, ecodes, AbsInfo

gi.require_version('Gst', '1.0')
gi.require_version('Gio', '2.0')
from gi.repository import Gst, GLib, Gio

# --- KEEP-ALIVE WINDOW ---
KEEP_ALIVE_SCRIPT = r"""
import sys
import time
import math
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

class KeepAliveWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Stream Keep-Alive")
        self.set_default_size(400, 150)
        self.set_keep_above(True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(box)
        label = Gtk.Label(label="<span size='x-large' weight='bold'>STEP 1: DRAG TO VIRTUAL SCREEN</span>")
        label.set_use_markup(True)
        box.pack_start(label, True, True, 10)
        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(400, 40)
        self.drawing_area.connect("draw", self.on_draw)
        box.pack_start(self.drawing_area, True, True, 0)
        GLib.timeout_add(16, self.tick)

    def tick(self):
        self.drawing_area.queue_draw()
        return True

    def on_draw(self, widget, cr):
        w = widget.get_allocated_width()
        h = widget.get_allocated_height()
        t = time.time() * 10
        r = (math.sin(t) + 1) / 2
        cr.set_source_rgb(r, 0.2, 0.4)
        cr.rectangle(0, 0, w, h)
        cr.fill()
        pos = (time.time() * 400) % w
        cr.set_source_rgb(1, 1, 1)
        cr.rectangle(pos, 0, 40, h)
        cr.fill()
        return False

win = KeepAliveWindow()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
"""

# --- DISPLAY MANAGER ---
class DisplayManager:
    def __init__(self):
        self.displays = []
        self.total_w = 0
        self.total_h = 0
        self.selected_display = None

    def scan_displays(self):
        try:
            result = subprocess.run(['kscreen-doctor', '-j'], capture_output=True, text=True)
            data = json.loads(result.stdout)
            valid_outputs = []
            max_x = 0
            max_y = 0

            for output in data['outputs']:
                if output.get('connected') and output.get('enabled'):
                    pos = output.get('pos', {'x': 0, 'y': 0})
                    size = output.get('size', {'width': 1920, 'height': 1080})
                    info = {
                        'id': output['id'],
                        'name': output['name'],
                        'x': pos['x'], 'y': pos['y'],
                        'w': size['width'], 'h': size['height']
                    }
                    valid_outputs.append(info)
                    max_x = max(max_x, pos['x'] + size['width'])
                    max_y = max(max_y, pos['y'] + size['height'])

            self.displays = valid_outputs
            self.total_w = max_x
            self.total_h = max_y
            return self.displays
        except Exception as e:
            print(f"Error scanning displays: {e}")
            return []

    def select_display_cli(self):
        print("\n--- DETECTED DISPLAYS ---")
        for idx, d in enumerate(self.displays):
            print(f" {idx + 1}: {d['name']} ({d['w']}x{d['h']} at X={d['x']}, Y={d['y']})")
        while True:
            try:
                choice = input("\nSelect Display to Stream (Number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(self.displays):
                    self.selected_display = self.displays[idx]
                    return self.selected_display
            except ValueError:
                pass

# --- INPUT INJECTION ---
class InputServer(threading.Thread):
    def __init__(self, display_mgr):
        super().__init__()
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 5001))
        self.dm = display_mgr

        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        self.ui = UInput(cap, name="Python-Stream-Mouse")

    def run(self):
        print(" [INPUT] Listening for events on Port 5001...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                raw_x = msg['x']
                raw_y = msg['y']

                local_pixel_x = raw_x * self.dm.selected_display['w']
                local_pixel_y = raw_y * self.dm.selected_display['h']

                global_pixel_x = self.dm.selected_display['x'] + local_pixel_x
                global_pixel_y = self.dm.selected_display['y'] + local_pixel_y

                abs_x = int((global_pixel_x / self.dm.total_w) * 65535)
                abs_y = int((global_pixel_y / self.dm.total_h) * 65535)

                abs_x = max(0, min(65535, abs_x))
                abs_y = max(0, min(65535, abs_y))

                if msg['type'] == 'move':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.syn()
                elif msg['type'] in ['press', 'release']:
                    btn_code = ecodes.BTN_LEFT
                    if msg['btn'] == 2: btn_code = ecodes.BTN_MIDDLE
                    if msg['btn'] == 3: btn_code = ecodes.BTN_RIGHT
                    val = 1 if msg['type'] == 'press' else 0
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.write(ecodes.EV_KEY, btn_code, val)
                    self.ui.syn()
            except Exception:
                pass

# --- RESOLUTION BROADCASTER (UPDATED) ---
class ResolutionBroadcaster(threading.Thread):
    def __init__(self, target_ip, w, h):
        super().__init__()
        self.daemon = True
        self.target_ip = target_ip
        self.w = w
        self.h = h
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        msg = json.dumps({"cmd": "resize", "w": self.w, "h": self.h}).encode()
        print(f" [INFO] Broadcasting resolution {self.w}x{self.h} to {self.target_ip}:5002 every 2s...")
        while True:
            try:
                self.sock.sendto(msg, (self.target_ip, 5002))
                time.sleep(2)
            except Exception as e:
                print(f"Broadcast Error: {e}")
                time.sleep(5)

# --- PORTAL LOGIC ---
class PortalClient:
    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.portal_name = "org.freedesktop.portal.Desktop"
        self.object_path = "/org/freedesktop/portal/desktop"
        self.interface = "org.freedesktop.portal.ScreenCast"
        self.sender_name = self.bus.get_unique_name().replace('.', '_').replace(':', '')

    def call_request(self, method, args, signature):
        request_token = f"req_{uuid.uuid4().hex}"
        args[-1]['handle_token'] = GLib.Variant('s', request_token)
        request_path = f"/org/freedesktop/portal/desktop/request/{self.sender_name}/{request_token}"
        loop = GLib.MainLoop()
        response_data = {}
        def on_response(conn, sender, path, iface, signal, params, data):
            if path == request_path:
                response_data['code'] = params[0]
                response_data['results'] = params[1]
                loop.quit()
        sub_id = self.bus.signal_subscribe(self.portal_name, "org.freedesktop.portal.Request", "Response", request_path, None, Gio.DBusSignalFlags.NONE, on_response, None)
        try:
            self.bus.call_sync(self.portal_name, self.object_path, self.interface, method, GLib.Variant(f"({signature})", tuple(args)), None, Gio.DBusCallFlags.NONE, -1, None)
        except Exception as e:
            self.bus.signal_unsubscribe(sub_id)
            raise e
        loop.run()
        self.bus.signal_unsubscribe(sub_id)
        if response_data.get('code') != 0: raise Exception(f"Request failed. Code: {response_data.get('code')}")
        return response_data['results']

    def run(self):
        print("[2/4] Creating Session...")
        session_token = f"sess_{uuid.uuid4().hex}"
        results = self.call_request("CreateSession", [{'session_handle_token': GLib.Variant('s', session_token)}], "a{sv}")
        session_handle = results['session_handle']
        print("[3/4] Select Source (Ensure you select the SAME display!)...")
        self.call_request("SelectSources", [session_handle, {"types": GLib.Variant("u", 1), "cursor_mode": GLib.Variant("u", 2)}], "oa{sv}")
        print("[4/4] Starting Stream...")
        results = self.call_request("Start", [session_handle, "", {}], "osa{sv}")
        return results['streams'][0][0]

def get_best_encoder():
    factory = Gst.ElementFactory.find
    if factory("nvh264enc"): return "nvh264enc preset=low-latency-hq zerolatency=true bitrate=15000 rc-mode=cbr"
    if factory("vaapih264enc"): return "vaapih264enc rate-control=cbr bitrate=15000 keyframe-period=60 max-bframes=0 refs=1"
    return "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30"

def run_pipeline(node_id, receiver_ip, dm_instance, window_proc=None):
    Gst.init(None)

    # 1. Start Input Server
    input_server = InputServer(dm_instance)
    input_server.start()

    # 2. Start Resolution Broadcaster (NEW)
    w = dm_instance.selected_display['w']
    h = dm_instance.selected_display['h']
    res_broadcaster = ResolutionBroadcaster(receiver_ip, w, h)
    res_broadcaster.start()

    # 3. Build Pipeline
    encoder_str = get_best_encoder()

    pipeline_str = (
        f"pipewiresrc path={node_id} do-timestamp=true ! "
        "queue max-size-buffers=3 leaky=upstream ! "
        "videoconvert ! "
        "videorate max-rate=60 skip-to-first=true ! "
        f"video/x-raw,format=NV12,width={w},height={h},framerate=60/1 ! "
        f"{encoder_str} ! "
        "rtph264pay config-interval=1 pt=96 ! "
        f"udpsink name=sink host={receiver_ip} port=5000 sync=false"
    )

    print(f"\nRunning Pipeline:\n{pipeline_str}")

    pipeline = None
    try:
        pipeline = Gst.parse_launch(pipeline_str)
        pipeline.set_state(Gst.State.PLAYING)

        if window_proc:
            try: window_proc.terminate()
            except: pass

        loop = GLib.MainLoop()
        loop.run()
    except Exception as e:
        print(f"\nPipeline Error: {e}")
    finally:
        if pipeline: pipeline.set_state(Gst.State.NULL)

if __name__ == "__main__":
    try:
        target_ip = sys.argv[1] if len(sys.argv) > 1 else input("Enter Receiver IP: ").strip() or "127.0.0.1"

        dm = DisplayManager()
        dm.scan_displays()
        selected_display = dm.select_display_cli()

        print("\n [1/4] LAUNCHING KEEP-ALIVE WINDOW...")
        keep_alive_proc = subprocess.Popen([sys.executable, "-c", KEEP_ALIVE_SCRIPT])
        input(" >>> Drag window to screen, then PRESS ENTER <<< ")

        client = PortalClient()
        node_id = client.run()

        run_pipeline(node_id, target_ip, dm, keep_alive_proc)

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if 'keep_alive_proc' in locals():
            try: keep_alive_proc.terminate()
            except: pass
