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

# --- KEEP-ALIVE WINDOW (RUNS AS SEPARATE PROCESS) ---
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

        info = Gtk.Label(label="This window primes the connection.\nIt will close automatically when the stream starts.")
        box.pack_start(info, True, True, 0)

        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(400, 40)
        self.drawing_area.connect("draw", self.on_draw)
        box.pack_start(self.drawing_area, True, True, 0)

        GLib.timeout_add(16, self.tick) # 60 FPS tick

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

# --- INPUT INJECTION CLASS ---
class InputServer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 5001))
        self.last_log = 0

        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        self.ui = UInput(cap, name="Python-Stream-Mouse")
        print(" [INPUT] Virtual Mouse Created.")

    def run(self):
        print(" [INPUT] Listening for events on Port 5001...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                now = time.time()
                if now - self.last_log > 5:
                    print(f" [INPUT] Receiving Events from {addr[0]}...")
                    self.last_log = now

                abs_x = int(msg['x'] * 65535)
                abs_y = int(msg['y'] * 65535)
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
            except Exception as e:
                pass

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

        print("[3/4] Select Screen (Choose the Virtual Display!)...")
        self.call_request("SelectSources", [session_handle, {"types": GLib.Variant("u", 1), "cursor_mode": GLib.Variant("u", 2)}], "oa{sv}")

        print("[4/4] Starting Stream...")
        results = self.call_request("Start", [session_handle, "", {}], "osa{sv}")
        return results['streams'][0][0]

def get_best_encoder():
    factory = Gst.ElementFactory.find
    if factory("nvh264enc"):
        # NVIDIA optimization
        return "nvh264enc preset=low-latency-hq zerolatency=true bitrate=15000 rc-mode=cbr"
    if factory("vaapih264enc"):
        # AMD/Intel optimization:
        # refs=1 (low latency)
        # max-bframes=0 (no future frame waiting)
        # bitrate=15000 (light compression load)
        return "vaapih264enc rate-control=cbr bitrate=15000 keyframe-period=60 max-bframes=0 refs=1"

    return "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30"

last_sent_time = 0
def monitor_traffic(pad, info, user_data):
    global last_sent_time
    now = time.time()
    if now - last_sent_time > 2.0:
        print(f" [VIDEO] STATUS: Active at 60 FPS. (Time: {time.strftime('%H:%M:%S')})")
        last_sent_time = now
    return Gst.PadProbeReturn.OK

def run_pipeline(node_id, receiver_ip, window_proc=None):
    Gst.init(None)

    input_server = InputServer()
    input_server.start()

    encoder_str = get_best_encoder()

    # OPTIMIZED PIPELINE:
    # 1. leaky=upstream: Drops OLD frames if network lags (reduces latency)
    # 2. skip-to-first=true: Helps videorate sync faster
    # 3. NV12: The required color format for hardware encoding
    pipeline_str = (
        f"pipewiresrc path={node_id} do-timestamp=true ! "
        "queue max-size-buffers=3 leaky=upstream ! "
        "videoconvert ! "
        "videorate max-rate=60 skip-to-first=true ! "
        "video/x-raw,format=NV12,framerate=60/1 ! "
        f"{encoder_str} ! "
        "rtph264pay config-interval=1 pt=96 ! "
        f"udpsink name=sink host={receiver_ip} port=5000 sync=false"
    )

    print(f"\nRunning Optimized Pipeline:\n{pipeline_str}")

    pipeline = None
    try:
        pipeline = Gst.parse_launch(pipeline_str)

        sink = pipeline.get_by_name("sink")
        sink_pad = sink.get_static_pad("sink")
        sink_pad.add_probe(Gst.PadProbeType.BUFFER, monitor_traffic, None)

        pipeline.set_state(Gst.State.PLAYING)

        # --- AUTO CLOSE WINDOW ---
        if window_proc:
            print(" [INFO] Stream started successfully. Closing helper window...")
            try:
                window_proc.terminate()
            except:
                pass

        loop = GLib.MainLoop()
        loop.run()
    except Exception as e:
        print(f"\nPipeline Error: {e}")
    finally:
        if pipeline:
            pipeline.set_state(Gst.State.NULL)

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            target_ip = sys.argv[1]
        else:
            print("No IP provided as argument.")
            target_ip = input("Enter Receiver IP (Steam Deck IP): ").strip() or "127.0.0.1"

        # --- STEP 1: LAUNCH KEEP-ALIVE WINDOW ---
        print("\n" + "="*60)
        print(" [1/4] LAUNCHING KEEP-ALIVE WINDOW...")
        print(" A window has opened. DRAG IT TO THE VIRTUAL DISPLAY.")
        print("="*60 + "\n")

        keep_alive_proc = subprocess.Popen([sys.executable, "-c", KEEP_ALIVE_SCRIPT])

        input(" >>> Drag window to Virtual Screen, then PRESS ENTER here <<< ")

        # --- STEP 2: START STREAMING ---
        client = PortalClient()
        node_id = client.run()

        # Pass the process handle so it can be closed once the stream starts
        run_pipeline(node_id, target_ip, keep_alive_proc)

    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'keep_alive_proc' in locals():
            try:
                keep_alive_proc.terminate()
            except:
                pass
