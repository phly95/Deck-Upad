import sys
import threading
import socket
import json
import uuid
import gi
import evdev
from evdev import UInput, ecodes, AbsInfo

gi.require_version('Gst', '1.0')
gi.require_version('Gio', '2.0')
from gi.repository import Gst, GLib, Gio

# --- INPUT INJECTION CLASS ---
class InputServer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 5001))

        # Create a Virtual Absolute Mouse
        # We use Absolute (EV_ABS) because it maps better to touchscreens/tablets
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
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                # Convert 0.0-1.0 to 0-65535
                abs_x = int(msg['x'] * 65535)
                abs_y = int(msg['y'] * 65535)

                # Sanity check
                abs_x = max(0, min(65535, abs_x))
                abs_y = max(0, min(65535, abs_y))

                if msg['type'] == 'move':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.syn()

                elif msg['type'] in ['press', 'release']:
                    # Map GDK button numbers to Linux Kernel Codes
                    btn_code = ecodes.BTN_LEFT
                    if msg['btn'] == 2: btn_code = ecodes.BTN_MIDDLE
                    if msg['btn'] == 3: btn_code = ecodes.BTN_RIGHT

                    val = 1 if msg['type'] == 'press' else 0

                    # Ensure cursor is at position before clicking
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.write(ecodes.EV_KEY, btn_code, val)
                    self.ui.syn()

            except Exception as e:
                print(f"Input Error: {e}")

# --- PORTAL & VIDEO LOGIC (Same as before) ---
class PortalClient:
    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.portal_name = "org.freedesktop.portal.Desktop"
        self.object_path = "/org/freedesktop/portal/desktop"
        self.interface = "org.freedesktop.portal.ScreenCast"
        self.main_loop = GLib.MainLoop()
        self.sender_name = self.bus.get_unique_name().replace('.', '_').replace(':', '')

    def call_request(self, method, args, signature):
        request_token = f"req_{uuid.uuid4().hex}"
        args[-1]['handle_token'] = GLib.Variant('s', request_token)
        request_path = f"/org/freedesktop/portal/desktop/request/{self.sender_name}/{request_token}"

        response_data = {}
        def on_response(conn, sender, path, iface, signal, params, data):
            if path == request_path:
                response_data['code'] = params[0]
                response_data['results'] = params[1]
                self.main_loop.quit()

        sub_id = self.bus.signal_subscribe(self.portal_name, "org.freedesktop.portal.Request", "Response", request_path, None, Gio.DBusSignalFlags.NONE, on_response, None)

        try:
            self.bus.call_sync(self.portal_name, self.object_path, self.interface, method, GLib.Variant(f"({signature})", tuple(args)), None, Gio.DBusCallFlags.NONE, -1, None)
        except Exception as e:
            self.bus.signal_unsubscribe(sub_id)
            raise e

        self.main_loop.run()
        self.bus.signal_unsubscribe(sub_id)
        if response_data.get('code') != 0: raise Exception(f"Request failed. Code: {response_data.get('code')}")
        return response_data['results']

    def run(self):
        print("[1/3] Creating Session...")
        session_token = f"sess_{uuid.uuid4().hex}"
        results = self.call_request("CreateSession", [{'session_handle_token': GLib.Variant('s', session_token)}], "a{sv}")
        session_handle = results['session_handle']

        print("[2/3] Select Screen...")
        self.call_request("SelectSources", [session_handle, {"types": GLib.Variant("u", 1), "cursor_mode": GLib.Variant("u", 2)}], "oa{sv}")

        print("[3/3] Starting Stream...")
        results = self.call_request("Start", [session_handle, "", {}], "osa{sv}")
        return results['streams'][0][0]

def run_pipeline(node_id):
    Gst.init(None)
    # Start Input Server
    input_server = InputServer()
    input_server.start()

    # Software encode pipeline (proven to work)
    pipeline_str = (
        f"pipewiresrc path={node_id} do-timestamp=true ! "
        "queue max-size-buffers=1 leaky=downstream ! "
        "videoconvert ! "
        "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30 ! "
        "rtph264pay config-interval=1 pt=96 ! "
        "udpsink host=127.0.0.1 port=5000 sync=false"
    )

    print(f"\nRunning with Input Server active...\n{pipeline_str}")
    pipeline = Gst.parse_launch(pipeline_str)
    pipeline.set_state(Gst.State.PLAYING)
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    pipeline.set_state(Gst.State.NULL)

if __name__ == "__main__":
    try:
        client = PortalClient()
        node_id = client.run()
        run_pipeline(node_id)
    except Exception as e:
        print(f"Error: {e}")
