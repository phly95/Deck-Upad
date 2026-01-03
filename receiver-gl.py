import sys
import os
import subprocess
import time
import argparse

# --- CONFIGURATION ---
CONTAINER_NAME = "stream-receiver"
BASE_IMAGE = "registry.fedoraproject.org/fedora:39"
CUSTOM_IMAGE = "localhost/stream-receiver-final"
SCRIPT_PATH = os.path.abspath(__file__)

# Dependencies for HW Acceleration + OpenGL
PACKAGES = [
    "python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
    "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
    "gstreamer1-plugins-bad-free", "gstreamer1-plugins-bad-free-gtk",
    "gstreamer1-vaapi", "gstreamer1-libav",
    "mesa-dri-drivers", "libwayland-client"
]

def run_host_logic():
    print(f"--- Stream Receiver Launcher (4K Low-Latency Tuned) ---")

    parser = argparse.ArgumentParser()
    parser.add_argument("sender_ip", nargs="?", help="IP of the Sender")
    args, unknown = parser.parse_known_args()

    sender_ip = args.sender_ip
    if not sender_ip:
        sender_ip = input("Enter Sender IP: ").strip()
        if not sender_ip: sys.exit(1)

    use_fullscreen = "0"
    if input("Run in Fullscreen? (y/N): ").strip().lower() in ["y", "yes"]:
        use_fullscreen = "1"

    # --- CONTAINER BUILD ---
    print("[1/4] Verifying Container...")
    has_image = subprocess.run(["podman", "image", "exists", CUSTOM_IMAGE], capture_output=True).returncode == 0

    if not has_image:
        print(f"      Building '{CUSTOM_IMAGE}'...")
        subprocess.run(["podman", "pull", BASE_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], stderr=subprocess.DEVNULL)
        subprocess.run(["podman", "run", "-d", "--name", f"{CONTAINER_NAME}-builder", BASE_IMAGE, "sleep", "infinity"], check=True)

        # RPM Fusion for potential NVIDIA drivers (optional but good)
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "install", "-y", "--nogpgcheck",
                        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"], check=True)

        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "makecache"], check=True)
        install_cmd = f"dnf install -y {' '.join(PACKAGES)}"
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "bash", "-c", install_cmd], check=True)
        subprocess.run(["podman", "commit", f"{CONTAINER_NAME}-builder", CUSTOM_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], check=True)

    try: subprocess.run(["xhost", "+local:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    print(f"[2/4] Launching Receiver...")
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")

    cmd = [
        "podman", "run", "--rm", "-it",
        "--name", CONTAINER_NAME,
        "--pull=never",
        "-p", "5000:5000/udp",
        "-p", "5002:5002/udp",
        "--userns=keep-id", "--ipc=host", "--security-opt", "label=disable",
        "--device", "/dev/dri", # GPU Access
        "-e", f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
        "-e", f"WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY', 'wayland-0')}",
        "-e", f"XDG_RUNTIME_DIR={runtime_dir}",
        "-e", "GDK_BACKEND=wayland,x11",
        "-e", f"SENDER_IP={sender_ip}",
        "-e", f"USE_FULLSCREEN={use_fullscreen}",
        "-v", "/tmp/.X11-unix:/tmp/.X11-unix:ro",
        "-v", f"{runtime_dir}:{runtime_dir}:rw",
        "-v", f"{SCRIPT_PATH}:/app/main.py:Z",
        CUSTOM_IMAGE, "python3", "/app/main.py", "--worker"
    ]
    try: subprocess.run(cmd)
    except KeyboardInterrupt: subprocess.run(["podman", "stop", "-t", "0", CONTAINER_NAME])

# ==========================================
#  GUI WORKER
# ==========================================
def run_gui_worker():
    import socket
    import json
    import threading
    import gi
    try:
        gi.require_version('Gst', '1.0')
        gi.require_version('Gtk', '3.0')
        gi.require_version('Gio', '2.0')
        from gi.repository import Gst, Gtk, Gdk, GLib, Gio
    except ImportError: sys.exit(1)

    HOST_IP = os.environ.get("SENDER_IP", "127.0.0.1")
    IS_FULLSCREEN = os.environ.get("USE_FULLSCREEN") == "1"
    INPUT_PORT = 5001
    VIDEO_PORT = 5000
    CONTROL_PORT = 5002

    # --- UTILS ---
    class ScreenSaverInhibitor:
        def __init__(self):
            self.cookie = None
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        def inhibit(self):
            try:
                result = self.bus.call_sync(
                    "org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver", "Inhibit",
                    GLib.Variant("(ss)", ("StreamReceiver", "Streaming")), None, Gio.DBusCallFlags.NONE, -1, None
                )
                self.cookie = result[0]
            except: pass
        def uninhibit(self):
            if self.cookie:
                try:
                    self.bus.call_sync(
                        "org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver", "UnInhibit",
                        GLib.Variant("(u)", (self.cookie,)), None, Gio.DBusCallFlags.NONE, -1, None
                    )
                except: pass

    # --- WINDOW ---
    class ReceiverWindow(Gtk.Window):
        def __init__(self):
            super().__init__(title="Stream Receiver")
            self.set_default_size(1280, 720)
            self.inhibitor = ScreenSaverInhibitor()
            self.inhibitor.inhibit()

            if IS_FULLSCREEN: self.fullscreen()

            self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_addr = (HOST_IP, INPUT_PORT)
            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.control_sock.bind(("0.0.0.0", CONTROL_PORT))

            self.source_w = 1920
            self.source_h = 1080
            self.last_move = 0
            self.move_interval = 1.0/240.0

            # Start Control Listener
            t = threading.Thread(target=self.listen_control, daemon=True)
            t.start()

            # Initialize GStreamer
            Gst.init(None)
            self.pipeline = self.build_pipeline(VIDEO_PORT)

            # Attach Widget
            sink = self.pipeline.get_by_name("sink")
            if not sink: sink = self.pipeline.get_by_name("glsink")

            self.video_widget = sink.get_property("widget")
            self.add(self.video_widget)

            # Events
            self.video_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK | Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON_RELEASE_MASK)
            self.video_widget.connect("motion-notify-event", self.on_motion)
            self.video_widget.connect("button-press-event", self.on_button)
            self.video_widget.connect("button-release-event", self.on_button)
            self.connect("key-press-event", self.on_key_press)

            self.pipeline.set_state(Gst.State.PLAYING)

        def build_pipeline(self, port):
            # 1. TUNED UDP SOURCE (buffer-size=10MB for 4K)
            src = (
                f"udpsrc port={port} buffer-size=10000000 "
                "caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
                "rtpjitterbuffer latency=0 mode=slave do-lost=true ! "
                "rtph264depay ! h264parse ! "
            )

            # 2. DROP QUEUE (The fix for 'Slow Motion')
            # 'leaky=downstream' drops the oldest frame if the decoder is busy.
            queue = "queue max-size-buffers=1 leaky=downstream ! "

            # 3. DECODER (Hardware Auto-detect)
            f = Gst.ElementFactory.find
            dec = "avdec_h264" # fallback
            if f("vaapih264dec"): dec = "vaapih264dec ! vaapipostproc"
            elif f("nvh264dec"): dec = "nvh264dec ! cudaupload ! cudaconvert ! cudadownload"

            # 4. SINK (OpenGL)
            sink = "videoconvert ! gtksink name=sink sync=false"
            if f("gtkglsink"):
                sink = "glsinkbin name=glsink sink=gtkglsink"

            full = f"{src} {queue} {dec} ! {sink}"
            print(f" [PIPELINE] {full}")
            return Gst.parse_launch(full)

        def listen_control(self):
            while True:
                try:
                    data = self.control_sock.recv(1024)
                    msg = json.loads(data.decode())
                    if msg.get("cmd") == "resize":
                        GLib.idle_add(self.update_resolution, msg['w'], msg['h'])
                except: pass

        def update_resolution(self, w, h):
            self.source_w, self.source_h = w, h
            if not IS_FULLSCREEN:
                # Logic to resize window safely
                s = Gdk.Screen.get_default()
                mw, mh = s.get_width()*0.9, s.get_height()*0.9
                nw, nh = w, h
                aspect = w/h
                if nw > mw: nw = mw; nh = nw/aspect
                if nh > mh: nh = mh; nw = nh*aspect
                self.resize(int(nw), int(nh))

        def map_input(self, w, x, y):
            ww, wh = w.get_allocated_width(), w.get_allocated_height()
            if ww == 0 or wh == 0: return 0.0, 0.0

            wa = ww / wh
            sa = self.source_w / self.source_h

            if wa > sa: # Window wider than source
                dh = wh
                dw = wh * sa
                ox = (ww - dw) / 2
                oy = 0
            else:
                dw = ww
                dh = ww / sa
                ox = 0
                oy = (wh - dh) / 2

            return max(0.0, min(1.0, (x-ox)/dw)), max(0.0, min(1.0, (y-oy)/dh))

        def on_motion(self, w, e):
            if time.time() - self.last_move < self.move_interval: return True
            self.last_move = time.time()
            nx, ny = self.map_input(w, e.x, e.y)
            try: self.input_sock.sendto(json.dumps({"type":"move","x":nx,"y":ny}).encode(), self.server_addr)
            except: pass
            return True

        def on_button(self, w, e):
            nx, ny = self.map_input(w, e.x, e.y)
            t = "press" if e.type == Gdk.EventType.BUTTON_PRESS else "release"
            try: self.input_sock.sendto(json.dumps({"type":t,"x":nx,"y":ny,"btn":e.button}).encode(), self.server_addr)
            except: pass
            return True

        def on_key_press(self, w, e):
            if e.keyval == Gdk.KEY_Escape: self.close()

        def close(self, *args):
            self.inhibitor.uninhibit()
            self.pipeline.set_state(Gst.State.NULL)
            Gtk.main_quit()

    win = ReceiverWindow()
    win.connect("destroy", win.close)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    if "--worker" in sys.argv: run_gui_worker()
    else: run_host_logic()
