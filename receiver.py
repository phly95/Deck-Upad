import sys
import os
import subprocess
import time

# --- CONFIGURATION ---
CONTAINER_NAME = "stream-receiver"
BASE_IMAGE = "registry.fedoraproject.org/fedora:39"
CUSTOM_IMAGE = "localhost/stream-receiver-v4"
SCRIPT_PATH = os.path.abspath(__file__)

PACKAGES = [
    "python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
    "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
    "gstreamer1-libav", "mesa-dri-drivers", "libwayland-client"
]

def run_host_logic():
    print(f"--- Stream Receiver Launcher ---")

    # 1. Check Image
    has_image = subprocess.run(["podman", "image", "exists", CUSTOM_IMAGE], capture_output=True).returncode == 0

    if not has_image:
        print(f"      Building local image '{CUSTOM_IMAGE}'...")
        subprocess.run(["podman", "pull", BASE_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], stderr=subprocess.DEVNULL)
        subprocess.run(["podman", "run", "-d", "--name", f"{CONTAINER_NAME}-builder", BASE_IMAGE, "sleep", "infinity"], check=True)

        # Enable RPM Fusion
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "install", "-y", "--nogpgcheck",
                        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"], check=True)

        # Install Packages
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "makecache"], check=True)
        install_cmd = f"dnf install -y {' '.join(PACKAGES)}"
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "bash", "-c", install_cmd], check=True)

        # Commit
        subprocess.run(["podman", "commit", f"{CONTAINER_NAME}-builder", CUSTOM_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], check=True)
        print("      Build Complete.")

    # 2. XHOST
    try: subprocess.run(["xhost", "+local:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    # 3. Launch
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    cmd = [
        "podman", "run", "--rm", "-it",
        "--name", CONTAINER_NAME,
        "--pull=never",
        "--net=host", "--userns=keep-id", "--ipc=host", "--security-opt", "label=disable",
        "--device", "/dev/dri",
        "-e", f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
        "-e", f"WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY', 'wayland-0')}",
        "-e", f"XDG_RUNTIME_DIR={runtime_dir}",
        "-e", "GDK_BACKEND=wayland,x11",
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
        from gi.repository import Gst, Gtk, Gdk, GLib
    except ImportError: sys.exit(1)

    HOST_IP = "127.0.0.1"
    INPUT_PORT = 5001
    VIDEO_PORT = 5000
    CONTROL_PORT = 5002

    class ReceiverWindow(Gtk.Window):
        def __init__(self):
            super().__init__(title="Stream Receiver")
            self.set_default_size(1280, 720)

            self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_addr = (HOST_IP, INPUT_PORT)

            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.control_sock.bind(("0.0.0.0", CONTROL_PORT))

            # Default Source Resolution (Assume 16:9 until told otherwise)
            self.source_w = 1920
            self.source_h = 1080

            self.listen_thread = threading.Thread(target=self.listen_control, daemon=True)
            self.listen_thread.start()

            Gst.init(None)
            self.pipeline = Gst.parse_launch(
                f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
                "rtpjitterbuffer latency=0 ! rtph264depay ! avdec_h264 ! videoconvert ! "
                "queue ! gtksink name=sink sync=false"
            )

            sink = self.pipeline.get_by_name("sink")
            self.video_widget = sink.get_property("widget")
            self.add(self.video_widget)

            self.video_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK |
                                         Gdk.EventMask.BUTTON_PRESS_MASK |
                                         Gdk.EventMask.BUTTON_RELEASE_MASK)
            self.video_widget.connect("motion-notify-event", self.on_motion)
            self.video_widget.connect("button-press-event", self.on_button)
            self.video_widget.connect("button-release-event", self.on_button)

            self.pipeline.set_state(Gst.State.PLAYING)
            self.last_move = 0

        def listen_control(self):
            while True:
                try:
                    data = self.control_sock.recv(1024)
                    msg = json.loads(data.decode())
                    if msg.get("cmd") == "resize":
                        GLib.idle_add(self.update_resolution, msg['w'], msg['h'])
                except Exception: pass

        def update_resolution(self, w, h):
            self.source_w = w
            self.source_h = h
            print(f" [DISPLAY] Source Resolution Updated: {w}x{h}")

            # Resize Window Logic
            screen = Gdk.Screen.get_default()
            max_w = screen.get_width() * 0.9
            max_h = screen.get_height() * 0.9

            aspect = w / h
            new_w = w
            new_h = h

            # Fit to screen if too big
            if new_w > max_w:
                new_w = max_w
                new_h = new_w / aspect
            if new_h > max_h:
                new_h = max_h
                new_w = new_h * aspect

            self.resize(int(new_w), int(new_h))

        def map_input_to_video(self, widget, x_in, y_in):
            """
            Compensates for black bars (Letterboxing/Pillarboxing).
            Converts raw Widget XY to Video Percentage XY (0.0 - 1.0).
            """
            # 1. Get current Widget Dimensions
            widget_w = widget.get_allocated_width()
            widget_h = widget.get_allocated_height()

            # 2. Calculate Aspect Ratios
            widget_aspect = widget_w / widget_h
            source_aspect = self.source_w / self.source_h

            # 3. Determine 'Drawn' Video Dimensions inside the widget
            # GStreamer 'videoconvert' typically fits image to center
            if widget_aspect > source_aspect:
                # Widget is wider than video -> PILLARBOX (Black bars Left/Right)
                draw_h = widget_h
                draw_w = widget_h * source_aspect
                offset_x = (widget_w - draw_w) / 2
                offset_y = 0
            else:
                # Widget is taller than video -> LETTERBOX (Black bars Top/Bottom)
                draw_w = widget_w
                draw_h = widget_w / source_aspect
                offset_x = 0
                offset_y = (widget_h - draw_h) / 2

            # 4. Normalize Input
            # Subtract the offset (start of video)
            rel_x = x_in - offset_x
            rel_y = y_in - offset_y

            # Divide by the DRAWN size, not the full widget size
            norm_x = rel_x / draw_w
            norm_y = rel_y / draw_h

            # 5. Clamp values to strict 0.0 - 1.0
            # (Ignores clicks in the black bars)
            norm_x = max(0.0, min(1.0, norm_x))
            norm_y = max(0.0, min(1.0, norm_y))

            return norm_x, norm_y

        def send_input(self, data):
            try: self.input_sock.sendto(json.dumps(data).encode(), self.server_addr)
            except: pass

        def on_motion(self, widget, event):
            if time.time() - self.last_move < 0.016: return True
            self.last_move = time.time()

            nx, ny = self.map_input_to_video(widget, event.x, event.y)
            self.send_input({"type": "move", "x": nx, "y": ny})
            return True

        def on_button(self, widget, event):
            nx, ny = self.map_input_to_video(widget, event.x, event.y)
            t = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"
            self.send_input({"type": t, "x": nx, "y": ny, "btn": event.button})
            return True

        def close(self, *args):
            self.pipeline.set_state(Gst.State.NULL)
            Gtk.main_quit()

    win = ReceiverWindow()
    win.connect("destroy", win.close)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    if "--worker" in sys.argv: run_gui_worker()
    else: run_host_logic()
