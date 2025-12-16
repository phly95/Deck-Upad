import sys
import os
import subprocess
import time
import argparse

# --- CONFIGURATION ---
CONTAINER_NAME = "stream-receiver"
# Use specific registry to ensure safe pull
BASE_IMAGE = "registry.fedoraproject.org/fedora:39"
CUSTOM_IMAGE = "localhost/stream-receiver-final"
SCRIPT_PATH = os.path.abspath(__file__)

PACKAGES = [
    "python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
    "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
    "gstreamer1-libav", "mesa-dri-drivers", "libwayland-client"
]

def run_host_logic():
    print(f"--- Stream Receiver Launcher ---")

    # --- INPUT HANDLING (CLI ARG or PROMPT) ---
    parser = argparse.ArgumentParser(description="Stream Receiver Host")
    parser.add_argument("sender_ip", nargs="?", help="IP address of the sender (Steam Deck)")
    args, unknown = parser.parse_known_args()

    sender_ip = args.sender_ip
    if not sender_ip:
        # Ask user if not provided in CLI (No default suggestion)
        sender_ip = input("Enter Sender (Steam Deck) IP: ").strip()
        if not sender_ip:
            print("Error: IP address is required.")
            sys.exit(1)

    # 2. Get Fullscreen Preference
    use_fullscreen = "0"
    fs_choice = input("Run in Fullscreen? (y/N): ").strip().lower()
    if fs_choice in ["y", "yes"]:
        use_fullscreen = "1"

    # --- BUILD LOGIC ---
    print("[1/4] Checking Container Image...")
    has_image = subprocess.run(["podman", "image", "exists", CUSTOM_IMAGE], capture_output=True).returncode == 0

    if not has_image:
        print(f"      Building local image '{CUSTOM_IMAGE}'...")
        subprocess.run(["podman", "pull", BASE_IMAGE], check=True)
        # Cleanup old builder
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], stderr=subprocess.DEVNULL)

        # Start builder
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

    # 2. XHOST (Allow display access)
    try: subprocess.run(["xhost", "+local:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    # 3. Launch
    print(f"[2/4] Launching Receiver (Target: {sender_ip})...")
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")

    cmd = [
        "podman", "run", "--rm", "-it",
        "--name", CONTAINER_NAME,
        "--pull=never",
        "--net=host", "--userns=keep-id", "--ipc=host", "--security-opt", "label=disable",
        "--device", "/dev/dri",

        # Pass Host Config to Container
        "-e", f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
        "-e", f"WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY', 'wayland-0')}",
        "-e", f"XDG_RUNTIME_DIR={runtime_dir}",
        "-e", "GDK_BACKEND=wayland,x11",
        "-e", f"SENDER_IP={sender_ip}",        # <--- PASSED HERE
        "-e", f"USE_FULLSCREEN={use_fullscreen}", # <--- PASSED HERE

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
        gi.require_version('Gio', '2.0') # For DBus/Screensaver inhibit
        from gi.repository import Gst, Gtk, Gdk, GLib, Gio
    except ImportError: sys.exit(1)

    # READ CONFIG FROM ENVIRONMENT
    HOST_IP = os.environ.get("SENDER_IP", "127.0.0.1")
    IS_FULLSCREEN = os.environ.get("USE_FULLSCREEN") == "1"

    INPUT_PORT = 5001
    VIDEO_PORT = 5000
    CONTROL_PORT = 5002

    class ScreenSaverInhibitor:
        """Prevents the screen from sleeping while streaming."""
        def __init__(self):
            self.cookie = None
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

        def inhibit(self):
            try:
                # Call org.freedesktop.ScreenSaver.Inhibit
                result = self.bus.call_sync(
                    "org.freedesktop.ScreenSaver",
                    "/org/freedesktop/ScreenSaver",
                    "org.freedesktop.ScreenSaver",
                    "Inhibit",
                    GLib.Variant("(ss)", ("StreamReceiver", "Streaming Video")),
                    None, Gio.DBusCallFlags.NONE, -1, None
                )
                self.cookie = result[0]
                print(" [POWER] Screen Saver Inhibited (Wake Lock Active).")
            except Exception as e:
                print(f" [POWER] Failed to inhibit screensaver: {e}")

        def uninhibit(self):
            if self.cookie:
                try:
                    self.bus.call_sync(
                        "org.freedesktop.ScreenSaver",
                        "/org/freedesktop/ScreenSaver",
                        "org.freedesktop.ScreenSaver",
                        "UnInhibit",
                        GLib.Variant("(u)", (self.cookie,)),
                        None, Gio.DBusCallFlags.NONE, -1, None
                    )
                except: pass

    class ReceiverWindow(Gtk.Window):
        def __init__(self):
            super().__init__(title="Stream Receiver")
            self.set_default_size(1280, 720)

            # 1. Wake Lock
            self.inhibitor = ScreenSaverInhibitor()
            self.inhibitor.inhibit()

            # 2. Fullscreen Logic
            if IS_FULLSCREEN:
                self.fullscreen()

            self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_addr = (HOST_IP, INPUT_PORT)

            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.control_sock.bind(("0.0.0.0", CONTROL_PORT))

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

            # Key Press for Exit (Essential for Fullscreen)
            self.connect("key-press-event", self.on_key_press)

            self.pipeline.set_state(Gst.State.PLAYING)

            # UPDATED: 240Hz Input Rate
            self.last_move = 0
            self.move_interval = 1.0 / 240.0 # ~4.1 ms

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

            # Only resize if NOT in fullscreen to avoid breaking window manager state
            if not IS_FULLSCREEN:
                screen = Gdk.Screen.get_default()
                max_w = screen.get_width() * 0.9
                max_h = screen.get_height() * 0.9

                aspect = w / h
                new_w = w
                new_h = h

                if new_w > max_w:
                    new_w = max_w
                    new_h = new_w / aspect
                if new_h > max_h:
                    new_h = max_h
                    new_w = new_h * aspect
                self.resize(int(new_w), int(new_h))

        def map_input_to_video(self, widget, x_in, y_in):
            widget_w = widget.get_allocated_width()
            widget_h = widget.get_allocated_height()

            # Safety check for zero-size
            if widget_w == 0 or widget_h == 0: return 0.0, 0.0

            widget_aspect = widget_w / widget_h
            source_aspect = self.source_w / self.source_h

            if widget_aspect > source_aspect:
                draw_h = widget_h
                draw_w = widget_h * source_aspect
                offset_x = (widget_w - draw_w) / 2
                offset_y = 0
            else:
                draw_w = widget_w
                draw_h = widget_w / source_aspect
                offset_x = 0
                offset_y = (widget_h - draw_h) / 2

            rel_x = x_in - offset_x
            rel_y = y_in - offset_y

            norm_x = rel_x / draw_w
            norm_y = rel_y / draw_h

            return max(0.0, min(1.0, norm_x)), max(0.0, min(1.0, norm_y))

        def send_input(self, data):
            try: self.input_sock.sendto(json.dumps(data).encode(), self.server_addr)
            except: pass

        def on_motion(self, widget, event):
            # UPDATED: 240Hz check
            if time.time() - self.last_move < self.move_interval: return True
            self.last_move = time.time()
            nx, ny = self.map_input_to_video(widget, event.x, event.y)
            self.send_input({"type": "move", "x": nx, "y": ny})
            return True

        def on_button(self, widget, event):
            nx, ny = self.map_input_to_video(widget, event.x, event.y)
            t = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"
            self.send_input({"type": t, "x": nx, "y": ny, "btn": event.button})
            return True

        def on_key_press(self, widget, event):
            # Allow ESC to quit
            if event.keyval == Gdk.KEY_Escape:
                self.close()

        def close(self, *args):
            self.inhibitor.uninhibit() # Release wake lock
            self.pipeline.set_state(Gst.State.NULL)
            Gtk.main_quit()

    win = ReceiverWindow()
    win.connect("destroy", win.close)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    if "--worker" in sys.argv: run_gui_worker()
    else: run_host_logic()
