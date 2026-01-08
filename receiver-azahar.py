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

PACKAGES = [
    "python3-gobject", "gtk3", "gstreamer1", "gstreamer1-plugins-base",
    "gstreamer1-plugins-good", "gstreamer1-plugins-good-gtk",
    "gstreamer1-libav", "gstreamer1-plugins-bad-free",
    "mesa-dri-drivers", "libwayland-client"
]

def run_host_logic():
    print(f"--- Stream Receiver Launcher ---")

    parser = argparse.ArgumentParser(description="Stream Receiver Host")
    parser.add_argument("sender_ip", nargs="?", help="IP address of the sender (Steam Deck)")
    args, unknown = parser.parse_known_args()

    sender_ip = args.sender_ip
    if not sender_ip:
        sender_ip = input("Enter Sender (Steam Deck) IP: ").strip()
        if not sender_ip:
            print("Error: IP address is required.")
            sys.exit(1)

    use_fullscreen = "0"
    fs_choice = input("Run in Fullscreen? (y/N): ").strip().lower()
    if fs_choice in ["y", "yes"]:
        use_fullscreen = "1"

    print("[1/4] Checking Container Image...")
    has_image = subprocess.run(["podman", "image", "exists", CUSTOM_IMAGE], capture_output=True).returncode == 0

    if not has_image:
        print(f"      Building local image '{CUSTOM_IMAGE}'...")
        subprocess.run(["podman", "pull", BASE_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], stderr=subprocess.DEVNULL)
        subprocess.run(["podman", "run", "-d", "--name", f"{CONTAINER_NAME}-builder", BASE_IMAGE, "sleep", "infinity"], check=True)
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "install", "-y", "--nogpgcheck",
                        "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"], check=True)
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "dnf", "makecache"], check=True)
        install_cmd = f"dnf install -y {' '.join(PACKAGES)}"
        subprocess.run(["podman", "exec", f"{CONTAINER_NAME}-builder", "bash", "-c", install_cmd], check=True)
        subprocess.run(["podman", "commit", f"{CONTAINER_NAME}-builder", CUSTOM_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], check=True)
        print("      Build Complete.")

    try: subprocess.run(["xhost", "+local:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    print(f"[2/4] Launching Receiver (Target: {sender_ip})...")
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")

    # NOTE: Using --net=host is critical for low latency and local testing
    cmd = [
        "podman", "run", "--rm", "-it",
        "--name", CONTAINER_NAME,
        "--pull=never",
        "--net=host", # <--- FIXED: Shares network stack (allows 127.0.0.1 communication)
        "--userns=keep-id", "--ipc=host", "--security-opt", "label=disable",
        "--device", "/dev/dri",
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

    HOST_IP = os.environ.get("SENDER_IP", "127.0.0.1")
    IS_FULLSCREEN = os.environ.get("USE_FULLSCREEN") == "1"
    INPUT_PORT = 5001
    VIDEO_PORT = 5000
    CONTROL_PORT = 5002

    class ReceiverWindow(Gtk.Window):
        def __init__(self):
            super().__init__(title="Stream Receiver")
            self.set_default_size(1280, 720)
            if IS_FULLSCREEN: self.fullscreen()

            self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_addr = (HOST_IP, INPUT_PORT)

            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Bind to specific IP or all depending on needs
            try: self.control_sock.bind(("0.0.0.0", CONTROL_PORT))
            except: pass # Might fail if port reused in --net=host

            self.source_w = 320
            self.source_h = 240

            self.listen_thread = threading.Thread(target=self.listen_control, daemon=True)
            self.listen_thread.start()

            Gst.init(None)
            self.pipeline = Gst.parse_launch(
                f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H265, payload=96\" ! "
                "rtpjitterbuffer latency=0 ! rtph265depay ! avdec_h265 ! videoconvert ! "
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
            self.connect("key-press-event", self.on_key_press)

            self.pipeline.set_state(Gst.State.PLAYING)
            self.last_move = 0
            self.move_interval = 1.0 / 120.0

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
            if not IS_FULLSCREEN:
                self.resize(w, h)

        def map_input(self, widget, x, y):
            win_w = widget.get_allocated_width()
            win_h = widget.get_allocated_height()

            if win_w == 0 or win_h == 0 or self.source_w == 0: return None

            win_aspect = win_w / win_h
            src_aspect = self.source_w / self.source_h

            if win_aspect > src_aspect:
                draw_h = win_h
                draw_w = win_h * src_aspect
                offset_x = (win_w - draw_w) / 2
                offset_y = 0
            else:
                draw_w = win_w
                draw_h = win_w / src_aspect
                offset_x = 0
                offset_y = (win_h - draw_h) / 2

            if x < offset_x or x > (offset_x + draw_w): return None
            if y < offset_y or y > (offset_y + draw_h): return None

            norm_x = (x - offset_x) / draw_w
            norm_y = (y - offset_y) / draw_h

            return max(0.0, min(1.0, norm_x)), max(0.0, min(1.0, norm_y))

        def send_input(self, data):
            try: self.input_sock.sendto(json.dumps(data).encode(), self.server_addr)
            except: pass

        def on_motion(self, widget, event):
            if time.time() - self.last_move < self.move_interval: return True
            self.last_move = time.time()
            res = self.map_input(widget, event.x, event.y)
            if res:
                self.send_input({"type": "move", "x": res[0], "y": res[1]})
            return True

        def on_button(self, widget, event):
            res = self.map_input(widget, event.x, event.y)
            if res:
                t = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"
                self.send_input({"type": t, "x": res[0], "y": res[1], "btn": event.button})
            return True

        def on_key_press(self, widget, event):
            if event.keyval == Gdk.KEY_Escape: self.close()

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
