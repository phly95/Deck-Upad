import sys
import os
import subprocess
import time

# --- CONFIGURATION ---
CONTAINER_NAME = "stream-receiver"
BASE_IMAGE = "fedora:39"
# CHANGED: Bumped to v3 to ensure clean build
CUSTOM_IMAGE = "stream-receiver-v3"
SCRIPT_PATH = os.path.abspath(__file__)

# Dependencies to install inside the container
PACKAGES = [
    "python3-gobject",
    "gtk3",
    "gstreamer1",
    "gstreamer1-plugins-base",
    "gstreamer1-plugins-good",
    "gstreamer1-plugins-good-gtk",
    "gstreamer1-libav",             # Requires RPM Fusion (handled below)
    "mesa-dri-drivers",
    "libwayland-client"             # Critical for Wayland
    # Removed "xorg-x11-server-utils" as it caused the build error
]

def run_host_logic():
    print(f"--- Stream Receiver Launcher ---")

    # 1. Check Image
    print("[1/4] Checking Container Image...")
    has_image = subprocess.run(
        ["podman", "image", "exists", CUSTOM_IMAGE],
        capture_output=True
    ).returncode == 0

    if not has_image:
        print(f"      Image '{CUSTOM_IMAGE}' not found. Building...")
        print("      (This includes installing RPM Fusion for H.264 codecs)")

        # Pull base
        subprocess.run(["podman", "pull", BASE_IMAGE], check=True)

        # Cleanup builder if stuck
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], stderr=subprocess.DEVNULL)

        # Start Builder
        subprocess.run([
            "podman", "run", "-d", "--name", f"{CONTAINER_NAME}-builder",
            BASE_IMAGE, "sleep", "infinity"
        ], check=True)

        # INSTALL STEPS
        print("      Enabling RPM Fusion (Free)...")
        # 1. Install RPM Fusion Free
        subprocess.run([
            "podman", "exec", f"{CONTAINER_NAME}-builder",
            "dnf", "install", "-y", "--nogpgcheck",
            "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-39.noarch.rpm"
        ], check=True)

        # 2. Update metadata
        subprocess.run([
            "podman", "exec", f"{CONTAINER_NAME}-builder",
            "dnf", "makecache"
        ], check=True)

        # 3. Install Packages
        print("      Installing GStreamer & Codecs...")
        install_cmd = f"dnf install -y {' '.join(PACKAGES)}"
        subprocess.run([
            "podman", "exec", f"{CONTAINER_NAME}-builder",
            "bash", "-c", install_cmd
        ], check=True)

        print(f"      Saving to '{CUSTOM_IMAGE}'...")
        subprocess.run(["podman", "commit", f"{CONTAINER_NAME}-builder", CUSTOM_IMAGE], check=True)
        subprocess.run(["podman", "rm", "-f", f"{CONTAINER_NAME}-builder"], check=True)
        print("      Build Complete.")
    else:
        print("      Image ready.")

    # 2. XHOST (Fallback)
    print("[2/4] Granting Display Access...")
    try:
        subprocess.run(["xhost", "+local:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

    # 3. Detect Sockets
    print("[3/4] Configuring Display Pass-through...")
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    wayland_display = os.environ.get("WAYLAND_DISPLAY", "wayland-0")
    x11_display = os.environ.get("DISPLAY", ":0")

    print(f"      Host: Wayland={wayland_display}, X11={x11_display}")

    # 4. Launch
    print("[4/4] Launching Receiver...")

    cmd = [
        "podman", "run", "--rm", "-it",
        "--name", CONTAINER_NAME,
        "--net=host",
        "--userns=keep-id",
        "--ipc=host",
        "--security-opt", "label=disable",
        "--device", "/dev/dri",

        # Environment
        "-e", f"DISPLAY={x11_display}",
        "-e", f"WAYLAND_DISPLAY={wayland_display}",
        "-e", f"XDG_RUNTIME_DIR={runtime_dir}",
        "-e", "GDK_BACKEND=wayland,x11",
        "-e", "XDG_CONFIG_HOME=/tmp",

        # Mounts
        "-v", "/tmp/.X11-unix:/tmp/.X11-unix:ro",
        "-v", f"{runtime_dir}:{runtime_dir}:rw",
        "-v", f"{SCRIPT_PATH}:/app/main.py:Z",

        CUSTOM_IMAGE,
        "python3", "/app/main.py", "--worker"
    ]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nStopping...")
        subprocess.run(["podman", "stop", "-t", "0", CONTAINER_NAME])

# ==========================================
#  GUI WORKER
# ==========================================

def run_gui_worker():
    import socket
    import json
    import gi

    try:
        gi.require_version('Gst', '1.0')
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gst, Gtk, Gdk
    except ImportError as e:
        print(f"Import Error: {e}")
        sys.exit(1)

    # CONFIG
    HOST_IP = "127.0.0.1"
    INPUT_PORT = 5001
    VIDEO_PORT = 5000

    class ReceiverWindow(Gtk.Window):
        def __init__(self):
            super().__init__(title="Stream Receiver")
            self.set_default_size(1280, 720)

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_address = (HOST_IP, INPUT_PORT)

            self.last_move_time = 0
            self.move_interval = 0.016

            Gst.init(None)

            # Pipeline
            self.pipeline = Gst.parse_launch(
                f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
                "rtpjitterbuffer latency=0 ! rtph264depay ! avdec_h264 ! videoconvert ! "
                "queue ! gtksink name=sink sync=false"
            )

            sink = self.pipeline.get_by_name("sink")
            video_widget = sink.get_property("widget")
            self.add(video_widget)

            video_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK |
                                    Gdk.EventMask.BUTTON_PRESS_MASK |
                                    Gdk.EventMask.BUTTON_RELEASE_MASK)

            video_widget.connect("motion-notify-event", self.on_motion)
            video_widget.connect("button-press-event", self.on_button)
            video_widget.connect("button-release-event", self.on_button)

            self.pipeline.set_state(Gst.State.PLAYING)

        def send_input(self, data):
            try:
                self.sock.sendto(json.dumps(data).encode(), self.server_address)
            except Exception: pass

        def on_motion(self, widget, event):
            current_time = time.time()
            if current_time - self.last_move_time < self.move_interval:
                return True
            self.last_move_time = current_time
            width = self.get_allocated_width()
            height = self.get_allocated_height()
            data = {"type": "move", "x": event.x / width, "y": event.y / height}
            self.send_input(data)
            return True

        def on_button(self, widget, event):
            width = self.get_allocated_width()
            height = self.get_allocated_height()
            etype = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"
            data = {"type": etype, "x": event.x / width, "y": event.y / height, "btn": event.button}
            self.send_input(data)
            return True

        def close(self, *args):
            self.pipeline.set_state(Gst.State.NULL)
            Gtk.main_quit()

    try:
        win = ReceiverWindow()
        win.connect("destroy", win.close)
        win.show_all()
        Gtk.main()
    except RuntimeError as e:
        print(f"\nFATAL GTK ERROR: {e}")

if __name__ == "__main__":
    if "--worker" in sys.argv:
        run_gui_worker()
    else:
        run_host_logic()
