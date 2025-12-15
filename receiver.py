#!/usr/bin/env python3
import subprocess
import sys
import os
import time

# --- CONFIGURATION ---
CONTAINER_NAME = "upad-receiver"
BASE_IMAGE = "alpine:latest"
# We can reuse v3 since the packages are correct, we are just changing the python script.
CUSTOM_IMAGE = "deck-upad-receiver-wayland-v3"
SCRIPT_PATH = "/tmp/receiver_internal.py"

# The Python Receiver Code
RECEIVER_CODE = r"""
import sys
import socket
import json
import time
import gi
import os

gi.require_version('Gst', '1.0')
gi.require_version('Gtk', '3.0')
gi.require_version('GstVideo', '1.0')

from gi.repository import Gst, Gtk, Gdk, GLib, GstVideo

INPUT_PORT = 5001
VIDEO_PORT = 5000

class ReceiverWindow(Gtk.Window):
    def __init__(self, sender_ip):
        super().__init__(title=f"Stream Receiver (Input -> {sender_ip})")
        self.set_default_size(1280, 800)
        self.fullscreen()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (sender_ip, INPUT_PORT)
        self.last_move_time = 0
        self.move_interval = 0.016

        Gst.init(None)

        # --- PIPELINE ---
        # 1. vaapih264dec: Hardware Decoder
        # 2. vaapipostproc: DOWNLOADS frame from GPU -> System Memory (Fixes Black Screen)
        # 3. videoscale: Ensures it fits the window
        # 4. videoconvert: Final safety conversion to BGRA for GTK
        pipeline_str = (
            f"udpsrc name=src port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
            "rtpjitterbuffer latency=0 ! "
            "queue max-size-buffers=1 leaky=downstream ! "
            "rtph264depay ! h264parse ! "
            "vaapih264dec ! "
            "vaapipostproc ! "
            "videoscale ! "
            "videoconvert ! video/x-raw,format=BGRA ! "
            "gtksink name=sink sync=false"
        )

        print(f"[DEBUG] Pipeline: {pipeline_str}")
        try:
            self.pipeline = Gst.parse_launch(pipeline_str)
        except Exception as e:
            print(f"\n[CRITICAL ERROR] Failed to create pipeline: {e}")
            sys.exit(1)

        # --- VIDEO WIDGET ---
        sink = self.pipeline.get_by_name("sink")
        video_widget = sink.get_property("widget")
        self.add(video_widget)

        # --- INPUTS ---
        video_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK |
                                Gdk.EventMask.BUTTON_PRESS_MASK |
                                Gdk.EventMask.BUTTON_RELEASE_MASK)
        video_widget.connect("motion-notify-event", self.on_motion)
        video_widget.connect("button-press-event", self.on_button)
        video_widget.connect("button-release-event", self.on_button)
        self.connect("key-press-event", self.on_key)

        # --- PROBE ---
        self.first_packet_received = False
        src = self.pipeline.get_by_name("src")
        src_pad = src.get_static_pad("src")
        src_pad.add_probe(Gst.PadProbeType.BUFFER, self.on_video_data, None)

        print(f"\n [VIDEO] WAITING FOR STREAM ON PORT {VIDEO_PORT}...")

        bus = self.pipeline.get_bus()
        bus.add_signal_watch()
        bus.connect("message::error", self.on_error)
        bus.connect("message::state-changed", self.on_state_change)

        self.show_all()
        self.pipeline.set_state(Gst.State.PLAYING)

    def on_video_data(self, pad, info, user_data):
        if not self.first_packet_received:
            print(" [VIDEO] CONNECTION DETECTED! First packet received.")
            self.first_packet_received = True
        return Gst.PadProbeReturn.OK

    def on_state_change(self, bus, msg):
        if msg.src == self.pipeline:
            old, new, pending = msg.parse_state_changed()
            if new == Gst.State.PLAYING:
                 print(" [GST] Pipeline is now PLAYING (Hardware Decoding Active)")

    def on_error(self, bus, msg):
        err, debug = msg.parse_error()
        print(f" [ERROR] Pipeline Error: {err} \nDebug info: {debug}")

    def send_input(self, data):
        try:
            self.sock.sendto(json.dumps(data).encode(), self.server_address)
        except Exception: pass

    def on_motion(self, widget, event):
        current_time = time.time()
        if current_time - self.last_move_time < self.move_interval: return True
        self.last_move_time = current_time
        width = self.get_allocated_width()
        height = self.get_allocated_height()
        self.send_input({"type": "move", "x": event.x / width, "y": event.y / height})
        return True

    def on_button(self, widget, event):
        width = self.get_allocated_width()
        height = self.get_allocated_height()
        etype = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"
        self.send_input({"type": etype, "x": event.x / width, "y": event.y / height, "btn": event.button})
        return True

    def on_key(self, widget, event):
        pass

    def close(self, *args):
        self.pipeline.set_state(Gst.State.NULL)
        Gtk.main_quit()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        win = ReceiverWindow(sys.argv[1])
        win.connect("destroy", win.close)
        Gtk.main()
"""

class ContainerManager:
    def __init__(self):
        self.cmd_runner = subprocess

    def run_cmd(self, cmd, check=True):
        print(f"CMD: {cmd}")
        return self.cmd_runner.run(cmd, shell=True, check=check)

    def image_exists(self, image_name):
        res = self.cmd_runner.run(f"podman images -q {image_name}", shell=True, stdout=subprocess.PIPE)
        return bool(res.stdout.strip())

    def prepare_x11(self):
        try:
            self.cmd_runner.run("xhost +local:", shell=True, check=False)
        except: pass

    def initialize_container(self):
        print("\n[1/3] Checking Container Image...")
        if self.image_exists(CUSTOM_IMAGE):
            print(f"      Image '{CUSTOM_IMAGE}' found. Skipping build.")
            return

        print(f"      Image not found. Building '{CUSTOM_IMAGE}' from {BASE_IMAGE}...")
        self.run_cmd(f"podman run -d --name {CONTAINER_NAME} {BASE_IMAGE} sleep infinity")

        pkgs = (
            "python3 py3-pip py3-gobject3 gtk+3.0 "
            "gstreamer gst-plugins-base gst-plugins-good gst-plugins-good-gtk gst-plugins-bad gst-plugins-ugly gst-libav "
            "gst-vaapi mesa-va-gallium libva-utils ttf-dejavu adwaita-icon-theme"
        )
        try:
            print("      Installing dependencies (apk)...")
            self.run_cmd(f"podman exec {CONTAINER_NAME} apk add --no-cache {pkgs}")
            print(f"      Committing to '{CUSTOM_IMAGE}'...")
            self.run_cmd(f"podman commit {CONTAINER_NAME} {CUSTOM_IMAGE}")
        finally:
            self.run_cmd(f"podman rm -f {CONTAINER_NAME}", check=False)

    def run_receiver(self, sender_ip):
        print(f"\n[2/3] Launching Receiver Container (Target: {sender_ip})...")
        self.prepare_x11()

        display = os.environ.get("DISPLAY", ":0")
        wayland_display = os.environ.get("WAYLAND_DISPLAY")
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", "/run/user/1000")

        if not wayland_display and os.path.exists(f"{xdg_runtime}/wayland-0"):
            wayland_display = "wayland-0"

        with open("receiver_internal.py", "w") as f:
            f.write(RECEIVER_CODE)

        print("[3/3] Checking GPU Status (vainfo)...")
        cmd = (
            f"podman run --rm -it "
            f"--name {CONTAINER_NAME} "
            f"--net=host "
            f"-e DISPLAY={display} "
            f"-e WAYLAND_DISPLAY={wayland_display} "
            f"-e XDG_RUNTIME_DIR={xdg_runtime} "
            f"-e LIBVA_DRIVER_NAME=radeonsi "
            f"-v /tmp/.X11-unix:/tmp/.X11-unix "
            f"-v {xdg_runtime}:{xdg_runtime} "
            f"-v $(pwd)/receiver_internal.py:{SCRIPT_PATH} "
            f"--device /dev/dri "
            f"--security-opt label=disable "
            f"{CUSTOM_IMAGE} "
            f"/bin/sh -c 'python3 {SCRIPT_PATH} {sender_ip}'"
        )

        try:
            self.run_cmd(cmd, check=False)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            if os.path.exists("receiver_internal.py"):
                os.remove("receiver_internal.py")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python receiver_container.py <SENDER_IP>")
        sender_ip = input("Enter Sender IP: ").strip()
        if not sender_ip: sys.exit(1)
    else:
        sender_ip = sys.argv[1]

    mgr = ContainerManager()
    try:
        mgr.initialize_container()
        mgr.run_receiver(sender_ip)
    except Exception as e:
        print(f"Error: {e}")
