import sys
import socket
import json
import time
import gi

gi.require_version('Gst', '1.0')
gi.require_version('Gtk', '3.0')
from gi.repository import Gst, Gtk, Gdk, GLib

# CONFIG
INPUT_PORT = 5001
VIDEO_PORT = 5000

class ReceiverWindow(Gtk.Window):
    def __init__(self, sender_ip):
        super().__init__(title=f"Stream Receiver (Input -> {sender_ip})")
        self.set_default_size(1280, 720)

        # Setup UDP Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use the provided sender_ip for input events
        self.server_address = (sender_ip, INPUT_PORT)

        # Rate Limiting for Mouse Move
        self.last_move_time = 0
        self.move_interval = 0.016  # ~60 updates per second

        Gst.init(None)

        # OPTIMIZATIONS:
        # 1. queue: Decouples the decoding thread from the Gtk drawing thread.
        # 2. sync=false: Tells Gtk to draw frames IMMEDIATELY, don't wait for clock.
        self.pipeline = Gst.parse_launch(
            f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
            "rtpjitterbuffer latency=0 ! rtph264depay ! avdec_h264 ! videoconvert ! "
            "queue ! gtksink name=sink sync=false"
        )

        sink = self.pipeline.get_by_name("sink")
        video_widget = sink.get_property("widget")
        self.add(video_widget)

        # Input Capture
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
        except Exception as e:
            print(f"Send Error: {e}")

    def on_motion(self, widget, event):
        # THROTTLE: Only send packets every ~16ms (60Hz)
        # This prevents flooding the Gtk Main Loop with network calls
        current_time = time.time()
        if current_time - self.last_move_time < self.move_interval:
            return True

        self.last_move_time = current_time

        width = self.get_allocated_width()
        height = self.get_allocated_height()

        data = {
            "type": "move",
            "x": event.x / width,
            "y": event.y / height
        }
        self.send_input(data)
        return True

    def on_button(self, widget, event):
        # We generally DON'T throttle clicks, latency matters more there
        width = self.get_allocated_width()
        height = self.get_allocated_height()
        etype = "press" if event.type == Gdk.EventType.BUTTON_PRESS else "release"

        data = {
            "type": etype,
            "x": event.x / width,
            "y": event.y / height,
            "btn": event.button
        }
        self.send_input(data)
        return True

    def close(self, *args):
        self.pipeline.set_state(Gst.State.NULL)
        Gtk.main_quit()

if __name__ == "__main__":
    # Determine Sender IP
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    else:
        print("No IP provided as argument.")
        target_ip = input("Enter Sender IP (default 127.0.0.1): ").strip() or "127.0.0.1"

    win = ReceiverWindow(target_ip)
    win.connect("destroy", win.close)
    win.show_all()
    Gtk.main()
