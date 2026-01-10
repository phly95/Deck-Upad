import sys
import socket
import json
import threading
import time
import gi

gi.require_version('Gst', '1.0')
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gst, Gtk, Gdk, GLib, Pango

# --- CONFIG ---
CONTROL_PORT = 5003  # Internal local control
VIDEO_PORT = 5000

class DeckUpadWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Deck-Upad")

        # Window Setup
        self.set_default_size(1280, 800)
        self.set_keep_above(True)
        self.fullscreen()

        # Dark Theme hint
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)

        # Main Container: Stack (Allows switching between Idle and Video)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(200)
        self.add(self.stack)

        # --- PAGE 1: IDLE SCREEN ---
        self.idle_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.idle_box.set_valign(Gtk.Align.CENTER)
        self.idle_box.set_halign(Gtk.Align.CENTER)

        # Logo Label
        lbl_logo = Gtk.Label()
        lbl_logo.set_markup("<span font='30' weight='bold' foreground='white'>Deck-Upad</span>")
        self.idle_box.pack_start(lbl_logo, True, True, 20)

        # Status Label
        self.lbl_status = Gtk.Label(label="Waiting for Host...")
        self.lbl_status.set_markup("<span font='14' foreground='#888888'>Waiting for Host...</span>")
        self.idle_box.pack_start(self.lbl_status, False, False, 10)

        # Background color for idle (Black)
        self.idle_area = Gtk.EventBox()
        self.idle_area.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0, 0, 1))
        self.idle_area.add(self.idle_box)

        self.stack.add_named(self.idle_area, "idle")

        # --- PAGE 2: VIDEO SCREEN ---
        self.video_area = Gtk.DrawingArea()
        # We override background to black to avoid artifacts
        self.video_area.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0, 0, 1))
        self.stack.add_named(self.video_area, "video")

        # --- GSTREAMER ---
        Gst.init(None)
        # Low latency H.264 pipeline
        self.pipeline = Gst.parse_launch(
            f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
            "rtpjitterbuffer latency=0 ! rtph264depay ! avdec_h264 ! videoconvert ! "
            "queue ! gtksink name=sink sync=false"
        )

        sink = self.pipeline.get_by_name("sink")
        self.sink_widget = sink.get_property("widget")
        self.stack.remove(self.video_area) # Swap the dummy with real sink
        self.stack.add_named(self.sink_widget, "video")

        # Connect Input Events (Pass mouse back to host)
        self.sink_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK |
                                    Gdk.EventMask.BUTTON_PRESS_MASK |
                                    Gdk.EventMask.BUTTON_RELEASE_MASK)
        self.sink_widget.connect("motion-notify-event", self.on_input_event, "move")
        self.sink_widget.connect("button-press-event", self.on_input_event, "press")
        self.sink_widget.connect("button-release-event", self.on_input_event, "release")

        # Start Listener Thread
        self.running = True
        self.ctl_thread = threading.Thread(target=self.control_listener, daemon=True)
        self.ctl_thread.start()

        # Input Networking
        self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # We don't know Host IP yet, usually passed in env or we assume gateway
        # For now, we broadcast input or use env var

        self.connect("destroy", self.on_close)
        self.show_all()

        # Start in Idle
        self.set_mode("idle", "Connected. Waiting for Video...")

    def set_mode(self, mode, message=None):
        if message:
            self.lbl_status.set_markup(f"<span font='14' foreground='#888888'>{message}</span>")

        if mode == "video":
            self.pipeline.set_state(Gst.State.PLAYING)
            self.stack.set_visible_child_name("video")
            # Hide cursor for immersion
            win = self.get_window()
            if win:
                cursor = Gdk.Cursor.new_from_name(self.get_display(), "none")
                win.set_cursor(cursor)
        else:
            self.pipeline.set_state(Gst.State.NULL)
            self.stack.set_visible_child_name("idle")
            win = self.get_window()
            if win: win.set_cursor(None) # Restore cursor

    def control_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", CONTROL_PORT))
        print(f"GUI Listener on {CONTROL_PORT}")
        while self.running:
            try:
                data, _ = s.recvfrom(1024)
                msg = data.decode().strip()
                GLib.idle_add(self.handle_command, msg)
            except: pass

    def handle_command(self, cmd):
        print(f"GUI Command: {cmd}")
        if cmd == "START_VIDEO":
            self.set_mode("video")
        elif cmd == "STOP_VIDEO":
            self.set_mode("idle", "Video Ended. Waiting...")
        elif cmd.startswith("STATUS:"):
            self.set_mode("idle", cmd.split(":", 1)[1])

    def on_input_event(self, widget, event, input_type):
        # We will implement Input forwarding later if needed
        # For now, the USB/IP controller handles the heavy lifting
        return True

    def on_close(self, *args):
        self.running = False
        Gtk.main_quit()

if __name__ == "__main__":
    win = DeckUpadWindow()
    Gtk.main()
