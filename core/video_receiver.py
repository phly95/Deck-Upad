import sys
import socket
import json
import threading
import time
import argparse
import gi

gi.require_version('Gst', '1.0')
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gst, Gtk, Gdk, GLib, Pango

# --- CONFIG ---
CONTROL_PORT = 5003
VIDEO_PORT = 5000
INPUT_PORT = 5001

class DeckUpadWindow(Gtk.Window):
    def __init__(self, host_ip, is_fullscreen=True):
        super().__init__(title="Deck-Upad Receiver")
        self.host_ip = host_ip

        self.set_default_size(1280, 800)

        if is_fullscreen:
            self.set_keep_above(True)
            self.fullscreen()
        else:
            self.set_keep_above(False)

        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(200)
        self.add(self.stack)

        # --- IDLE SCREEN ---
        self.idle_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.idle_box.set_valign(Gtk.Align.CENTER)
        self.idle_box.set_halign(Gtk.Align.CENTER)

        lbl_logo = Gtk.Label()
        lbl_logo.set_markup("<span font='30' weight='bold' foreground='white'>Deck-Upad</span>")
        self.idle_box.pack_start(lbl_logo, True, True, 20)

        self.lbl_status = Gtk.Label()
        self.lbl_status.set_markup("<span font='14' foreground='#888888'>Waiting for Stream...</span>")
        self.idle_box.pack_start(self.lbl_status, False, False, 10)

        self.idle_area = Gtk.EventBox()
        self.idle_area.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0, 0, 1))
        self.idle_area.add(self.idle_box)
        self.stack.add_named(self.idle_area, "idle")

        # --- VIDEO SCREEN ---
        self.video_area = Gtk.DrawingArea()
        self.video_area.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0, 0, 1))
        self.stack.add_named(self.video_area, "video")

        Gst.init(None)
        # Pipeline is always configured to receive
        self.pipeline = Gst.parse_launch(
            f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
            "rtpjitterbuffer latency=0 ! rtph264depay ! avdec_h264 ! videoconvert ! "
            "queue ! gtksink name=sink sync=false"
        )

        sink = self.pipeline.get_by_name("sink")
        self.sink_widget = sink.get_property("widget")
        self.stack.remove(self.video_area)
        self.stack.add_named(self.sink_widget, "video")

        # --- INPUT HANDLING ---
        self.sink_widget.set_events(Gdk.EventMask.POINTER_MOTION_MASK |
                                    Gdk.EventMask.BUTTON_PRESS_MASK |
                                    Gdk.EventMask.BUTTON_RELEASE_MASK)
        self.sink_widget.connect("motion-notify-event", self.on_input_event, "move")
        self.sink_widget.connect("button-press-event", self.on_input_event, "press")
        self.sink_widget.connect("button-release-event", self.on_input_event, "release")

        self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.last_move = 0

        # Default Stream Dimensions
        self.stream_w = 1280
        self.stream_h = 800

        self.running = True
        self.ctl_thread = threading.Thread(target=self.control_listener, daemon=True)
        self.ctl_thread.start()

        self.connect("destroy", self.on_close)
        self.show_all()

        # --- FIX: Start Pipeline Immediately ---
        # We keep the pipeline playing 100% of the time.
        # If no video is sending, udpsrc just waits.
        self.pipeline.set_state(Gst.State.PLAYING)
        self.set_mode("idle")

    def set_mode(self, mode, message=None):
        if message:
            self.lbl_status.set_markup(f"<span font='14' foreground='#888888'>{message}</span>")

        if mode == "video":
            # Just show the video widget. The pipeline is already running.
            self.stack.set_visible_child_name("video")

            # Hide Cursor
            win = self.get_window()
            if win:
                cursor = Gdk.Cursor.new_from_name(self.get_display(), "none")
                win.set_cursor(cursor)
        else:
            # Show idle screen. We do NOT stop the pipeline.
            self.stack.set_visible_child_name("idle")

            # Restore Cursor
            win = self.get_window()
            if win: win.set_cursor(None)

    def control_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", CONTROL_PORT))
            while self.running:
                data, _ = s.recvfrom(1024)
                msg = data.decode().strip()
                GLib.idle_add(self.handle_command, msg)
        except: pass

    def handle_command(self, cmd):
        if cmd == "START_VIDEO": self.set_mode("video")
        elif cmd == "STOP_VIDEO": self.set_mode("idle", "Video Ended. Waiting...")
        elif cmd.startswith("STATUS:"): self.set_mode("idle", cmd.split(":", 1)[1])
        elif cmd.startswith("RES_UPDATE:"):
            try:
                parts = cmd.split(":")[1].split("x")
                self.stream_w = int(parts[0])
                self.stream_h = int(parts[1])
                print(f"Receiver: Updated Stream Resolution: {self.stream_w}x{self.stream_h}")
            except: pass

    def on_input_event(self, widget, event, input_type):
        if not self.host_ip: return False

        if input_type == "move":
            if time.time() - self.last_move < 0.016: return True
            self.last_move = time.time()

        win_w = widget.get_allocated_width()
        win_h = widget.get_allocated_height()
        if win_w == 0 or win_h == 0 or self.stream_w == 0: return False

        # --- ASPECT RATIO CORRECTION ---
        win_aspect = win_w / win_h
        src_aspect = self.stream_w / self.stream_h

        if win_aspect > src_aspect:
            # Pillarbox
            draw_h = win_h
            draw_w = win_h * src_aspect
            offset_x = (win_w - draw_w) / 2
            offset_y = 0
        else:
            # Letterbox
            draw_w = win_w
            draw_h = win_w / src_aspect
            offset_x = 0
            offset_y = (win_h - draw_h) / 2

        if event.x < offset_x or event.x > (offset_x + draw_w): return True
        if event.y < offset_y or event.y > (offset_y + draw_h): return True

        nx = (event.x - offset_x) / draw_w
        ny = (event.y - offset_y) / draw_h

        nx = max(0.0, min(1.0, nx))
        ny = max(0.0, min(1.0, ny))

        payload = json.dumps({"type": input_type, "x": nx, "y": ny}).encode()
        try:
            self.input_sock.sendto(payload, (self.host_ip, INPUT_PORT))
        except: pass

        return True

    def on_close(self, *args):
        self.running = False
        Gtk.main_quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-ip", default="127.0.0.1", help="Target Host IP for input")
    parser.add_argument("--windowed", action="store_true", help="Start in windowed mode")
    args = parser.parse_args()

    win = DeckUpadWindow(host_ip=args.host_ip, is_fullscreen=not args.windowed)
    Gtk.main()
