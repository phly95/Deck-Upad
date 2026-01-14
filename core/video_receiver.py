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
from gi.repository import Gst, Gtk, Gdk, GLib, Pango, GstVideo

# --- CONFIG ---
CONTROL_PORT = 5003
VIDEO_PORT = 5000
INPUT_PORT = 5001

class DeckUpadWindow(Gtk.Window):
    def __init__(self, host_ip, is_fullscreen=False):
        super().__init__(title="Deck-Upad Receiver")
        self.host_ip = host_ip
        self.is_fullscreen_active = is_fullscreen

        self.set_default_size(1280, 800)
        self.set_keep_above(False)

        if self.is_fullscreen_active:
            self.fullscreen()

        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(200)
        self.add(self.stack)

        self.idle_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.idle_box.set_valign(Gtk.Align.CENTER)
        self.idle_box.set_halign(Gtk.Align.CENTER)

        lbl = Gtk.Label(label="Waiting for Stream...")
        self.idle_box.pack_start(lbl, True, True, 0)

        self.spinner = Gtk.Spinner()
        self.spinner.start()
        self.idle_box.pack_start(self.spinner, True, True, 0)

        self.idle_area = Gtk.EventBox()
        self.idle_area.add(self.idle_box)
        self.idle_area.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.1, 0.1, 0.1, 1))

        self.stack.add_named(self.idle_area, "idle")

        self.video_area = Gtk.DrawingArea()
        self.video_area.connect("realize", self.on_realize)
        self.video_area.connect("draw", self.on_draw)
        self.video_area.set_events(Gdk.EventMask.ALL_EVENTS_MASK)
        self.video_area.connect("button-press-event", self.on_input, "press")
        self.video_area.connect("button-release-event", self.on_input, "release")
        self.video_area.connect("motion-notify-event", self.on_input, "move")
        self.stack.add_named(self.video_area, "video")

        self.connect("key-press-event", self.on_key_press)

        self.input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pipeline = None
        self.xid = None
        self.stream_w = 1280
        self.stream_h = 800
        self.running = True

        self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control_sock.bind(("0.0.0.0", CONTROL_PORT))
        self.control_sock.setblocking(False)
        GLib.timeout_add(100, self.check_control_messages)

        self.connect("destroy", self.on_close)
        self.show_all()

    def on_key_press(self, widget, event):
        if event.keyval == Gdk.KEY_F11:
            if self.is_fullscreen_active:
                self.unfullscreen()
                self.is_fullscreen_active = False
            else:
                self.fullscreen()
                self.is_fullscreen_active = True
        elif event.keyval == Gdk.KEY_Escape:
            if self.is_fullscreen_active:
                self.unfullscreen()
                self.is_fullscreen_active = False

    def on_realize(self, widget):
        window = widget.get_window()
        if window:
            try:
                self.xid = window.get_xid()
            except:
                print("[RX] Could not get XID (Wayland?)")

    def on_draw(self, widget, cr):
        cr.set_source_rgb(0, 0, 0)
        cr.paint()

    def check_control_messages(self):
        try:
            while True:
                data, _ = self.control_sock.recvfrom(1024)
                msg = data.decode().strip()
                print(f"[RX] CMD: {msg}")
                if msg == "START_VIDEO": self.start_pipeline()
                elif msg == "STOP_VIDEO": self.stop_pipeline()
                elif msg.startswith("RES_UPDATE:"):
                    try:
                        res = msg.split(":")[1].split("x")
                        self.stream_w = int(res[0])
                        self.stream_h = int(res[1])
                        print(f"[RX] Resolution Update: {self.stream_w}x{self.stream_h}")
                    except: pass
        except BlockingIOError: pass
        except Exception as e: print(f"[RX] Error: {e}")
        return True

    def start_pipeline(self):
        self.stop_pipeline()
        print(f"[RX] Starting GStreamer Pipeline... {self.stream_w}x{self.stream_h}")
        self.stack.set_visible_child_name("video")

        pipeline_str = (
            f"udpsrc port={VIDEO_PORT} caps=\"application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=96\" ! "
            f"rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! "
            f"xvimagesink name=sink sync=false render-delay=0"
        )

        try:
            self.pipeline = Gst.parse_launch(pipeline_str)
            bus = self.pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect('message', self.on_message)

            if self.xid:
                sink = self.pipeline.get_by_name("sink")
                # CORRECT FIX: Call set_window_handle on the interface, not the object directly
                GstVideo.VideoOverlay.set_window_handle(sink, self.xid)

            self.pipeline.set_state(Gst.State.PLAYING)
        except Exception as e:
            print(f"[RX] Pipeline Error: {e}")
            self.stop_pipeline()

    def stop_pipeline(self):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline = None
        self.stack.set_visible_child_name("idle")

    def on_message(self, bus, message):
        t = message.type
        if t == Gst.MessageType.ERROR:
            err, debug = message.parse_error()
            print(f"[RX] GStreamer Error: {err} {debug}")
            self.stop_pipeline()
        elif t == Gst.MessageType.EOS:
            self.stop_pipeline()

    def on_input(self, widget, event, input_type):
        if not self.running: return False
        alloc = widget.get_allocation()
        win_w, win_h = alloc.width, alloc.height
        if win_w == 0 or win_h == 0: return False

        win_aspect = win_w / win_h
        src_aspect = self.stream_w / self.stream_h

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

        if event.x < offset_x or event.x > (offset_x + draw_w): return True
        if event.y < offset_y or event.y > (offset_y + draw_h): return True

        nx = (event.x - offset_x) / draw_w
        ny = (event.y - offset_y) / draw_h
        nx = max(0.0, min(1.0, nx))
        ny = max(0.0, min(1.0, ny))

        payload = json.dumps({"type": input_type, "x": nx, "y": ny}).encode()
        try: self.input_sock.sendto(payload, (self.host_ip, INPUT_PORT))
        except: pass
        return True

    def on_close(self, *args):
        self.running = False
        Gtk.main_quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--host-ip", dest="host", help="Alias for --host")
    parser.add_argument("--fullscreen", action="store_true")
    parser.add_argument("--windowed", action="store_true")
    args = parser.parse_args()

    is_fs = args.fullscreen
    if args.windowed: is_fs = False

    Gst.init(None)
    win = DeckUpadWindow(args.host, is_fullscreen=is_fs)
    Gtk.main()
