import socket
import json
import threading
import os
import sys
import time

try:
    from evdev import UInput, ecodes, AbsInfo
    HAS_EVDEV = True
except ImportError:
    HAS_EVDEV = False

class InputServer(threading.Thread):
    def __init__(self, port=5001, control_port=5004):
        super().__init__()
        self.port = port
        self.control_port = control_port
        self.running = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.port))

        self.ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ctrl_sock.bind(("0.0.0.0", self.control_port))

        self.ui = None

        # Dimensions
        self.host_w = 1920
        self.host_h = 1080
        self.stream_w = 0
        self.stream_h = 0

        # Start Control Thread
        threading.Thread(target=self._control_loop, daemon=True).start()

    def _control_loop(self):
        print(f"[InputServer] Control Listener on UDP {self.control_port}")
        while self.running:
            try:
                data, _ = self.ctrl_sock.recvfrom(1024)
                msg = data.decode().strip()

                if msg.startswith("HOST_RES:"):
                    parts = msg.split(":")[1].split("x")
                    self.host_w = int(parts[0])
                    self.host_h = int(parts[1])
                    print(f"[InputServer] Host Resolution Updated: {self.host_w}x{self.host_h}")

                elif msg.startswith("STREAM_RES:"):
                    parts = msg.split(":")[1].split("x")
                    self.stream_w = int(parts[0])
                    self.stream_h = int(parts[1])
                    print(f"[InputServer] Stream Resolution Updated: {self.stream_w}x{self.stream_h}")

            except: pass

    def calculate_input_box(self):
        """
        Calculates valid area on HOST screen.
        Matches Sender's logic for pillarboxing/letterboxing.
        """
        if self.stream_w == 0 or self.stream_h == 0:
            return (0.0, 0.0, 1.0, 1.0)

        host_aspect = self.host_w / self.host_h
        stream_aspect = self.stream_w / self.stream_h

        if host_aspect > stream_aspect:
            # Pillarbox (Bars on sides)
            draw_w = self.host_h * stream_aspect
            off_x = (self.host_w - draw_w) / 2.0

            bx = off_x / self.host_w
            by = 0.0
            bw = draw_w / self.host_w
            bh = 1.0
        else:
            # Letterbox (Bars on top)
            draw_h = self.host_w / stream_aspect
            off_y = (self.host_h - draw_h) / 2.0

            bx = 0.0
            by = off_y / self.host_h
            bw = 1.0
            bh = draw_h / self.host_h

        return (bx, by, bw, bh)

    def _init_uinput(self):
        if not HAS_EVDEV: return False
        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_TOUCH],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        try:
            self.ui = UInput(cap, name="Deck-Upad-Virtual-Touch", version=0x1)
            print("[InputServer] Virtual Touch Device Created.")
            return True
        except: return False

    def run(self):
        if not self._init_uinput(): return
        print(f"[InputServer] Listening on UDP {self.port}...")

        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                rx = msg['x']
                ry = msg['y']

                # Map 0..1 (Video Space) -> 0..1 (Host Screen Space)
                ib_x, ib_y, ib_w, ib_h = self.calculate_input_box()

                final_x = ib_x + (rx * ib_w)
                final_y = ib_y + (ry * ib_h)

                abs_x = int(final_x * 65535)
                abs_y = int(final_y * 65535)

                abs_x = max(0, min(65535, abs_x))
                abs_y = max(0, min(65535, abs_y))

                if msg['type'] == 'move':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.syn()
                elif msg['type'] == 'press':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 1)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOUCH, 1)
                    self.ui.syn()
                elif msg['type'] == 'release':
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 0)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOUCH, 0)
                    self.ui.syn()
            except: pass

    def stop(self):
        self.running = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"{}", ("127.0.0.1", self.port))
            s.sendto(b"STOP", ("127.0.0.1", self.control_port))
        except: pass
        self.sock.close()
        self.ctrl_sock.close()
        if self.ui: self.ui.close()

if __name__ == "__main__":
    server = InputServer()
    server.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
