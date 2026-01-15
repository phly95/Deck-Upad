import socket
import json
import threading
import os
import sys
import time
import subprocess

try:
    from evdev import UInput, ecodes, AbsInfo
    HAS_EVDEV = True
except ImportError:
    HAS_EVDEV = False

try:
    import glfw
    HAS_GLFW = True
except ImportError:
    HAS_GLFW = False

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
        self.host_w = 1920
        self.host_h = 1080
        self.stream_w = 0
        self.stream_h = 0

        self._detect_host_res()
        threading.Thread(target=self._control_loop, daemon=True).start()

    def _detect_host_res(self):
        if not HAS_GLFW: return
        try:
            if not glfw.init(): return
            monitor = glfw.get_primary_monitor()
            if monitor:
                mode = glfw.get_video_mode(monitor)
                self.host_w = mode.size.width
                self.host_h = mode.size.height
            glfw.terminate()
        except: pass

    def update_stream_dimensions(self, w, h):
        self.stream_w = w
        self.stream_h = h

    def _control_loop(self):
        while self.running:
            try:
                data, _ = self.ctrl_sock.recvfrom(1024)
                msg = data.decode().strip()

                if msg.startswith("HOST_RES:"):
                    parts = msg.split(":")[1].split("x")
                    self.host_w = int(parts[0])
                    self.host_h = int(parts[1])
                elif msg.startswith("STREAM_RES:"):
                    parts = msg.split(":")[1].split("x")
                    self.update_stream_dimensions(int(parts[0]), int(parts[1]))
                elif msg == "STOP":
                    break
            except: pass

    def calculate_input_box(self):
        if self.stream_w == 0 or self.stream_h == 0:
            return (0.0, 0.0, 1.0, 1.0)

        host_aspect = self.host_w / self.host_h
        stream_aspect = self.stream_w / self.stream_h

        if host_aspect > stream_aspect:
            # Pillarbox
            draw_w = (self.host_h * stream_aspect) / self.host_w
            bx = (1.0 - draw_w) / 2.0
            by = 0.0
            bw = draw_w
            bh = 1.0
        else:
            # Letterbox
            draw_h = (self.host_w / stream_aspect) / self.host_h
            bx = 0.0
            by = (1.0 - draw_h) / 2.0
            bw = 1.0
            bh = draw_h

        return (bx, by, bw, bh)

    def _init_uinput(self):
        if not HAS_EVDEV: return False

        # 1. Define Capabilities for a pure Touchscreen
        # BTN_TOUCH: Reports contact
        # BTN_TOOL_FINGER: Reports that the contact is a finger (Required for libinput)
        cap_keys = [ecodes.BTN_TOUCH, ecodes.BTN_TOOL_FINGER]

        # 2. Define Absolute Axes
        # resolution=320 is arbitrary but necessary.
        # Without resolution, libinput treats it as undefined/invalid for DIRECT mapping.
        cap_abs = [
            (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=320)),
            (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=320))
        ]

        cap = {
            ecodes.EV_KEY: cap_keys,
            ecodes.EV_ABS: cap_abs
        }

        try:
            # 3. Use INPUT_PROP_DIRECT
            # This tells Gamescope "This device maps 1:1 to the screen pixels"
            self.ui = UInput(
                cap,
                name="Deck-Upad-Touchscreen",
                version=0x1,
                input_props=[ecodes.INPUT_PROP_DIRECT]
            )

            # 4. FIX PERMISSIONS
            # The script runs as root (sudo), so the /dev/input/eventX node is root-only.
            # Gamescope runs as user 'deck'. We must allow 'deck' to read the device.
            if self.ui.device and self.ui.device.path:
                print(f"[InputServer] Setting permissions on {self.ui.device.path} for access...")
                try:
                    os.chmod(self.ui.device.path, 0o666)
                except Exception as e:
                    print(f"[InputServer] Warning: Failed to chmod device: {e}")

            # 5. TRIGGER UDEV
            # Force the OS to re-scan the new device so properties apply immediately
            subprocess.run("udevadm trigger --action=add --sysname-match=event*", shell=True)

            print("[InputServer] Virtual Touchscreen initialized successfully.")
            return True
        except Exception as e:
            print(f"[InputServer] Failed to init UInput: {e}")
            return False

    def run(self):
        if not self._init_uinput(): return

        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                rx = msg['x']
                ry = msg['y']

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
                    # Indicate a finger is touching the screen
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOUCH, 1)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOOL_FINGER, 1)
                    self.ui.syn()
                elif msg['type'] == 'release':
                    # Indicate finger lifted
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOUCH, 0)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOOL_FINGER, 0)
                    self.ui.syn()
            except OSError: break
            except Exception: pass

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
