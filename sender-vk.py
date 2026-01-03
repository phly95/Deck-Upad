import sys
import socket
import struct
import mmap
import os
import fcntl
import time
import json
import threading
import argparse
import select
import gi
import evdev
from evdev import UInput, ecodes, AbsInfo

gi.require_version('Gst', '1.0')
from gi.repository import Gst, GLib

# --- CONFIGURATION ---
SOCKET_PATH = '\0/com/obsproject/vkcapture'
TEX_FMT = '<BBiii4i4iQIBI65x'
CTRL_FMT = '<BBBB16s12x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

DMA_BUF_IOCTL_SYNC = 0x40086200
DMA_BUF_SYNC_READ = 1
DMA_BUF_SYNC_START = 0
DMA_BUF_SYNC_END = 4

TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS

def dma_sync(fd, flags):
    try:
        sync_args = struct.pack('Q', flags)
        fcntl.ioctl(fd, DMA_BUF_IOCTL_SYNC, sync_args)
    except OSError:
        pass

# --- INPUT HANDLING ---
class InputServer(threading.Thread):
    def __init__(self, sender_instance):
        super().__init__()
        self.daemon = True
        self.sender = sender_instance # Reference to access crop state
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 5001))
        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        try:
            self.ui = UInput(cap, name="Stream-Vk-Mouse")
        except:
            self.ui = None

    def run(self):
        if not self.ui: return
        while True:
            try:
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                # --- COORDINATE MAPPING ---
                # 1. Receiver sends 0.0-1.0 relative to the CROPPED window
                rel_x = msg['x']
                rel_y = msg['y']

                # 2. Get current full dimensions and crop settings from Sender
                full_w = self.sender.current_w
                full_h = self.sender.current_h

                # Default to full screen if no info yet
                if full_w == 0 or full_h == 0:
                    real_x = rel_x
                    real_y = rel_y
                else:
                    # Apply Crop Offset
                    # If we are cropping, we project the small window back onto the large canvas
                    crop = self.sender.active_crop # (x, y, w, h) or None

                    if crop:
                        cx, cy, cw, ch = crop
                        # Map 0-1 of crop to pixels
                        px_x = cx + (rel_x * cw)
                        px_y = cy + (rel_y * ch)

                        # Normalize back to 0-1 of FULL screen
                        real_x = px_x / full_w
                        real_y = px_y / full_h
                    else:
                        real_x = rel_x
                        real_y = rel_y

                # 3. Scale to UInput range
                abs_x = int(real_x * 65535)
                abs_y = int(real_y * 65535)

                # Clamp for safety
                abs_x = max(0, min(65535, abs_x))
                abs_y = max(0, min(65535, abs_y))

                if msg['type'] == 'move':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.syn()
                elif msg['type'] in ['press', 'release']:
                    btn = ecodes.BTN_LEFT
                    if msg['btn'] == 2: btn = ecodes.BTN_MIDDLE
                    if msg['btn'] == 3: btn = ecodes.BTN_RIGHT
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.write(ecodes.EV_KEY, btn, 1 if msg['type'] == 'press' else 0)
                    self.ui.syn()
            except: pass

# --- GSTREAMER SENDER ---
class VkCaptureSender:
    def __init__(self, receiver_ip, crop_arg=None):
        Gst.init(None)
        self.receiver_ip = receiver_ip

        # Parse crop argument "x,y,w,h" into a tuple
        self.user_crop = None
        if crop_arg:
            try:
                self.user_crop = tuple(map(int, crop_arg.split(',')))
                if len(self.user_crop) != 4: raise ValueError
                print(f" [CONFIG] Crop Region Set: {self.user_crop}")
            except:
                print(" [ERROR] Invalid crop format. Use 'x,y,w,h' (e.g., '0,0,1280,720')")
                sys.exit(1)

        self.active_crop = None # Validated crop for current resolution

        self.pipeline = None
        self.appsrc = None
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setblocking(True)
        try:
            self.server.bind(SOCKET_PATH)
        except OSError:
            print("Socket bind failed (is capture already running?).")
            sys.exit(1)
        self.server.listen(1)

        # Pass self to InputServer so it can access crop info
        self.input_server = InputServer(self)
        self.input_server.start()
        self.ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.current_w = 0
        self.current_h = 0
        self.current_stride = 0
        self.pipeline_running = False

        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)

    def get_encoder_str(self):
        f = Gst.ElementFactory.find
        if f("nvh264enc"):
            return "nvh264enc preset=low-latency-hq zerolatency=true bitrate=15000 rc-mode=cbr"
        if f("vaapih264enc"):
            return "vaapih264enc rate-control=cbr bitrate=15000 keyframe-period=60"
        return "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30 bitrate=8000"

    def send_resolution_packet(self):
        """Broadcasts current resolution to receiver (Heartbeat)."""
        try:
            # If cropping, tell receiver the CROPPED size, not full size
            w, h = self.current_w, self.current_h
            if self.active_crop:
                _, _, w, h = self.active_crop

            msg = json.dumps({"cmd": "resize", "w": w, "h": h}).encode()
            self.ctl_sock.sendto(msg, (self.receiver_ip, 5002))
        except: pass

    def restart_pipeline(self, width, height, stride, format_str="BGRA"):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)

        print(f" [PIPELINE] Input: {width}x{height} (Stride: {stride})")

        self.current_w = width
        self.current_h = height
        self.current_stride = stride

        # --- CROP LOGIC ---
        bytes_per_pixel = 4
        padded_width = stride // bytes_per_pixel

        # Default: No Crop
        crop_left = 0
        crop_top = 0
        crop_right = padded_width - width # Stride padding removal
        crop_bottom = 0

        self.active_crop = None

        if self.user_crop:
            ux, uy, uw, uh = self.user_crop
            # Validate bounds
            if ux + uw <= width and uy + uh <= height:
                self.active_crop = self.user_crop
                print(f" [PIPELINE] Applying Crop: {self.active_crop}")

                crop_left = ux
                crop_top = uy
                # videocrop 'right' removes pixels from the right edge of the BUFFER.
                # Buffer Width = padded_width.
                # We want to keep pixels from ux to ux+uw.
                # Pixels to remove from right = (padded_width) - (ux + uw)
                crop_right = padded_width - (ux + uw)
                crop_bottom = height - (uy + uh)
            else:
                print(f" [WARNING] Crop {self.user_crop} out of bounds for {width}x{height}. Ignoring.")

        # Send resize command immediately
        self.send_resolution_packet()

        enc_str = self.get_encoder_str()

        # Added crop properties
        launch_str = (
            f"appsrc name=src format=time is-live=true do-timestamp=false ! "
            f"video/x-raw,format={format_str},width={padded_width},height={height},framerate={TARGET_FPS}/1 ! "
            f"videocrop left={crop_left} right={crop_right} top={crop_top} bottom={crop_bottom} ! "
            "videoconvert ! "
            f"{enc_str} ! "
            "rtph264pay config-interval=1 pt=96 ! "
            f"udpsink host={self.receiver_ip} port=5000 sync=false"
        )

        try:
            self.pipeline = Gst.parse_launch(launch_str)
            self.appsrc = self.pipeline.get_by_name("src")
            self.pipeline.set_state(Gst.State.PLAYING)
            self.pipeline_running = True
            self.frame_count = 0
        except Exception as e:
            print(f"Error launching pipeline: {e}")
            self.pipeline_running = False

    def loop(self):
        print("--- WAITING FOR GAME ---")
        while True:
            # Blocking wait for initial connection
            conn, _ = self.server.accept()
            print(" >> Game Connected!")

            # Send Handshake
            try:
                conn.send(struct.pack(CTRL_FMT, 1, 0, 1, 1, b'\0'*16))
            except:
                conn.close(); continue

            # Switch to Non-Blocking for the loop
            conn.setblocking(False)

            current_fd = None
            mapped_buf = None

            fps_timer = time.time()
            frames_in_sec = 0

            # Connection Loop
            try:
                while True:
                    loop_start = time.time()

                    # 1. Check for Messages (Non-Blocking)
                    readable, _, _ = select.select([conn], [], [], 0)
                    if readable:
                        try:
                            data, ancdata, _, _ = conn.recvmsg(TEX_SIZE, socket.CMSG_LEN(struct.calcsize('i') * 4))
                            if not data:
                                break # Remote closed

                            if data[0] == TYPE_TEXTURE_DATA:
                                fields = struct.unpack(TEX_FMT, data)
                                w, h = fields[2], fields[3]
                                fmt, stride = fields[4], fields[5]

                                fds = []
                                for c, t, d in ancdata:
                                    if c == socket.SOL_SOCKET and t == socket.SCM_RIGHTS:
                                        fds.extend(struct.unpack('i' * (len(d) // 4), d))

                                if fds:
                                    if current_fd:
                                        os.close(current_fd)
                                        if mapped_buf: mapped_buf.close()

                                    current_fd = fds[0]
                                    try:
                                        buf_size = os.lseek(current_fd, 0, os.SEEK_END)
                                        os.lseek(current_fd, 0, os.SEEK_SET)
                                        mapped_buf = mmap.mmap(current_fd, buf_size, mmap.MAP_SHARED, mmap.PROT_READ)
                                    except OSError:
                                        break

                                if w != self.current_w or h != self.current_h or stride != self.current_stride:
                                    self.restart_pipeline(w, h, stride)
                        except BlockingIOError: pass
                        except ConnectionResetError: break

                    # 2. Render Frame
                    if self.pipeline_running and mapped_buf and current_fd:
                        frame_len = self.current_h * self.current_stride

                        # Ensure we don't read past buffer if stride/height calcs are slightly off
                        if frame_len > mapped_buf.size():
                             frame_len = mapped_buf.size()

                        dma_sync(current_fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ)
                        mapped_buf.seek(0)
                        raw_bytes = mapped_buf.read(frame_len)
                        dma_sync(current_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ)

                        gst_buf = Gst.Buffer.new_wrapped(raw_bytes)

                        pts = self.frame_count * self.duration
                        gst_buf.pts = pts
                        gst_buf.dts = pts
                        gst_buf.duration = self.duration
                        self.frame_count += 1

                        self.appsrc.emit("push-buffer", gst_buf)

                        frames_in_sec += 1
                        if time.time() - fps_timer > 1.0:
                            disp_w = self.active_crop[2] if self.active_crop else self.current_w
                            disp_h = self.active_crop[3] if self.active_crop else self.current_h
                            print(f"Sending: {frames_in_sec} FPS | Res: {disp_w}x{disp_h} (Src: {self.current_w}x{self.current_h})")

                            # --- HEARTBEAT ---
                            # Re-send resolution for late joiners
                            self.send_resolution_packet()

                            frames_in_sec = 0
                            fps_timer = time.time()

                    # 3. Rate Limiter
                    elapsed = time.time() - loop_start
                    to_sleep = FRAME_INTERVAL - elapsed
                    if to_sleep > 0:
                        time.sleep(to_sleep)

            except Exception as e:
                print(f"Loop Error: {e}")
            finally:
                if mapped_buf: mapped_buf.close()
                if current_fd: os.close(current_fd)
                conn.close()
                if self.pipeline:
                    self.pipeline.set_state(Gst.State.NULL)
                print(" >> Game Disconnected")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", nargs="?", help="IP of the Steam Deck/Receiver")
    parser.add_argument("--crop", help="Define crop region as 'x,y,w,h' (e.g. 100,100,1280,720)")
    args = parser.parse_args()

    target_ip = args.receiver_ip
    if not target_ip:
        target_ip = input("Enter Receiver IP: ").strip()

    sender = VkCaptureSender(target_ip, args.crop)
    try:
        sender.loop()
    except KeyboardInterrupt:
        pass
