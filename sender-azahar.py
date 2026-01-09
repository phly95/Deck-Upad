import sys
import socket
import struct
import os
import time
import json
import threading
import argparse
import select
import ctypes
import glfw
import gi
import evdev
from evdev import UInput, ecodes, AbsInfo
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.EGL import *

gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GLib, GstVideo

# --- CONFIGURATION ---
SOCKET_PATH = '\0/com/obsproject/vkcapture'
TEX_FMT = '<BBiii4i4iQIBI65x'
CTRL_FMT = '<BBBB16s12x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS

# --- VISUAL CORRECTIONS ONLY ---
FLIP_X = True   # Mirror Horizontal
FLIP_Y = False  # Mirror Vertical

# EGL Constants
EGL_LINUX_DMA_BUF_EXT = 0x3270
EGL_LINUX_DRM_FOURCC_EXT = 0x3271
EGL_DMA_BUF_PLANE0_FD_EXT = 0x3272
EGL_DMA_BUF_PLANE0_OFFSET_EXT = 0x3273
EGL_DMA_BUF_PLANE0_PITCH_EXT = 0x3274
EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT = 0x3443
EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT = 0x3444

VERTEX_SHADER = """
#version 330 core
layout(location = 0) in vec2 position;
layout(location = 1) in vec2 texCoord;
out vec2 TexCoord;
void main() {
    gl_Position = vec4(position, 0.0, 1.0);
    TexCoord = texCoord;
}
"""

FRAGMENT_SHADER = """
#version 330 core
in vec2 TexCoord;
out vec4 color;
uniform sampler2D tex;
void main() {
    vec4 c = texture(tex, TexCoord);
    color = vec4(c.r, c.g, c.b, 1.0);
}
"""

class InputServer(threading.Thread):
    def __init__(self, sender_instance):
        super().__init__()
        self.daemon = True
        self.sender = sender_instance
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 5001))

        # We keep the UInput definition as the full 0-65535 range.
        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE, ecodes.BTN_TOUCH],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        try:
            self.ui = UInput(cap, name="Stream-Vk-Touch")
            print(" [INPUT] Virtual Touch Device Created via UInput")
        except Exception as e:
            print(f" [ERROR] UInput Init Failed (Need sudo?): {e}")
            self.ui = None

    def calculate_input_box(self):
        # If we haven't received video frames yet, default to full screen
        if self.sender.output_w == 0 or self.sender.output_h == 0:
            return (0.0, 0.0, 1.0, 1.0)

        monitor = glfw.get_primary_monitor()
        if not monitor: return (0.0, 0.0, 1.0, 1.0)

        mode = glfw.get_video_mode(monitor)
        host_w, host_h = mode.size.width, mode.size.height

        if host_w == 0 or host_h == 0: return (0.0, 0.0, 1.0, 1.0)

        stream_w = self.sender.output_w
        stream_h = self.sender.output_h

        host_aspect = host_w / host_h
        stream_aspect = stream_w / stream_h

        if host_aspect > stream_aspect:
            # Pillarbox
            draw_h = host_h
            draw_w = host_h * stream_aspect
            off_x = (host_w - draw_w) / 2.0
            off_y = 0.0
        else:
            # Letterbox
            draw_w = host_w
            draw_h = host_w / stream_aspect
            off_x = 0.0
            off_y = (host_h - draw_h) / 2.0

        bx = off_x / host_w
        by = off_y / host_h
        bw = draw_w / host_w
        bh = draw_h / host_h

        return (bx, by, bw, bh)

    def run(self):
        if not self.ui: return
        while True:
            try:
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                rx = msg['x']
                ry = msg['y']

                if self.sender.input_swap_axes:
                    rx, ry = ry, rx
                if self.sender.input_invert_x:
                    rx = 1.0 - rx
                if self.sender.input_invert_y:
                    ry = 1.0 - ry

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
                elif msg['type'] in ['press', 'release']:
                    btn = ecodes.BTN_LEFT
                    val = 1 if msg['type'] == 'press' else 0
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, abs_x)
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, abs_y)
                    self.ui.write(ecodes.EV_KEY, btn, val)
                    self.ui.write(ecodes.EV_KEY, ecodes.BTN_TOUCH, val)
                    self.ui.syn()
            except Exception as e:
                pass

class VkCaptureSender:
    def __init__(self, args):
        Gst.init(None)
        if not glfw.init(): raise Exception("GLFW init failed")

        glfw.window_hint(glfw.VISIBLE, True)
        glfw.window_hint(glfw.DECORATED, False)
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
        glfw.window_hint(glfw.CONTEXT_CREATION_API, glfw.EGL_CONTEXT_API)

        self.window = glfw.create_window(1, 1, "StreamHost", None, None)
        glfw.make_context_current(self.window)

        self.receiver_ip = args.receiver_ip
        self.fit_screen = args.fit_screen

        self.input_swap_axes = args.swap_input_axes
        self.input_invert_x = args.invert_input_x
        self.input_invert_y = args.invert_input_y

        self.user_crop = None
        if args.crop:
            try: self.user_crop = tuple(map(int, args.crop.split(',')))
            except: pass

        self.input_box = (0.0, 0.0, 1.0, 1.0)
        if args.input_box:
            try: self.input_box = tuple(map(float, args.input_box.split(',')))
            except: pass

        self.fixed_size = None
        if args.fixed_size:
            try: self.fixed_size = tuple(map(int, args.fixed_size.split(',')))
            except: pass

        self.output_w = 0
        self.output_h = 0

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setblocking(True)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind(SOCKET_PATH)
        except OSError:
            print("Socket bind failed - Address in use?")
            sys.exit(1)
        self.server.listen(1)

        self.ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.is_rotated = False

        self.input_server = InputServer(self)
        self.input_server.start()

        self.egl_display = eglGetCurrentDisplay()
        self.init_gl()

        self.pipeline = None
        self.appsrc = None
        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)
        self.egl_image = None

    def init_gl(self):
        def get_proc(name, args, res):
            addr = glfw.get_proc_address(name)
            return ctypes.CFUNCTYPE(res, *args)(addr) if addr else None

        self.glEGLImageTargetTexture2DOES = get_proc("glEGLImageTargetTexture2DOES", [ctypes.c_uint, ctypes.c_void_p], None)
        self.eglCreateImageKHR = get_proc("eglCreateImageKHR", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_void_p)
        self.eglDestroyImageKHR = get_proc("eglDestroyImageKHR", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int)

        self.shader = shaders.compileProgram(
            shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER),
            shaders.compileShader(FRAGMENT_SHADER, GL_FRAGMENT_SHADER)
        )

        self.vao = glGenVertexArrays(1)
        self.vbo = glGenBuffers(1)
        self.fbo = glGenFramebuffers(1)
        self.import_tex = glGenTextures(1)

        glBindTexture(GL_TEXTURE_2D, self.import_tex)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)

    def setup_fbo(self, w, h):
        glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
        tex = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, tex)
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, None)
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0)
        glBindFramebuffer(GL_FRAMEBUFFER, 0)

    def setup_pipeline(self, width, height):
        if self.pipeline: self.pipeline.set_state(Gst.State.NULL)

        self.output_w = width
        self.output_h = height

        f = Gst.ElementFactory.find

        # --- H.264 ENCODER SELECTION ---
        # Prioritize Nvidia (nvh264enc) first.
        # If we check 'vaapih264enc' first on an Nvidia system with gstreamer-vaapi installed,
        # it might try to use it and produce a black screen.

        if f("nvh264enc"):
            print(" [ENCODER] Using NVIDIA H.264")
            enc = "nvh264enc preset=low-latency-hq zerolatency=true bitrate=10000 rc-mode=cbr"
        elif f("vaapih264enc"):
            print(" [ENCODER] Using VAAPI H.264 (Intel/AMD)")
            enc = "videoconvert ! vaapih264enc rate-control=cbr bitrate=10000 keyframe-period=60"
        elif f("x264enc"):
            print(" [ENCODER] Using CPU H.264 (x264)")
            enc = "videoconvert ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=5000"
        else:
            print(" [ERROR] No H.264 encoder found!")
            sys.exit(1)

        # Force H.264 Payloader
        payloader = "rtph264pay"

        pipeline_str = (
            f"appsrc name=src format=time is-live=true do-timestamp=false ! "
            f"video/x-raw,format=RGBA,width={width},height={height},framerate={TARGET_FPS}/1 ! "
            f"videoconvert ! video/x-raw,format=NV12 ! "
            f"{enc} ! {payloader} config-interval=1 pt=96 ! "
            f"udpsink host={self.receiver_ip} port=5000 sync=false"
        )

        print(f" [PIPELINE] Starting {width}x{height} RGBA->NV12 via {payloader}")
        self.pipeline = Gst.parse_launch(pipeline_str)
        self.appsrc = self.pipeline.get_by_name("src")
        self.pipeline.set_state(Gst.State.PLAYING)
        self.frame_count = 0
        try:
            # Send control msg. Note: Receiver might need to restart if it's running a different codec
            msg = json.dumps({"cmd": "resize", "w": width, "h": height}).encode()
            self.ctl_sock.sendto(msg, (self.receiver_ip, 5002))
        except: pass

    def calculate_quad(self, w, h, crop, rotate=False):
        u0, v0 = 0.0, 0.0
        u1, v1 = 1.0, 1.0

        if crop:
            cx, cy, cw, ch = crop
            u0 = cx / w; v0 = cy / h
            u1 = (cx + cw) / w; v1 = (cy + ch) / h

        if rotate:
            if FLIP_X: v0, v1 = v1, v0
            if FLIP_Y: u0, u1 = u1, u0
            data = [
                -1.0, -1.0, u1, v1,
                 1.0, -1.0, u1, v0,
                 1.0,  1.0, u0, v0,
                -1.0, -1.0, u1, v1,
                 1.0,  1.0, u0, v0,
                -1.0,  1.0, u0, v1
            ]
        else:
            if FLIP_X: u0, u1 = u1, u0
            if FLIP_Y: v0, v1 = v1, v0
            data = [
                -1.0, -1.0, u0, v1,
                 1.0, -1.0, u1, v1,
                 1.0,  1.0, u1, v0,
                -1.0, -1.0, u0, v1,
                 1.0,  1.0, u1, v0,
                -1.0,  1.0, u0, v0
            ]
        return (ctypes.c_float * len(data))(*data)

    def loop(self):
        print("--- WAITING FOR GAME ---")
        try:
            while True:
                try:
                    conn, _ = self.server.accept()
                except OSError:
                    break

                print(" >> Connected")
                try: conn.send(struct.pack(CTRL_FMT, 1, 0, 1, 1, b'\0'*16))
                except: conn.close(); continue
                conn.setblocking(False)

                current_fd = -1
                fps_timer = time.time()
                frames = 0

                try:
                    while True:
                        loop_start = time.time()
                        glfw.poll_events()

                        readable, _, _ = select.select([conn], [], [], 0)
                        if readable:
                            try:
                                data, ancdata, _, _ = conn.recvmsg(TEX_SIZE, socket.CMSG_LEN(struct.calcsize('i') * 4))
                                if not data: break
                                if data[0] == TYPE_TEXTURE_DATA:
                                    fields = struct.unpack(TEX_FMT, data)
                                    w, h, fmt, stride = fields[2], fields[3], fields[4], fields[5]
                                    mod = fields[13]
                                    fds = []
                                    for c, t, d in ancdata:
                                        if c == socket.SOL_SOCKET and t == socket.SCM_RIGHTS:
                                            fds.extend(struct.unpack('i'*(len(d)//4), d))
                                    if fds:
                                        if current_fd != -1: os.close(current_fd)
                                        current_fd = fds[0]

                                        if self.egl_image:
                                            self.eglDestroyImageKHR(self.egl_display, self.egl_image)

                                        attribs = [
                                            EGL_WIDTH, w, EGL_HEIGHT, h,
                                            EGL_LINUX_DRM_FOURCC_EXT, fmt,
                                            EGL_DMA_BUF_PLANE0_FD_EXT, current_fd,
                                            EGL_DMA_BUF_PLANE0_OFFSET_EXT, 0,
                                            EGL_DMA_BUF_PLANE0_PITCH_EXT, stride,
                                            EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT, mod & 0xFFFFFFFF,
                                            EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT, (mod >> 32) & 0xFFFFFFFF,
                                            EGL_NONE
                                        ]
                                        attr = (ctypes.c_int * len(attribs))(*attribs)
                                        self.egl_image = self.eglCreateImageKHR(self.egl_display, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, None, attr)

                                        glBindTexture(GL_TEXTURE_2D, self.import_tex)
                                        self.glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, self.egl_image)

                                        content_w, content_h = w, h
                                        self.is_rotated = False

                                        if w < h:
                                            print(f" [AUTO] Rotating {w}x{h} -> {h}x{w}")
                                            content_w, content_h = h, w
                                            self.is_rotated = True

                                        crop_rect = None
                                        if self.user_crop:
                                            ux, uy, uw, uh = self.user_crop
                                            if ux+uw <= w and uy+uh <= h:
                                                crop_rect = (ux, uy, uw, uh)
                                                if not self.is_rotated:
                                                    content_w, content_h = uw, uh
                                                else:
                                                    content_w, content_h = uh, uw

                                        final_w, final_h = content_w, content_h

                                        if self.fixed_size:
                                            max_w, max_h = self.fixed_size
                                            aspect = content_w / content_h

                                            if aspect > (max_w / max_h):
                                                final_w = max_w
                                                final_h = int(max_w / aspect)
                                            else:
                                                final_h = max_h
                                                final_w = int(max_h * aspect)

                                            if final_w % 2 != 0: final_w -= 1
                                            if final_h % 2 != 0: final_h -= 1

                                        if self.output_w != final_w or self.output_h != final_h:
                                            print(f" [RESIZE] Output: {final_w}x{final_h} (Source: {content_w}x{content_h})")
                                            self.setup_fbo(final_w, final_h)
                                            self.setup_pipeline(final_w, final_h)

                                            q_arr = self.calculate_quad(w, h, crop_rect, rotate=self.is_rotated)
                                            glBindVertexArray(self.vao)
                                            glBindBuffer(GL_ARRAY_BUFFER, self.vbo)
                                            glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(q_arr), q_arr, GL_STATIC_DRAW)
                                            glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(0))
                                            glEnableVertexAttribArray(0)
                                            glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(2 * 4))
                                            glEnableVertexAttribArray(1)

                            except Exception as e:
                                print(f"Socket Error: {e}")
                                break

                        if self.appsrc and current_fd != -1 and self.egl_image:
                            glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                            glViewport(0, 0, self.output_w, self.output_h)
                            glUseProgram(self.shader)
                            glBindVertexArray(self.vao)
                            glActiveTexture(GL_TEXTURE0)
                            glBindTexture(GL_TEXTURE_2D, self.import_tex)

                            glDrawArrays(GL_TRIANGLES, 0, 6)
                            glFinish()

                            glPixelStorei(GL_PACK_ALIGNMENT, 1)
                            pixels = glReadPixels(0, 0, self.output_w, self.output_h, GL_RGBA, GL_UNSIGNED_BYTE)
                            buf = Gst.Buffer.new_wrapped(pixels)

                            GstVideo.buffer_add_video_meta_full(
                                buf, GstVideo.VideoFrameFlags.NONE,
                                GstVideo.VideoFormat.RGBA,
                                self.output_w, self.output_h,
                                1,
                                [0, 0, 0, 0],
                                [self.output_w * 4, 0, 0, 0]
                            )

                            pts = self.frame_count * self.duration
                            buf.pts = pts; buf.dts = pts; buf.duration = self.duration
                            self.frame_count += 1

                            self.appsrc.emit("push-buffer", buf)
                            glBindFramebuffer(GL_FRAMEBUFFER, 0)
                            frames += 1

                        if time.time() - fps_timer > 1.0:
                            print(f"Sending: {frames} FPS")
                            frames = 0
                            fps_timer = time.time()

                        elapsed = time.time() - loop_start
                        if elapsed < FRAME_INTERVAL:
                            time.sleep(FRAME_INTERVAL - elapsed)

                finally:
                    if current_fd != -1: os.close(current_fd)
                    conn.close()
                    print(" >> Disconnected")

        except KeyboardInterrupt:
            print("\nExiting via KeyboardInterrupt...")

        finally:
            print("Cleaning up resources...")
            self.server.close()

            if self.pipeline:
                self.pipeline.set_state(Gst.State.NULL)

            if self.egl_image:
                self.eglDestroyImageKHR(self.egl_display, self.egl_image)

            glfw.terminate()
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", nargs="?", help="IP")
    parser.add_argument("--crop", help="x,y,w,h")
    parser.add_argument("--input-box", help="x,y,w,h")
    parser.add_argument("--fixed-size", help="W,H (e.g. 1280,800) - Fit video within these dims maintaining aspect")
    parser.add_argument("--fit-screen", action="store_true")

    parser.add_argument("--swap-input-axes", action="store_true", help="Swap X/Y input axes")
    parser.add_argument("--invert-input-x", action="store_true", help="Invert X input")
    parser.add_argument("--invert-input-y", action="store_true", help="Invert Y input")

    args = parser.parse_args()

    target_ip = args.receiver_ip if args.receiver_ip else input("IP: ").strip()
    VkCaptureSender(args).loop()
