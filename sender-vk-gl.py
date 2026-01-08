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
from gi.repository import Gst, GLib

# --- CONFIGURATION ---
SOCKET_PATH = '\0/com/obsproject/vkcapture'
TEX_FMT = '<BBiii4i4iQIBI65x'
CTRL_FMT = '<BBBB16s12x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS

# FLIP SETTINGS
# Enable this to fix "Backwards Text" (Horizontal Mirror)
FLIP_X = True
# Enable this if the image is Upside Down
FLIP_Y = False

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
        cap = {
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE],
            ecodes.EV_ABS: [
                (ecodes.ABS_X, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0)),
                (ecodes.ABS_Y, AbsInfo(value=0, min=0, max=65535, fuzz=0, flat=0, resolution=0))
            ]
        }
        try: self.ui = UInput(cap, name="Stream-Vk-Mouse")
        except: self.ui = None

    def run(self):
        if not self.ui: return
        while True:
            try:
                data, _ = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())

                rx = msg['x']
                ry = msg['y']

                # Correct input mapping if we are flipping/rotating
                # If we flip the video X, we must flip the Input X to match
                if FLIP_X: rx = 1.0 - rx
                if FLIP_Y: ry = 1.0 - ry

                if self.sender.is_rotated:
                    # Swap X/Y for Portrait->Landscape mapping
                    rx, ry = ry, rx

                if msg['type'] == 'move':
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, int(rx * 65535))
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, int(ry * 65535))
                    self.ui.syn()
                elif msg['type'] in ['press', 'release']:
                    btn = ecodes.BTN_LEFT
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_X, int(rx * 65535))
                    self.ui.write(ecodes.EV_ABS, ecodes.ABS_Y, int(ry * 65535))
                    self.ui.write(ecodes.EV_KEY, btn, 1 if msg['type'] == 'press' else 0)
                    self.ui.syn()
            except: pass

class VkCaptureSender:
    def __init__(self, receiver_ip, crop_arg=None):
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

        self.receiver_ip = receiver_ip
        self.user_crop = None
        if crop_arg:
            try: self.user_crop = tuple(map(int, crop_arg.split(',')))
            except: pass

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setblocking(True)
        try:
            self.server.bind(SOCKET_PATH)
        except OSError:
            print("Socket bind failed.")
            sys.exit(1)
        self.server.listen(1)

        self.ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.input_server = InputServer(self)
        self.input_server.start()

        self.egl_display = eglGetCurrentDisplay()
        self.init_gl()

        self.pipeline = None
        self.appsrc = None
        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)
        self.output_w = 0
        self.output_h = 0
        self.is_rotated = False
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

        # --- ENCODER SELECTION ---
        # We switch to Constant Quality (QP) mode for sharper images.
        # Lower QP = Higher Quality (and higher bandwidth).
        # QP 20 is a "Visually Lossless" sweet spot for gaming.

        if f("nvh264enc"):
            # NVIDIA GPU
            # rc-mode=constqp: Constant Quantization Parameter
            # qp-const=20: High quality
            # preset=low-latency-hq: Better quality than just 'default'
            enc = "nvh264enc preset=low-latency-hq rc-mode=constqp qp-const=20 zerolatency=true"

        elif f("vaapih264enc"):
            # INTEL / AMD GPU
            # AMD VAAPI drivers sometimes struggle with CQP, so we fallback to a massive bitrate (15Mbps)
            # If your driver supports it, you can try 'rate-control=cqp'
            enc = "videoconvert ! vaapih264enc rate-control=cbr bitrate=15000 keyframe-period=60"

        else:
            # SOFTWARE (x264)
            # pass=qual: Constant Quality mode
            # quantizer=20: The quality target (lower is better)
            # speed-preset=superfast: Slightly better than ultrafast, minimal latency cost
            enc = "videoconvert ! x264enc tune=zerolatency speed-preset=superfast pass=qual quantizer=20 key-int-max=60"

        # NOTE: We force 'videoconvert' for x264/vaapi to ensure colorspace compatibility (RGBA -> YUV420)

        pipeline_str = (
            f"appsrc name=src format=time is-live=true do-timestamp=false ! "
            f"video/x-raw,format=RGBA,width={width},height={height},framerate={TARGET_FPS}/1 ! "
            f"{enc} ! rtph264pay config-interval=1 pt=96 ! "
            f"udpsink host={self.receiver_ip} port=5000 sync=false"
        )

        print(f" [PIPELINE] Starting {width}x{height} RGBA")
        self.pipeline = Gst.parse_launch(pipeline_str)
        self.appsrc = self.pipeline.get_by_name("src")
        self.pipeline.set_state(Gst.State.PLAYING)
        self.frame_count = 0
        try:
            msg = json.dumps({"cmd": "resize", "w": width, "h": height}).encode()
            self.ctl_sock.sendto(msg, (self.receiver_ip, 5002))
        except: pass

    def calculate_quad(self, tex_w, tex_h, crop, rotate=False):
        cx, cy, cw, ch = crop
        u0 = cx / tex_w; v0 = cy / tex_h
        u1 = (cx + cw) / tex_w; v1 = (cy + ch) / tex_h

        if rotate:
            # 90 Deg Rotation (Source V -> Output X, Source U -> Output Y)
            # If Flipping X (Horizontal): Swap Source Vs
            # If Flipping Y (Vertical):   Swap Source Us
            if FLIP_X: v0, v1 = v1, v0
            if FLIP_Y: u0, u1 = u1, u0

            data = [
                -1.0, -1.0, u1, v1, # BL -> Source Bottom-Left (u1, v1)
                 1.0, -1.0, u1, v0, # BR -> Source Top-Left    (u1, v0)
                 1.0,  1.0, u0, v0, # TR -> Source Top-Right   (u0, v0)
                -1.0, -1.0, u1, v1,
                 1.0,  1.0, u0, v0,
                -1.0,  1.0, u0, v1  # TL -> Source Bottom-Right(u0, v1)
            ]
        else:
            # Standard (Source U -> Output X, Source V -> Output Y)
            # If Flipping X: Swap Source Us
            # If Flipping Y: Swap Source Vs
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
        while True:
            conn, _ = self.server.accept()
            print(" >> Connected")
            try: conn.send(struct.pack(CTRL_FMT, 1, 0, 1, 1, b'\0'*16))
            except: conn.close(); continue
            conn.setblocking(False)

            current_fd = -1
            tex_w = 0; tex_h = 0

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

                                    if not self.egl_image:
                                        print(" [GL] Failed to create EGL Image")
                                        break

                                    glBindTexture(GL_TEXTURE_2D, self.import_tex)
                                    self.glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, self.egl_image)

                                    aligned_w = stride // 4

                                    fx=0; fy=0; fw=w; fh=h
                                    if self.user_crop:
                                        ux, uy, uw, uh = self.user_crop
                                        if ux+uw <= w and uy+uh <= h:
                                            fx=ux; fy=uy; fw=uw; fh=uh

                                    # AUTO-ROTATION LOGIC
                                    target_w, target_h = fw, fh
                                    self.is_rotated = False

                                    if fw < fh:
                                        print(f" [AUTO] Detected Portrait ({fw}x{fh}). Rotating to Landscape ({fh}x{fw}).")
                                        target_w, target_h = fh, fw
                                        self.is_rotated = True

                                    if self.output_w != target_w or self.output_h != target_h or tex_w != aligned_w:
                                        tex_w = aligned_w; tex_h = h
                                        self.setup_fbo(target_w, target_h)
                                        self.setup_pipeline(target_w, target_h)

                                        q_arr = self.calculate_quad(tex_w, h, (fx, fy, fw, fh), rotate=self.is_rotated)
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

                        pixels = glReadPixels(0, 0, self.output_w, self.output_h, GL_RGBA, GL_UNSIGNED_BYTE)

                        buf = Gst.Buffer.new_wrapped(pixels)
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
                if self.pipeline: self.pipeline.set_state(Gst.State.NULL)
                print(" >> Disconnected")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", nargs="?", help="IP")
    parser.add_argument("--crop", help="x,y,w,h")
    args = parser.parse_args()
    target_ip = args.receiver_ip if args.receiver_ip else input("IP: ").strip()
    VkCaptureSender(target_ip, args.crop).loop()
