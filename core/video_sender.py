import sys
import socket
import struct
import os
import time
import json
import threading
import select
import ctypes
import glfw
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.EGL import *
import gi

gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstVideo, GLib

# --- CONFIGURATION ---
SOCKET_PATH = '\0/com/DeckUpad/video'
TEX_FMT = '<BBiii4i4iQIBI65x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS

# Visual Corrections
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

class VideoSender:
    def __init__(self, target_ip, status_queue=None):
        self.target_ip = target_ip
        self.status_queue = status_queue
        self.running = True

        self.window = None
        self.egl_display = None
        self.pipeline = None
        self.appsrc = None
        self.egl_image = None
        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)

        # OpenGL Objects
        self.vao = None
        self.vbo = None
        self.fbo = None
        self.shader = None
        self.import_tex = None

        # Dimensions
        self.output_w = 0
        self.output_h = 0
        self.user_crop = None
        self.is_rotated = False

    def notify(self, msg):
        if self.status_queue:
            self.status_queue.put(msg)
        print(f"[VideoSender] {msg}", flush=True)

    def init_gl(self):
        # Initialize GLFW
        if not glfw.init():
            raise Exception("GLFW init failed")

        glfw.window_hint(glfw.VISIBLE, False) # Headless
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
        glfw.window_hint(glfw.CONTEXT_CREATION_API, glfw.EGL_CONTEXT_API)

        self.window = glfw.create_window(1, 1, "DeckUpadSender", None, None)
        if not self.window:
            glfw.terminate()
            raise Exception("Failed to create GLFW window")

        glfw.make_context_current(self.window)
        self.egl_display = eglGetCurrentDisplay()

        # Helper to load EGL Extensions
        def get_proc(name, args, res):
            addr = glfw.get_proc_address(name)
            return ctypes.CFUNCTYPE(res, *args)(addr) if addr else None

        self.glEGLImageTargetTexture2DOES = get_proc("glEGLImageTargetTexture2DOES", [ctypes.c_uint, ctypes.c_void_p], None)
        self.eglCreateImageKHR = get_proc("eglCreateImageKHR", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_void_p)
        self.eglDestroyImageKHR = get_proc("eglDestroyImageKHR", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int)

        # Compile Shaders
        self.shader = shaders.compileProgram(
            shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER),
            shaders.compileShader(FRAGMENT_SHADER, GL_FRAGMENT_SHADER)
        )

        # Generate Objects
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
        # cleanup temp tex (the FBO keeps reference)
        glDeleteTextures(1, [tex])

    def setup_pipeline(self, width, height):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline = None

        self.output_w = width
        self.output_h = height

        self.notify(f"Setting up pipeline: {width}x{height} -> {self.target_ip}")

        f = Gst.ElementFactory.find
        enc = ""
        # Priority: NVIDIA -> VAAPI -> CPU
        if f("nvh264enc"):
            print(" [ENCODER] Using NVIDIA H.264")
            enc = "nvh264enc preset=low-latency-hq zerolatency=true bitrate=10000 rc-mode=cbr"
        elif f("vaapih264enc"):
            print(" [ENCODER] Using VAAPI H.264 (Intel/AMD)")
            enc = "videoconvert ! vaapih264enc rate-control=cbr bitrate=10000 keyframe-period=60"
        else:
            print(" [ENCODER] Using CPU H.264 (x264) - Warning: High Latency")
            enc = "videoconvert ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=5000"

        pipeline_str = (
            f"appsrc name=src format=time is-live=true do-timestamp=false ! "
            f"video/x-raw,format=RGBA,width={width},height={height},framerate={TARGET_FPS}/1 ! "
            f"videoconvert ! video/x-raw,format=NV12 ! "
            f"{enc} ! rtph264pay config-interval=1 pt=96 ! "
            f"udpsink host={self.target_ip} port=5000 sync=false"
        )

        try:
            self.pipeline = Gst.parse_launch(pipeline_str)
            self.appsrc = self.pipeline.get_by_name("src")
            self.pipeline.set_state(Gst.State.PLAYING)
            self.frame_count = 0
            self.notify("VIDEO_STARTING")
        except Exception as e:
            self.notify(f"Pipeline Error: {e}")

    def calculate_quad(self, w, h, crop, rotate=False):
        u0, v0 = 0.0, 0.0
        u1, v1 = 1.0, 1.0

        if crop:
            cx, cy, cw, ch = crop
            u0 = cx / w; v0 = cy / h
            u1 = (cx + cw) / w; v1 = (cy + ch) / h

        if rotate:
            # Handle Citra/Azahar rotation weirdness
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

    def run(self):
        Gst.init(None)
        self.init_gl()

        # Setup Server Socket
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setblocking(True)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Unlink if exists
        try: os.unlink(SOCKET_PATH)
        except OSError: pass # Might be abstract namespace

        try:
            server.bind(SOCKET_PATH)
        except OSError:
            # If abstract namespace '\0...', bind might fail if in use.
            self.notify("Socket bind failed - Address in use?")
            return

        server.listen(1)
        self.notify("VIDEO_READY_WAITING_FOR_APP")

        try:
            while self.running:
                # Wait for App (Azahar) connection
                try:
                    conn, _ = server.accept()
                except OSError:
                    break

                self.notify("APP_CONNECTED")

                # Handshake required by Citra/Azahar protocol
                # 1=Capturing, 0=Mods, 1=Linear, 1=MapHost
                try: conn.send(struct.pack('<BBBB16s12x', 1, 0, 1, 1, b'\0'*16))
                except: conn.close(); continue

                conn.setblocking(False)

                current_fd = -1

                # Render Loop
                try:
                    while True:
                        loop_start = time.time()
                        glfw.poll_events() # Keep window responsive

                        # Non-blocking receive
                        readable, _, _ = select.select([conn], [], [], 0)
                        if readable:
                            try:
                                # Receive Texture Packet + FD via Ancillary Data
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

                                        # Import DMA-BUF as EGLImage
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

                                        # Bind to Texture
                                        glBindTexture(GL_TEXTURE_2D, self.import_tex)
                                        self.glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, self.egl_image)

                                        # Logic to handle rotation (Azahar screens are often rotated)
                                        content_w, content_h = w, h
                                        self.is_rotated = False

                                        # Heuristic: If Width < Height, likely rotated
                                        if w < h:
                                            content_w, content_h = h, w
                                            self.is_rotated = True

                                        # Check if Pipeline Resize needed
                                        if self.output_w != content_w or self.output_h != content_h:
                                            self.setup_fbo(content_w, content_h)
                                            self.setup_pipeline(content_w, content_h)

                                            # Update Quad Geometry
                                            q_arr = self.calculate_quad(w, h, None, rotate=self.is_rotated)
                                            glBindVertexArray(self.vao)
                                            glBindBuffer(GL_ARRAY_BUFFER, self.vbo)
                                            glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(q_arr), q_arr, GL_STATIC_DRAW)
                                            glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(0))
                                            glEnableVertexAttribArray(0)
                                            glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(2 * 4))
                                            glEnableVertexAttribArray(1)

                            except Exception as e:
                                print(f"Recv Error: {e}")
                                break

                        # Draw & Push if we have a valid image and pipeline
                        if self.appsrc and current_fd != -1 and self.egl_image:
                            glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                            glViewport(0, 0, self.output_w, self.output_h)
                            glUseProgram(self.shader)
                            glBindVertexArray(self.vao)
                            glActiveTexture(GL_TEXTURE0)
                            glBindTexture(GL_TEXTURE_2D, self.import_tex)

                            glDrawArrays(GL_TRIANGLES, 0, 6)
                            glFinish()

                            # Read Pixels (GPU -> CPU)
                            # NOTE: PBOs would be faster, but glReadPixels is standard for simple setups
                            glPixelStorei(GL_PACK_ALIGNMENT, 1)
                            pixels = glReadPixels(0, 0, self.output_w, self.output_h, GL_RGBA, GL_UNSIGNED_BYTE)

                            # Wrap in GStreamer Buffer
                            buf = Gst.Buffer.new_wrapped(pixels)

                            # Add Video Meta
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

                        # Frame Limiter
                        elapsed = time.time() - loop_start
                        if elapsed < FRAME_INTERVAL:
                            time.sleep(FRAME_INTERVAL - elapsed)

                finally:
                    # Cleanup when App disconnects
                    if current_fd != -1: os.close(current_fd)
                    conn.close()
                    self.notify("VIDEO_STOPPED")
                    if self.pipeline:
                        self.pipeline.set_state(Gst.State.NULL)
                        self.pipeline = None

        except KeyboardInterrupt:
            pass
        finally:
            server.close()
            if self.egl_image:
                self.eglDestroyImageKHR(self.egl_display, self.egl_image)
            glfw.terminate()

def run_sender_process(target_ip, queue):
    """
    Wrapper to run VideoSender in a separate process.
    """
    try:
        sender = VideoSender(target_ip, queue)
        sender.run()
    except Exception as e:
        if queue: queue.put(f"CRASH: {e}")
        print(f"[VideoSender CRASH] {e}")

if __name__ == "__main__":
    # Test Mode
    run_sender_process("127.0.0.1", None)
