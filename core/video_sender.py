#!/usr/bin/env python3
import sys
import socket
import struct
import os
import time
import argparse
import ctypes
import select
import math
import glfw
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.EGL import *
import gi

gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstVideo, GLib

# --- CONFIGURATION ---
# The abstract socket path used by Azahar/Citra for IPC
# Note: The leading null byte '\0' indicates the Abstract Namespace
SOCKET_PATH = '\0/com/DeckUpad/video'

# Binary struct format for the texture metadata packet
TEX_FMT = '<BBiii4i4iQIBI65x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS

# Visual Corrections
FLIP_X = True   # Mirror Horizontal (often needed for front-facing camera logic or specific emulators)
FLIP_Y = False  # Mirror Vertical (OpenGL vs GStreamer coordinate systems)

# --- EGL EXTENSION CONSTANTS ---
EGL_LINUX_DMA_BUF_EXT = 0x3270
EGL_LINUX_DRM_FOURCC_EXT = 0x3271
EGL_DMA_BUF_PLANE0_FD_EXT = 0x3272
EGL_DMA_BUF_PLANE0_OFFSET_EXT = 0x3273
EGL_DMA_BUF_PLANE0_PITCH_EXT = 0x3274
EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT = 0x3443
EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT = 0x3444

# --- SHADERS ---
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

# Simple Test Shader for Test Mode (Generating pulsing colors)
TEST_FRAGMENT_SHADER = """
#version 330 core
in vec2 TexCoord;
out vec4 color;
uniform float time;
void main() {
    float r = 0.5 + 0.5 * sin(time + TexCoord.x * 5.0);
    float g = 0.5 + 0.5 * cos(time + TexCoord.y * 5.0);
    // Green/Teal pattern to verify color space
    color = vec4(r, g, 0.5, 1.0);
}
"""

class VideoSender:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.running = True

        # Initialize GStreamer
        Gst.init(None)

        # Initialize GLFW for Headless OpenGL Context
        if not glfw.init():
            self.notify("CRASH: GLFW init failed")
            sys.exit(1)

        glfw.window_hint(glfw.VISIBLE, False)
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
        glfw.window_hint(glfw.CONTEXT_CREATION_API, glfw.EGL_CONTEXT_API)

        self.window = glfw.create_window(1, 1, "DeckUpadSender", None, None)
        if not self.window:
            glfw.terminate()
            self.notify("CRASH: Failed to create Window/Context")
            sys.exit(1)

        glfw.make_context_current(self.window)
        self.egl_display = eglGetCurrentDisplay()

        # Load GL extensions and compile shaders
        self.init_gl()

        # GStreamer State
        self.pipeline = None
        self.appsrc = None
        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)

        # State Tracking
        self.output_w = 0
        self.output_h = 0
        self.egl_image = None
        self.is_rotated = False
        self.server = None

    def notify(self, msg):
        """Prints to stdout so the parent daemon/launcher can read the status."""
        print(msg, flush=True)

    def init_gl(self):
        # Helper to load EGL functions
        def get_proc(name, args, res):
            addr = glfw.get_proc_address(name)
            return ctypes.CFUNCTYPE(res, *args)(addr) if addr else None

        # Load required EGL extensions for DMA-BUF import
        self.glEGLImageTargetTexture2DOES = get_proc("glEGLImageTargetTexture2DOES", [ctypes.c_uint, ctypes.c_void_p], None)
        self.eglCreateImageKHR = get_proc("eglCreateImageKHR", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_void_p)
        self.eglDestroyImageKHR = get_proc("eglDestroyImageKHR", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int)

        # Compile Shaders
        self.shader = shaders.compileProgram(
            shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER),
            shaders.compileShader(FRAGMENT_SHADER, GL_FRAGMENT_SHADER)
        )

        # Compile Test Shader
        self.test_shader = shaders.compileProgram(
            shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER),
            shaders.compileShader(TEST_FRAGMENT_SHADER, GL_FRAGMENT_SHADER)
        )

        # Generate Buffers
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
        glDeleteTextures(1, [tex])

    def setup_pipeline(self, width, height):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline = None

        self.output_w = width
        self.output_h = height

        self.notify(f"Configuring GStreamer for {width}x{height} -> {self.target_ip}")

        f = Gst.ElementFactory.find
        enc = ""

        # Hardware Encoder Selection Logic
        if f("nvh264enc"):
            self.notify("Using NVIDIA NVENC")
            enc = "nvh264enc preset=low-latency-hq zerolatency=true bitrate=10000 rc-mode=cbr"
        elif f("vaapih264enc"):
            self.notify("Using VAAPI (Intel/AMD)")
            enc = "videoconvert ! vaapih264enc rate-control=cbr bitrate=10000 keyframe-period=60"
        else:
            self.notify("Using Software x264 (Warning: Higher Latency)")
            enc = "videoconvert ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=5000"

        # Construct Pipeline
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

    def calculate_quad(self, w, h, rotate=False):
        # Standard UVs
        u0, v0 = 0.0, 0.0
        u1, v1 = 1.0, 1.0

        if rotate:
            # Handle swap for rotated screens (Common in 3DS emulation)
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
            # Standard logic
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

    def run_test_mode(self):
        """
        Simulates a game connection by generating a test pattern locally via OpenGL shaders.
        Does not require the Emulator to be running.
        """
        self.notify("TEST_MODE_ACTIVE")
        W, H = 1280, 800 # Deck Resolution

        self.setup_fbo(W, H)
        self.setup_pipeline(W, H)

        # Setup Geometry (No rotation for test)
        q_arr = self.calculate_quad(W, H, rotate=False)
        glBindVertexArray(self.vao)
        glBindBuffer(GL_ARRAY_BUFFER, self.vbo)
        glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(q_arr), q_arr, GL_STATIC_DRAW)
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(0))
        glEnableVertexAttribArray(0)
        glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(2 * 4))
        glEnableVertexAttribArray(1)

        sim_time = 0.0

        try:
            while self.running:
                loop_start = time.time()
                glfw.poll_events()
                sim_time += 0.05

                if self.appsrc:
                    glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                    glViewport(0, 0, W, H)

                    # Use Test Shader
                    glUseProgram(self.test_shader)

                    # Pass time uniform for animation
                    loc = glGetUniformLocation(self.test_shader, "time")
                    glUniform1f(loc, sim_time)

                    glBindVertexArray(self.vao)
                    glDrawArrays(GL_TRIANGLES, 0, 6)
                    glFinish()

                    # Read Pixels (GPU -> CPU)
                    glPixelStorei(GL_PACK_ALIGNMENT, 1)
                    pixels = glReadPixels(0, 0, W, H, GL_RGBA, GL_UNSIGNED_BYTE)

                    # Push to GStreamer
                    buf = Gst.Buffer.new_wrapped(pixels)
                    GstVideo.buffer_add_video_meta_full(buf, GstVideo.VideoFrameFlags.NONE, GstVideo.VideoFormat.RGBA, W, H, 1, [0, 0, 0, 0], [W * 4, 0, 0, 0])
                    pts = self.frame_count * self.duration
                    buf.pts = pts; buf.dts = pts; buf.duration = self.duration
                    self.frame_count += 1
                    self.appsrc.emit("push-buffer", buf)
                    glBindFramebuffer(GL_FRAMEBUFFER, 0)

                elapsed = time.time() - loop_start
                if elapsed < FRAME_INTERVAL: time.sleep(FRAME_INTERVAL - elapsed)
        finally:
            if self.pipeline: self.pipeline.set_state(Gst.State.NULL)
            glfw.terminate()

    def run(self):
        # 1. Setup Unix Socket
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Cleanup if exists (Only for filesystem sockets, skip for abstract namespace starting with \0)
        if not SOCKET_PATH.startswith('\0'):
            try: os.unlink(SOCKET_PATH)
            except OSError: pass

        try:
            self.server.bind(SOCKET_PATH)
        except OSError:
            self.notify("CRASH: Socket address in use")
            sys.exit(1)

        self.server.listen(1)
        self.notify("VIDEO_READY")

        try:
            while self.running:
                # 2. Wait for App (Azahar) connection
                try:
                    conn, _ = self.server.accept()
                except OSError: break

                self.notify("APP_CONNECTED")

                # 3. Handshake (Required by Citra/Azahar protocol)
                try: conn.send(struct.pack('<BBBB16s12x', 1, 0, 1, 1, b'\0'*16))
                except: conn.close(); continue

                conn.setblocking(False)
                current_fd = -1

                try:
                    while True:
                        loop_start = time.time()
                        glfw.poll_events()

                        # 4. Check for new Frame Data (Non-blocking)
                        readable, _, _ = select.select([conn], [], [], 0)
                        if readable:
                            try:
                                # Receive Texture Meta + FD
                                data, ancdata, _, _ = conn.recvmsg(TEX_SIZE, socket.CMSG_LEN(struct.calcsize('i') * 4))
                                if not data: break

                                if data[0] == TYPE_TEXTURE_DATA:
                                    fields = struct.unpack(TEX_FMT, data)
                                    w, h, fmt, stride = fields[2], fields[3], fields[4], fields[5]
                                    mod = fields[13]

                                    # Extract FD
                                    fds = []
                                    for c, t, d in ancdata:
                                        if c == socket.SOL_SOCKET and t == socket.SCM_RIGHTS:
                                            fds.extend(struct.unpack('i'*(len(d)//4), d))

                                    if fds:
                                        if current_fd != -1: os.close(current_fd)
                                        current_fd = fds[0]

                                        # Import DMA-BUF -> EGLImage
                                        if self.egl_image: self.eglDestroyImageKHR(self.egl_display, self.egl_image)

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

                                        # Bind to GL Texture
                                        glBindTexture(GL_TEXTURE_2D, self.import_tex)
                                        self.glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, self.egl_image)

                                        # Determine Rotation (Heuristic: Width < Height usually means it's rotated)
                                        content_w, content_h = w, h
                                        self.is_rotated = False
                                        if w < h:
                                            content_w, content_h = h, w
                                            self.is_rotated = True

                                        # Check if Pipeline needs creation or resize
                                        if self.output_w != content_w or self.output_h != content_h:
                                            self.setup_fbo(content_w, content_h)
                                            self.setup_pipeline(content_w, content_h)

                                            # Update Geometry
                                            q_arr = self.calculate_quad(w, h, rotate=self.is_rotated)
                                            glBindVertexArray(self.vao)
                                            glBindBuffer(GL_ARRAY_BUFFER, self.vbo)
                                            glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(q_arr), q_arr, GL_STATIC_DRAW)
                                            glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(0))
                                            glEnableVertexAttribArray(0)
                                            glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(2 * 4))
                                            glEnableVertexAttribArray(1)

                            except Exception as e:
                                self.notify(f"Recv Error: {e}")
                                break

                        # 5. Draw & Push (If we have valid data)
                        if self.appsrc and current_fd != -1 and self.egl_image:
                            glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                            glViewport(0, 0, self.output_w, self.output_h)
                            glUseProgram(self.shader)
                            glBindVertexArray(self.vao)
                            glActiveTexture(GL_TEXTURE0)
                            glBindTexture(GL_TEXTURE_2D, self.import_tex)

                            # Draw Quad
                            glDrawArrays(GL_TRIANGLES, 0, 6)
                            glFinish()

                            # Read Pixels
                            glPixelStorei(GL_PACK_ALIGNMENT, 1)
                            pixels = glReadPixels(0, 0, self.output_w, self.output_h, GL_RGBA, GL_UNSIGNED_BYTE)

                            # Push to GStreamer
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

                        # Frame Pacing
                        elapsed = time.time() - loop_start
                        if elapsed < FRAME_INTERVAL: time.sleep(FRAME_INTERVAL - elapsed)

                finally:
                    # Cleanup loop state when App disconnects
                    if current_fd != -1: os.close(current_fd)
                    conn.close()
                    self.notify("VIDEO_STOPPED")
                    if self.pipeline:
                        self.pipeline.set_state(Gst.State.NULL)
                        self.pipeline = None
        finally:
            if self.server: self.server.close()
            if self.egl_image:
                self.eglDestroyImageKHR(self.egl_display, self.egl_image)
            glfw.terminate()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_ip", help="IP address of the Deck")
    parser.add_argument("--test-mode", action="store_true", help="Generate test pattern instead of reading socket")
    args = parser.parse_args()

    sender = VideoSender(args.target_ip)

    if args.test_mode:
        sender.run_test_mode()
    else:
        sender.run()
