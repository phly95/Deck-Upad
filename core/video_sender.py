#!/usr/bin/env python3
import sys
import os

# --- CONFIGURATION ---
# 1. Force EGL Platform for PyOpenGL BEFORE importing OpenGL
# This ensures PyOpenGL uses eglGetCurrentContext() instead of GLX/WGL
os.environ["PYOPENGL_PLATFORM"] = "egl"
# 2. Force Render Node to avoid locking the Display
os.environ["GST_VAAPI_DRM_DEVICE"] = "/dev/dri/renderD128"

import socket
import struct
import time
import argparse
import ctypes
import select
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.EGL import *
import gi

gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstVideo

SOCKET_PATH = '\0/com/DeckUpad/video'
TEX_FMT = '<BBiii4i4iQIBI65x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11
TARGET_FPS = 60
FRAME_INTERVAL = 1.0 / TARGET_FPS
FLIP_X = True
FLIP_Y = False

# Max resolution for the Deck (16:10 aspect ratio preserved via scaling)
MAX_WIDTH = 1280
MAX_HEIGHT = 800

# --- EGL CONSTANTS ---
EGL_PLATFORM_GBM_KHR = 0x31D7
EGL_LINUX_DMA_BUF_EXT = 0x3270
EGL_LINUX_DRM_FOURCC_EXT = 0x3271
EGL_DMA_BUF_PLANE0_FD_EXT = 0x3272
EGL_DMA_BUF_PLANE0_OFFSET_EXT = 0x3273
EGL_DMA_BUF_PLANE0_PITCH_EXT = 0x3274
EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT = 0x3443
EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT = 0x3444
GL_TEXTURE_EXTERNAL_OES = 0x8D65

# --- SHADERS ---
VERTEX_SHADER = """
#version 100
attribute vec2 position;
attribute vec2 texCoord;
varying vec2 TexCoord;
void main() {
    gl_Position = vec4(position, 0.0, 1.0);
    TexCoord = texCoord;
}
"""

FRAGMENT_SHADER = """
#version 100
#extension GL_OES_EGL_image_external : require
precision mediump float;
varying vec2 TexCoord;
uniform samplerExternalOES tex;
void main() {
    gl_FragColor = texture2D(tex, TexCoord);
}
"""

TEST_FRAGMENT_SHADER = """
#version 100
precision mediump float;
varying vec2 TexCoord;
uniform float time;
void main() {
    float r = 0.5 + 0.5 * sin(time + TexCoord.x * 5.0);
    float g = 0.5 + 0.5 * cos(time + TexCoord.y * 5.0);
    gl_FragColor = vec4(r, g, 0.5, 1.0);
}
"""

class VideoSenderHeadless:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.running = True

        self.drm_fd = None
        self.gbm_dev = None
        self.egl_display = EGL_NO_DISPLAY
        self.egl_context = EGL_NO_CONTEXT

        Gst.init(None)

        if not self.init_headless_egl():
            self.notify("CRASH: Failed to initialize EGL/GBM")
            sys.exit(1)

        self.init_gl()

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if not SOCKET_PATH.startswith('\0'):
            try: os.unlink(SOCKET_PATH)
            except OSError: pass

        try:
            self.server.bind(SOCKET_PATH)
        except OSError:
            self.notify("CRASH: Socket address in use")
            sys.exit(1)

        self.server.listen(1)

        self.pipeline = None
        self.appsrc = None
        self.frame_count = 0
        self.duration = Gst.util_uint64_scale_int(1, Gst.SECOND, TARGET_FPS)
        self.output_w = 0
        self.output_h = 0
        self.egl_image = None
        self.is_rotated = False
        self.use_fallback_enc = False

    def notify(self, msg):
        print(msg, flush=True)

    def init_headless_egl(self):
        try:
            self.libgbm = ctypes.CDLL('libgbm.so.1')
            self.libEGL = ctypes.CDLL('libEGL.so.1')
            self.libgbm.gbm_create_device.argtypes = [ctypes.c_int]
            self.libgbm.gbm_create_device.restype = ctypes.c_void_p

            dev = "/dev/dri/renderD128"
            try:
                self.drm_fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)
                self.notify(f"[Headless] Opened DRM render node: {dev}")
            except OSError:
                self.notify(f"[Headless] Error: Could not open {dev}.")
                return False

            self.gbm_dev = self.libgbm.gbm_create_device(self.drm_fd)
            if not self.gbm_dev: return False

            eglGetPlatformDisplayEXT = self.get_egl_proc("eglGetPlatformDisplayEXT", [ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_void_p)

            if eglGetPlatformDisplayEXT:
                self.egl_display = eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, self.gbm_dev, None)
            else:
                self.egl_display = eglGetDisplay(self.gbm_dev)

            if self.egl_display == EGL_NO_DISPLAY: return False

            major, minor = ctypes.c_int(), ctypes.c_int()
            if not eglInitialize(self.egl_display, ctypes.byref(major), ctypes.byref(minor)): return False

            eglBindAPI(EGL_OPENGL_ES_API)

            # Note: Removed EGL_PBUFFER_BIT to fix EGL_BAD_CONFIG
            config_attribs = [EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE]
            config_attribs_arr = (EGLint * len(config_attribs))(*config_attribs)

            configs = (EGLConfig * 1)()
            num_configs = EGLint()
            if not eglChooseConfig(self.egl_display, config_attribs_arr, configs, 1, ctypes.byref(num_configs)): return False

            context_attribs = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE]
            context_attribs_arr = (EGLint * len(context_attribs))(*context_attribs)

            self.egl_context = eglCreateContext(self.egl_display, configs[0], EGL_NO_CONTEXT, context_attribs_arr)
            if self.egl_context == EGL_NO_CONTEXT: return False

            # Use EGL_NO_SURFACE (Surfaceless Context)
            if not eglMakeCurrent(self.egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, self.egl_context): return False
            return True

        except Exception as e:
            self.notify(f"EGL Setup Error: {e}")
            return False

    def get_egl_proc(self, name, args, res):
        addr = eglGetProcAddress(name)
        if addr: return ctypes.CFUNCTYPE(res, *args)(addr)
        return None

    def init_gl(self):
        self.glEGLImageTargetTexture2DOES = self.get_egl_proc("glEGLImageTargetTexture2DOES", [ctypes.c_uint, ctypes.c_void_p], None)
        self.eglCreateImageKHR = self.get_egl_proc("eglCreateImageKHR", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_void_p)
        self.eglDestroyImageKHR = self.get_egl_proc("eglDestroyImageKHR", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int)

        if not self.eglCreateImageKHR or not self.glEGLImageTargetTexture2DOES:
            self.notify("CRASH: EGL Image Extensions missing")
            sys.exit(1)

        try:
            self.shader = shaders.compileProgram(shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER), shaders.compileShader(FRAGMENT_SHADER, GL_FRAGMENT_SHADER))
            self.test_shader = shaders.compileProgram(shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER), shaders.compileShader(TEST_FRAGMENT_SHADER, GL_FRAGMENT_SHADER))
        except Exception as e:
            self.notify(f"Shader Compile Error: {e}")
            sys.exit(1)

        self.vao = glGenVertexArrays(1)
        self.vbo = glGenBuffers(1)
        self.fbo = glGenFramebuffers(1)
        self.import_tex = glGenTextures(1)

        glBindTexture(GL_TEXTURE_EXTERNAL_OES, self.import_tex)
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR)

    def setup_fbo(self, w, h):
        glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
        tex = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, tex)
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, None)
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0)
        glBindFramebuffer(GL_FRAMEBUFFER, 0)
        glDeleteTextures(1, [tex])

    def create_gst_pipeline(self, width, height):
        f = Gst.ElementFactory.find

        pipeline_head = (
            f"appsrc name=src format=time is-live=true do-timestamp=false ! "
            f"video/x-raw,format=RGBA,width={width},height={height},framerate={TARGET_FPS}/1 ! "
        )

        pipeline_tail = f"rtph264pay config-interval=1 pt=96 ! udpsink host={self.target_ip} port=5000 sync=false"

        enc = ""
        # 1. Try NVIDIA NVENC
        if f("nvh264enc"):
             self.notify("--- Encoder: NVENC (NVIDIA) ---")
             enc = "videoconvert ! video/x-raw,format=NV12 ! nvh264enc preset=low-latency-hq bitrate=10000 zerolatency=true !"

        # 2. Try Modern VAAPI (gstreamer-plugin-va)
        elif f("vah264enc") and not self.use_fallback_enc:
             self.notify("--- Encoder: VAAPI (Modern vah264enc) ---")
             # FIX: Changed 'keyframe-period' to 'key-int-max'
             enc = "videoconvert ! video/x-raw,format=NV12 ! vah264enc bitrate=10000 key-int-max=60 !"

        # 3. Try Legacy VAAPI (gstreamer-vaapi)
        elif f("vaapih264enc") and not self.use_fallback_enc:
             self.notify("--- Encoder: VAAPI (Legacy vaapih264enc) ---")
             enc = "videoconvert ! video/x-raw,format=NV12 ! vaapih264enc rate-control=cbr bitrate=10000 keyframe-period=60 !"

        # 4. Try x264 (Software)
        elif f("x264enc"):
            self.notify("--- Encoder: x264 (Software) ---")
            enc = "videoconvert ! video/x-raw,format=I420 ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=5000 key-int-max=60 !"
        # 4. Try OpenH264 (Common Fallback)
        elif f("openh264enc"):
            self.notify("--- Encoder: OpenH264 (Software) ---")
            enc = "videoconvert ! video/x-raw,format=I420 ! openh264enc bitrate=5000000 !"
        # 5. Try FFmpeg/LibAV (Universal Fallback)
        elif f("avenc_h264"):
            self.notify("--- Encoder: libav/ffmpeg (Software) ---")
            enc = "videoconvert ! video/x-raw,format=I420 ! avenc_h264 bitrate=5000000 !"
        else:
            self.notify("CRITICAL: No suitable H.264 encoder found.")
            return None, None

        pipeline_str = pipeline_head + enc + pipeline_tail

        try:
            pipeline = Gst.parse_launch(pipeline_str)
            appsrc = pipeline.get_by_name("src")
            bus = pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self.on_gst_message)
            return pipeline, appsrc
        except Exception as e:
            self.notify(f"GStreamer Parse Error: {e}")
            return None, None

    def on_gst_message(self, bus, msg):
        if msg.type == Gst.MessageType.ERROR:
            err, debug = msg.parse_error()
            self.notify(f"GStreamer ERROR: {err}")
            self.notify(f"Debug info: {debug}")
            self.use_fallback_enc = True
            if self.pipeline:
                self.pipeline.set_state(Gst.State.NULL)
                self.pipeline = None

    def setup_pipeline(self, width, height):
        if self.pipeline:
            self.pipeline.set_state(Gst.State.NULL)
            self.pipeline = None

        self.output_w = width
        self.output_h = height
        self.notify(f"STREAM_RES:{width}x{height}")

        self.pipeline, self.appsrc = self.create_gst_pipeline(width, height)
        if self.pipeline:
            if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
                self.notify("Pipeline failed to start. Retrying with fallback...")
                self.use_fallback_enc = True
                self.pipeline.set_state(Gst.State.NULL)
                self.pipeline = None
            else:
                self.notify("VIDEO_STARTING")
        else:
            time.sleep(1)

        self.frame_count = 0

    def calculate_quad(self, w, h, rotate=False):
        u0, v0 = 0.0, 0.0
        u1, v1 = 1.0, 1.0
        if rotate:
            if FLIP_X: v0, v1 = v1, v0
            if FLIP_Y: u0, u1 = u1, u0
            data = [-1.0, -1.0, u1, v1, 1.0, -1.0, u1, v0, 1.0, 1.0, u0, v0, -1.0, -1.0, u1, v1, 1.0, 1.0, u0, v0, -1.0, 1.0, u0, v1]
        else:
            if FLIP_X: u0, u1 = u1, u0
            if FLIP_Y: v0, v1 = v1, v0
            data = [-1.0, -1.0, u0, v1, 1.0, -1.0, u1, v1, 1.0, 1.0, u1, v0, -1.0, -1.0, u0, v1, 1.0, 1.0, u1, v0, -1.0, 1.0, u0, v0]
        return (ctypes.c_float * len(data))(*data)

    def run_test_mode(self):
        self.notify("TEST_MODE_ACTIVE")
        W, H = 1280, 800
        self.setup_fbo(W, H)
        self.setup_pipeline(W, H)
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
                sim_time += 0.05
                if self.appsrc:
                    glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                    glViewport(0, 0, W, H)
                    glUseProgram(self.test_shader)
                    loc = glGetUniformLocation(self.test_shader, "time")
                    glUniform1f(loc, sim_time)
                    glBindVertexArray(self.vao)
                    glDrawArrays(GL_TRIANGLES, 0, 6)
                    glFinish()
                    glPixelStorei(GL_PACK_ALIGNMENT, 1)
                    pixels = glReadPixels(0, 0, W, H, GL_RGBA, GL_UNSIGNED_BYTE)
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
            self.cleanup()

    def run(self):
        self.notify("VIDEO_READY (Headless Mode)")
        try:
            while self.running:
                try: conn, _ = self.server.accept()
                except OSError: break
                self.notify("APP_CONNECTED")
                try: conn.send(struct.pack('<BBBB16s12x', 1, 0, 1, 1, b'\0'*16))
                except: conn.close(); continue
                conn.setblocking(False)
                current_fd = -1
                try:
                    while True:
                        loop_start = time.time()

                        readable, _, _ = select.select([conn], [], [], 0)

                        if readable:
                            # --- FIX 1: Restore Context AFTER select returns ---
                            if not eglMakeCurrent(self.egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, self.egl_context):
                                err = eglGetError()
                                self.notify(f"WARNING: Context Lost in Loop! Error: {err}")
                            # ---------------------------------------------------

                            try:
                                data, ancdata, _, _ = conn.recvmsg(TEX_SIZE, socket.CMSG_LEN(struct.calcsize('i') * 4))
                                if not data: self.notify("Socket Closed by Peer"); break
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
                                        if self.egl_image: self.eglDestroyImageKHR(self.egl_display, self.egl_image)
                                        attribs = [EGL_WIDTH, w, EGL_HEIGHT, h, EGL_LINUX_DRM_FOURCC_EXT, fmt, EGL_DMA_BUF_PLANE0_FD_EXT, current_fd, EGL_DMA_BUF_PLANE0_OFFSET_EXT, 0, EGL_DMA_BUF_PLANE0_PITCH_EXT, stride, EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT, mod & 0xFFFFFFFF, EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT, (mod >> 32) & 0xFFFFFFFF, EGL_NONE]
                                        attr = (ctypes.c_int * len(attribs))(*attribs)
                                        self.egl_image = self.eglCreateImageKHR(self.egl_display, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, None, attr)
                                        glActiveTexture(GL_TEXTURE0)
                                        glBindTexture(GL_TEXTURE_EXTERNAL_OES, self.import_tex)
                                        self.glEGLImageTargetTexture2DOES(GL_TEXTURE_EXTERNAL_OES, self.egl_image)
                                        content_w, content_h = w, h
                                        self.is_rotated = False
                                        if w < h:
                                            content_w, content_h = h, w
                                            self.is_rotated = True

                                        # --- SCALING LOGIC ---
                                        scale_factor = 1.0
                                        if content_w > MAX_WIDTH or content_h > MAX_HEIGHT:
                                            scale_factor = min(MAX_WIDTH / content_w, MAX_HEIGHT / content_h)

                                        target_w = int(content_w * scale_factor)
                                        target_h = int(content_h * scale_factor)

                                        # Ensure even dimensions
                                        if target_w % 2 != 0: target_w -= 1
                                        if target_h % 2 != 0: target_h -= 1
                                        target_w = max(2, target_w)
                                        target_h = max(2, target_h)
                                        # ---------------------

                                        if self.output_w != target_w or self.output_h != target_h:
                                            self.setup_fbo(target_w, target_h)
                                            self.setup_pipeline(target_w, target_h)
                                            q_arr = self.calculate_quad(w, h, rotate=self.is_rotated)
                                            glBindVertexArray(self.vao)
                                            glBindBuffer(GL_ARRAY_BUFFER, self.vbo)
                                            glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(q_arr), q_arr, GL_STATIC_DRAW)
                                            glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(0))
                                            glEnableVertexAttribArray(0)
                                            glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * 4, ctypes.c_void_p(2 * 4))
                                            glEnableVertexAttribArray(1)
                            except Exception as e:
                                self.notify(f"Recv Error: {e}"); break

                        if self.pipeline is None and self.output_w > 0: self.setup_pipeline(self.output_w, self.output_h)

                        if self.appsrc and current_fd != -1 and self.egl_image:
                            # --- FIX 2: Restore Context Before Rendering ---
                            if not eglMakeCurrent(self.egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, self.egl_context):
                                err = eglGetError()
                                self.notify(f"WARNING: Context Lost before Render! Error: {err}")
                            # -----------------------------------------------

                            glBindFramebuffer(GL_FRAMEBUFFER, self.fbo)
                            glViewport(0, 0, self.output_w, self.output_h)
                            glUseProgram(self.shader)
                            glActiveTexture(GL_TEXTURE0)
                            glBindTexture(GL_TEXTURE_EXTERNAL_OES, self.import_tex)
                            glBindVertexArray(self.vao)
                            glDrawArrays(GL_TRIANGLES, 0, 6)
                            glFinish()
                            glPixelStorei(GL_PACK_ALIGNMENT, 1)
                            pixels = glReadPixels(0, 0, self.output_w, self.output_h, GL_RGBA, GL_UNSIGNED_BYTE)
                            buf = Gst.Buffer.new_wrapped(pixels)
                            GstVideo.buffer_add_video_meta_full(buf, GstVideo.VideoFrameFlags.NONE, GstVideo.VideoFormat.RGBA, self.output_w, self.output_h, 1, [0, 0, 0, 0], [self.output_w * 4, 0, 0, 0])
                            pts = self.frame_count * self.duration
                            buf.pts = pts; buf.dts = pts; buf.duration = self.duration
                            self.frame_count += 1
                            self.appsrc.emit("push-buffer", buf)
                            glBindFramebuffer(GL_FRAMEBUFFER, 0)

                        elapsed = time.time() - loop_start
                        if elapsed < FRAME_INTERVAL: time.sleep(FRAME_INTERVAL - elapsed)
                finally:
                    if current_fd != -1: os.close(current_fd)
                    conn.close()
                    self.notify("VIDEO_STOPPED")
                    self.output_w = 0
                    self.output_h = 0
                    if self.pipeline:
                        self.pipeline.set_state(Gst.State.NULL)
                        self.pipeline = None
        finally:
            self.cleanup()

    def cleanup(self):
        if self.server: self.server.close()
        if self.egl_image and self.eglDestroyImageKHR: self.eglDestroyImageKHR(self.egl_display, self.egl_image)
        if self.egl_display != EGL_NO_DISPLAY: eglTerminate(self.egl_display)
        if self.drm_fd: os.close(self.drm_fd)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_ip", help="IP address of the Deck")
    parser.add_argument("--test-mode", action="store_true", help="Generate test pattern")
    args = parser.parse_args()

    sender = VideoSenderHeadless(args.target_ip)
    if args.test_mode: sender.run_test_mode()
    else: sender.run()
