import socket
import struct
import os
import sys
import ctypes
import select
import glfw
import mmap
import fcntl
import gc
import time
from OpenGL.GL import *
from OpenGL.GL import shaders
from OpenGL.EGL import *

# --- Constants ---
SOCKET_PATH = '\0/com/obsproject/vkcapture'
TEX_FMT = '<BBiii4i4iQIBI65x'
TEX_SIZE = 128
# Handshake: capturing(1), no_mods(0), linear(1), map_host(0)
CTRL_FMT = '<BBBB16s12x'

# Packet Types
PACKET_TYPE_CLIENT = 10
PACKET_TYPE_TEXTURE = 11

# DMA Sync
DMA_BUF_IOCTL_SYNC = 0x40086200
DMA_BUF_SYNC_READ = 1
DMA_BUF_SYNC_START = 0
DMA_BUF_SYNC_END = 4

# EGL
EGL_LINUX_DMA_BUF_EXT = 0x3270
EGL_LINUX_DRM_FOURCC_EXT = 0x3271
EGL_DMA_BUF_PLANE0_FD_EXT = 0x3272
EGL_DMA_BUF_PLANE0_OFFSET_EXT = 0x3273
EGL_DMA_BUF_PLANE0_PITCH_EXT = 0x3274
EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT = 0x3443
EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT = 0x3444

VERTEX_SHADER = """
#version 330
layout(location = 0) in vec2 position;
layout(location = 1) in vec2 texCoord;
out vec2 TexCoord;
void main() {
    gl_Position = vec4(position, 0.0, 1.0);
    TexCoord = texCoord;
}
"""

FRAGMENT_SHADER = """
#version 330
in vec2 TexCoord;
out vec4 color;
uniform sampler2D tex;
void main() {
    vec4 c = texture(tex, TexCoord);
    color = vec4(c.r, c.g, c.b, 1.0);
}
"""

def dma_sync(fd, flags):
    try:
        sync_args = struct.pack('Q', flags)
        fcntl.ioctl(fd, DMA_BUF_IOCTL_SYNC, sync_args)
    except OSError: pass

class VkCaptureViewer:
    def __init__(self):
        self.server = None
        self.conn = None
        self.current_fd = None
        self.texture_id = None
        self.egl_image = None
        self.width = 640
        self.height = 480
        self.connected = False
        self.window = None
        self.shader = None
        self.vao = None
        self.egl_display = EGL_NO_DISPLAY
        self.fallback_mode = False
        self.mapped_buf = None
        self.mapped_ptr = None

        # Extensions
        self.glEGLImageTargetTexture2DOES = None
        self.eglCreateImageKHR = None
        self.eglDestroyImageKHR = None

    def get_extension_func(self, name, argtypes, restype=None):
        address = glfw.get_proc_address(name)
        if not address: return None
        proto = ctypes.CFUNCTYPE(restype, *argtypes)
        return proto(address)

    def init_window(self):
        if not glfw.init(): raise Exception("GLFW init failed")

        glfw.window_hint(glfw.CONTEXT_CREATION_API, glfw.EGL_CONTEXT_API)
        glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
        glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
        glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)

        self.window = glfw.create_window(self.width, self.height, "VkCapture Viewer", None, None)
        if not self.window:
            glfw.terminate()
            raise Exception("Window creation failed")

        glfw.make_context_current(self.window)

        self.glEGLImageTargetTexture2DOES = self.get_extension_func(
            "glEGLImageTargetTexture2DOES", [ctypes.c_uint, ctypes.c_void_p])
        self.eglCreateImageKHR = self.get_extension_func(
            "eglCreateImageKHR",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)],
            ctypes.c_void_p)
        self.eglDestroyImageKHR = self.get_extension_func(
            "eglDestroyImageKHR", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int)

        self.egl_display = eglGetCurrentDisplay()
        if self.egl_display == EGL_NO_DISPLAY:
            self.egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY)
            if not eglInitialize(self.egl_display, None, None):
                print("EGL Init failed. Using software fallback.")
                self.fallback_mode = True

        self.init_gl()

    def init_gl(self):
        self.shader = shaders.compileProgram(
            shaders.compileShader(VERTEX_SHADER, GL_VERTEX_SHADER),
            shaders.compileShader(FRAGMENT_SHADER, GL_FRAGMENT_SHADER)
        )

        vertices = [-1.0, -1.0, 0.0, 1.0,  1.0, -1.0, 1.0, 1.0,
                     1.0,  1.0, 1.0, 0.0, -1.0,  1.0, 0.0, 0.0]
        indices = [0, 1, 2, 2, 3, 0]

        vertices_array = (ctypes.c_float * len(vertices))(*vertices)
        indices_array = (ctypes.c_uint * len(indices))(*indices)

        self.vao = glGenVertexArrays(1)
        glBindVertexArray(self.vao)

        vbo = glGenBuffers(1)
        glBindBuffer(GL_ARRAY_BUFFER, vbo)
        glBufferData(GL_ARRAY_BUFFER, ctypes.sizeof(vertices_array), vertices_array, GL_STATIC_DRAW)

        ebo = glGenBuffers(1)
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ebo)
        glBufferData(GL_ELEMENT_ARRAY_BUFFER, ctypes.sizeof(indices_array), indices_array, GL_STATIC_DRAW)

        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * ctypes.sizeof(ctypes.c_float), ctypes.c_void_p(0))
        glEnableVertexAttribArray(0)
        glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * ctypes.sizeof(ctypes.c_float), ctypes.c_void_p(2 * ctypes.sizeof(ctypes.c_float)))
        glEnableVertexAttribArray(1)

        self.texture_id = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, self.texture_id)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)
        glDisable(GL_BLEND)

    def init_socket(self):
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.setblocking(False)
        try:
            self.server.bind(SOCKET_PATH)
        except OSError: pass
        self.server.listen(1)
        print("Listening for obs-vkcapture...")

    def resize_window(self, w, h):
        if w != self.width or h != self.height:
            print(f"Resizing to: {w}x{h}")
            self.width = w
            self.height = h
            glfw.set_window_size(self.window, w, h)
            glViewport(0, 0, w, h)

    def release_buffer(self):
        if self.mapped_ptr is not None:
            del self.mapped_ptr
            self.mapped_ptr = None
        gc.collect()
        if self.mapped_buf is not None:
            try: self.mapped_buf.close()
            except BufferError: pass
            self.mapped_buf = None

    def update_texture(self, fd, width, height, stride, fmt, modifier):
        self.resize_window(width, height)
        if self.egl_image:
            self.eglDestroyImageKHR(self.egl_display, self.egl_image)
            self.egl_image = None

        self.release_buffer()

        if not self.fallback_mode and self.eglCreateImageKHR:
            attribs = [
                EGL_WIDTH, width, EGL_HEIGHT, height,
                EGL_LINUX_DRM_FOURCC_EXT, fmt,
                EGL_DMA_BUF_PLANE0_FD_EXT, fd,
                EGL_DMA_BUF_PLANE0_OFFSET_EXT, 0,
                EGL_DMA_BUF_PLANE0_PITCH_EXT, stride,
            ]

            # ONLY add modifier if it is valid (not 0x00ffffffffffffff)
            # DRM_FORMAT_MOD_INVALID is ((1ULL << 56) - 1)
            if modifier != 0x00ffffffffffffff:
                mod_hi = (modifier >> 32) & 0xFFFFFFFF
                mod_lo = modifier & 0xFFFFFFFF
                attribs.extend([
                    EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT, mod_lo,
                    EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT, mod_hi,
                ])

            attribs.append(EGL_NONE)

            attrib_array = (ctypes.c_int * len(attribs))(*attribs)
            self.egl_image = self.eglCreateImageKHR(
                self.egl_display, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, None, attrib_array
            )

            if self.egl_image:
                glBindTexture(GL_TEXTURE_2D, self.texture_id)
                self.glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, self.egl_image)
                return
            else:
                print("EGLImage creation failed. Modifiers might be incompatible.")
                self.fallback_mode = True

    def update_frame_software(self):
        if self.fallback_mode and self.mapped_buf and self.current_fd:
             try:
                dma_sync(self.current_fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ)
                glBindTexture(GL_TEXTURE_2D, self.texture_id)
                glPixelStorei(GL_UNPACK_ROW_LENGTH, 0)
                if self.mapped_ptr:
                    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, self.width, self.height, GL_BGRA, GL_UNSIGNED_BYTE, self.mapped_ptr)
                else:
                    self.mapped_buf.seek(0)
                    data = self.mapped_buf.read()
                    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, self.width, self.height, GL_BGRA, GL_UNSIGNED_BYTE, data)
                dma_sync(self.current_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ)
             except Exception: pass

    def handle_socket(self):
        readers = [self.server]
        if self.conn: readers.append(self.conn)
        readable, _, _ = select.select(readers, [], [], 0)

        for s in readable:
            if s is self.server:
                # Accept new connection
                new_conn, _ = self.server.accept()
                print("Game Connected.")
                if self.conn: self.conn.close()
                self.conn = new_conn
                self.conn.setblocking(False) # NON-BLOCKING for drain loop
                self.connected = True
                try: self.conn.send(struct.pack(CTRL_FMT, 1, 0, 1, 0, b'\0'*16))
                except BrokenPipeError: self.reset_connection("Handshake Failed")

            elif s is self.conn:
                # DRAIN LOOP: Read ALL packets available
                while True:
                    try:
                        data, ancdata, _, _ = self.conn.recvmsg(
                            TEX_SIZE, socket.CMSG_SPACE(struct.calcsize('i') * 4)
                        )
                    except BlockingIOError:
                        # Buffer Empty - We are done for this tick
                        break
                    except (OSError, ConnectionResetError):
                        self.reset_connection("Remote Error")
                        break

                    if not data:
                        self.reset_connection("Remote Closed")
                        break

                    if len(data) < TEX_SIZE:
                        continue # Skip partial packets

                    pkt_type = data[0]
                    if pkt_type == PACKET_TYPE_CLIENT:
                        continue # Ignore metadata

                    # Process Texture Packet
                    try:
                        fields = struct.unpack(TEX_FMT, data)
                        w, h, fmt, stride, mod = fields[2], fields[3], fields[4], fields[5], fields[13]
                        fds = []
                        for c, t, d in ancdata:
                            if c == socket.SOL_SOCKET and t == socket.SCM_RIGHTS:
                                fds.extend(struct.unpack('i'*(len(d)//4), d))

                        if fds:
                            if self.current_fd: os.close(self.current_fd)
                            self.current_fd = fds[0]
                            self.update_texture(self.current_fd, w, h, stride, fmt, mod)
                        # Note: We update texture state here, but drawing happens in main loop
                    except struct.error:
                        continue

    def reset_connection(self, reason="Unknown"):
        print(f"Resetting connection: {reason}")
        if self.conn: self.conn.close()
        self.conn = None; self.connected = False
        if self.current_fd: os.close(self.current_fd); self.current_fd = None
        self.fallback_mode = False
        self.release_buffer()

    def run(self):
        self.init_window(); self.init_socket()
        try:
            while not glfw.window_should_close(self.window):
                self.handle_socket()
                if self.fallback_mode and self.connected:
                    self.update_frame_software()

                glClearColor(0.2, 0.2, 0.2, 1.0)
                glClear(GL_COLOR_BUFFER_BIT)
                if self.connected and self.texture_id:
                    glUseProgram(self.shader)
                    glBindVertexArray(self.vao)
                    glBindTexture(GL_TEXTURE_2D, self.texture_id)
                    glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, None)
                glfw.swap_buffers(self.window)
                glfw.poll_events()
        finally: self.cleanup()

    def cleanup(self):
        self.release_buffer()
        if self.conn: self.conn.close()
        self.server.close()
        if self.current_fd: os.close(self.current_fd)
        glfw.terminate()

if __name__ == "__main__":
    VkCaptureViewer().run()
