import socket
import struct
import mmap
import os
import fcntl
import numpy as np
import cv2
import select
import gc
import argparse
import sys

# --- Constants ---
SOCKET_PATH = '\0/com/obsproject/vkcapture'
CTRL_FMT = '<BBBB16s12x'
TEX_FMT = '<BBiii4i4iQIBI65x'
TEX_SIZE = 128
TYPE_TEXTURE_DATA = 11

DMA_BUF_IOCTL_SYNC = 0x40086200
DMA_BUF_SYNC_READ = 1
DMA_BUF_SYNC_START = 0
DMA_BUF_SYNC_END = 4

def dma_sync(fd, flags):
    try:
        sync_args = struct.pack('Q', flags)
        fcntl.ioctl(fd, DMA_BUF_IOCTL_SYNC, sync_args)
    except OSError:
        pass

def parse_arguments():
    parser = argparse.ArgumentParser(description="View obs-vkcapture output, optionally split into regions.")
    parser.add_argument(
        '-r', '--region',
        action='append',
        help='Define a region window in format x,y,w,h (e.g., -r 0,0,1920,1080). Can be used multiple times.'
    )
    return parser.parse_args()

def cleanup_views(raw, img, crop, mapped_buf, fd):
    """
    Helper to safely destroy numpy views and close buffers.
    Must completely release buffer references before closing mmap.
    """
    # 1. Delete NumPy views
    # Assigning None drops the reference
    crop = None
    img = None
    raw = None

    # 2. Force Garbage Collection
    # This ensures the buffer exports in C-land are actually released
    # so that mmap can be closed without BufferError.
    del crop
    del img
    del raw
    gc.collect()

    # 3. Close Map and FD
    if mapped_buf:
        try:
            mapped_buf.close()
        except (ValueError, BufferError):
            pass

    if fd:
        try:
            os.close(fd)
        except OSError:
            pass

    return None, None, None, None, None # return Nones to reset state vars

def main():
    args = parse_arguments()

    # Parse regions
    regions = []
    if args.region:
        for r_str in args.region:
            try:
                x, y, w, h = map(int, r_str.split(','))
                regions.append({'x': x, 'y': y, 'w': w, 'h': h})
            except ValueError:
                print(f"Error: Invalid region format '{r_str}'. Expected x,y,w,h")
                sys.exit(1)

    show_full_window = len(regions) == 0

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.setblocking(False)
    try:
        server.bind(SOCKET_PATH)
    except OSError as e:
        print(f"Error binding socket: {e}")
        return
    server.listen(1)

    print(f"Viewer started.")
    if show_full_window:
        print("Mode: Full Capture")
    else:
        print(f"Mode: {len(regions)} Custom Region(s)")
    print("Waiting for game...")

    # State variables
    conn = None
    mapped_buf = None
    current_fd = None
    width, height, stride = 0, 0, 0

    # Views (Must be tracked to prevent BufferErrors on resize)
    raw = None
    img = None
    crop = None

    try:
        while True:
            readers = [server]
            if conn:
                readers.append(conn)

            readable, _, _ = select.select(readers, [], [], 0.01)

            for s in readable:
                if s is server:
                    # --- NEW CONNECTION (RESTART) ---
                    new_conn, _ = server.accept()
                    print("Game connected!")

                    # Clean up previous connection completely
                    if conn:
                        conn.close()
                        raw, img, crop, mapped_buf, current_fd = cleanup_views(raw, img, crop, mapped_buf, current_fd)
                        width, height = 0, 0

                    conn = new_conn
                    conn.setblocking(True)

                    try:
                        msg = struct.pack(CTRL_FMT, 1, 0, 1, 1, b'\0'*16)
                        conn.send(msg)
                    except BrokenPipeError:
                        conn = None
                        print("Handshake failed.")

                elif s is conn:
                    # --- DATA FROM GAME ---
                    try:
                        data, ancdata, flags, addr = conn.recvmsg(TEX_SIZE, socket.CMSG_LEN(struct.calcsize('i') * 4))

                        if not data:
                            print("Game disconnected.")
                            conn.close()
                            conn = None
                            raw, img, crop, mapped_buf, current_fd = cleanup_views(raw, img, crop, mapped_buf, current_fd)
                            width, height = 0, 0
                            continue

                        if data[0] == TYPE_TEXTURE_DATA and len(data) == TEX_SIZE:
                            fields = struct.unpack(TEX_FMT, data)
                            new_w, new_h, new_stride = fields[2], fields[3], fields[5]

                            fds = []
                            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                                if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                                    fds.extend(struct.unpack('i' * (len(cmsg_data) // 4), cmsg_data))

                            if fds:
                                # --- RESIZE EVENT ---
                                # 1. Close old FD/Map first (must release views first)
                                if current_fd:
                                    os.close(current_fd)
                                    current_fd = None

                                # Explicit cleanup of numpy views before re-mapping
                                raw, img, crop, mapped_buf, _ = cleanup_views(raw, img, crop, mapped_buf, None)

                                # 2. Map new FD
                                current_fd = fds[0]
                                try:
                                    size = os.lseek(current_fd, 0, os.SEEK_END)
                                    os.lseek(current_fd, 0, os.SEEK_SET)
                                    mapped_buf = mmap.mmap(current_fd, size, mmap.MAP_SHARED, mmap.PROT_READ)
                                    width, height, stride = new_w, new_h, new_stride
                                    print(f"Texture update: {width}x{height}")
                                except OSError as e:
                                    print(f"Failed to map new texture: {e}")
                                    if current_fd: os.close(current_fd)
                                    current_fd = None

                    except (ConnectionResetError, BrokenPipeError):
                        print("Connection lost.")
                        conn.close()
                        conn = None
                        raw, img, crop, mapped_buf, current_fd = cleanup_views(raw, img, crop, mapped_buf, current_fd)

            # --- RENDER FRAME ---
            if conn and mapped_buf and width > 0 and height > 0:
                try:
                    dma_sync(current_fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ)

                    # Re-create raw view every frame (cheap) to ensure validity
                    raw = np.frombuffer(mapped_buf, dtype=np.uint8)
                    expected_size = stride * height

                    if raw.size >= expected_size:
                        # Construct main image view
                        img = raw[:expected_size].reshape((height, stride))
                        img = img[:, :width*4]
                        img = img.reshape((height, width, 4))

                        # Note: Vulkan capture is usually BGRA. OpenCV expects BGR(A).
                        # No conversion needed usually.

                        if show_full_window:
                            cv2.imshow("OBS VkCapture - Full", img)
                        else:
                            for idx, reg in enumerate(regions):
                                rx, ry, rw, rh = reg['x'], reg['y'], reg['w'], reg['h']

                                # Bounds Checking
                                start_y = max(0, min(ry, height))
                                end_y = max(0, min(ry + rh, height))
                                start_x = max(0, min(rx, width))
                                end_x = max(0, min(rx + rw, width))

                                if end_x > start_x and end_y > start_y:
                                    # Create the view
                                    crop = img[start_y:end_y, start_x:end_x]
                                    cv2.imshow(f"Region {idx+1} ({rx},{ry})", crop)

                    dma_sync(current_fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ)

                except ValueError:
                    # Handle resize race conditions (buffer size mismatch)
                    pass
                except OSError:
                    pass

            # GUI Loop
            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                break

    except KeyboardInterrupt:
        pass
    finally:
        cleanup_views(raw, img, crop, mapped_buf, current_fd)
        if conn: conn.close()
        server.close()
        cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
