import subprocess
import os
import sys
import time
import threading

# Configuration
CONTAINER_NAME = "video-sender"
IMAGE_NAME = "video-sender-ready"
BASE_IMAGE = "registry.fedoraproject.org/fedora:43"

class VideoSenderManager:
    def __init__(self):
        self.proc = None

    def _run_cmd(self, cmd_list, description):
        """Helper to run commands and capture output for debugging."""
        print(f"   > {description}...")
        try:
            res = subprocess.run(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            if res.returncode != 0:
                error_msg = (
                    f"\n[!!!] COMMAND FAILED: {description}\n"
                    f"EXIT CODE: {res.returncode}\n"
                    f"--- OUTPUT START ---\n"
                    f"{res.stdout}\n"
                    f"--- OUTPUT END ---\n"
                )
                raise Exception(error_msg)
            return res.stdout
        except OSError as e:
            raise Exception(f"Failed to execute command: {e}")

    def ensure_image_exists(self):
        # Check if image exists
        res = subprocess.run(["podman", "images", "-q", IMAGE_NAME], stdout=subprocess.PIPE, text=True)
        if res.stdout.strip():
            return

        print(f"[SenderMgr] Building {IMAGE_NAME} (Internet Required)...")
        builder = f"{CONTAINER_NAME}-builder"

        try:
            subprocess.run(["podman", "rm", "-f", builder], stderr=subprocess.DEVNULL)

            # Start builder
            self._run_cmd(
                ["podman", "run", "-d", "--name", builder, BASE_IMAGE, "sleep", "infinity"],
                "Starting Base Container"
            )

            # FIX FOR STEAMOS: Disable zchunk to prevent disk space errors
            self._run_cmd(
                ["podman", "exec", builder, "/bin/bash", "-c", "echo zchunk=False >> /etc/dnf/dnf.conf && dnf clean all"],
                "Configuring DNF for limited storage"
            )

            # Install RPM Fusion
            rpm_fusion_cmd = (
                "dnf install -y "
                "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm "
                "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm"
            )
            self._run_cmd(
                ["podman", "exec", builder, "sh", "-c", rpm_fusion_cmd],
                "Enabling RPM Fusion Repos"
            )

            # Refresh Metadata
            self._run_cmd(
                ["podman", "exec", builder, "dnf", "update", "-y"],
                "Updating DNF Metadata"
            )

            # Install Deps
            # Added: libva-utils (for vainfo debugging)
            deps = [
                "python3", "python3-pip",
                "mesa-dri-drivers",
                "mesa-va-drivers-freeworld", # <--- FIX: Use Freeworld driver for H.264
                "intel-media-driver",
                "libgbm", "libglvnd-egl",
                "gstreamer1", "gstreamer1-plugins-base", "gstreamer1-plugins-good",
                "gstreamer1-plugins-bad-free", "gstreamer1-plugins-ugly",
                "gstreamer1-libav",
                "gstreamer1-vaapi",
                "python3-gobject", "procps-ng", "python3-numpy",
                "libva-utils"
            ]

            # Added --setopt=install_weak_deps=False
            install_cmd = ["podman", "exec", builder, "dnf", "install", "-y", "--setopt=install_weak_deps=False", "--allowerasing", "--skip-broken"] + deps
            self._run_cmd(install_cmd, "Installing Packages")

            # Install PyOpenGL
            self._run_cmd(
                ["podman", "exec", builder, "pip", "install", "PyOpenGL"],
                "Installing Python Libs"
            )

            # Commit
            self._run_cmd(
                ["podman", "commit", builder, IMAGE_NAME],
                "Saving Image"
            )

        except Exception as e:
            print(f"[SenderMgr] Build Error: {e}")
            subprocess.run(["podman", "stop", builder], stderr=subprocess.DEVNULL)
            raise e
        finally:
            subprocess.run(["podman", "rm", "-f", builder], stderr=subprocess.DEVNULL)

    def start(self, target_ip, test_mode=False):
        self.stop()

        script_path = os.path.abspath("core/video_sender.py")

        env_vars = []
        for key in ["LIBVA_DRIVER_NAME", "NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES"]:
            if key in os.environ:
                env_vars.extend(["-e", f"{key}={os.environ[key]}"])

        # Auto-detect driver
        if "LIBVA_DRIVER_NAME" not in os.environ:
            try:
                if os.path.exists("/sys/class/drm/card0/device/vendor"):
                    with open("/sys/class/drm/card0/device/vendor", "r") as f:
                        vendor = f.read().strip()
                    if vendor == "0x1002":
                        print("[SenderMgr] Detected AMD GPU (forcing radeonsi)")
                        env_vars.extend(["-e", "LIBVA_DRIVER_NAME=radeonsi"])
                    elif vendor == "0x8086":
                        print("[SenderMgr] Detected Intel GPU (forcing iHD)")
                        env_vars.extend(["-e", "LIBVA_DRIVER_NAME=iHD"])
            except: pass

        # FIX: Add --tmpfs /tmp and direct GStreamer cache there
        cmd = [
            "podman", "run", "--rm", "--replace",
            "--name", CONTAINER_NAME,
            "--net=host",
            "--privileged",

            # --- FIX: SECURITY & DEVICES ---
            "--security-opt", "label=disable",  # Disable SELinux isolation
            "--device", "/dev/dri",             # Map all DRI devices recursively

            # Map /tmp to RAM to avoid /var writes
            "--tmpfs", "/tmp",
            "-e", "XDG_CACHE_HOME=/tmp/.cache",

            "-v", "/dev/dri:/dev/dri",
            "-v", f"{script_path}:/app/sender.py",
        ] + env_vars + [
            IMAGE_NAME,
            "sh", "-c",
            # We run 'vainfo' first to debug the driver state, then run the python script
            "echo '--- VAINFO DEBUG ---'; vainfo; echo '--------------------'; "
            "python3 -u /app/sender.py " + target_ip + (" --test-mode" if test_mode else "")
        ]

        print(f"[SenderMgr] Launching Container for Target: {target_ip}")

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        return self.proc

    def stop(self):
        if self.proc:
            self.proc.terminate()
        subprocess.run(["podman", "rm", "-f", CONTAINER_NAME], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
