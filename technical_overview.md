# Low-Latency Containerized Network Stack for Real-Time Device Communication

## Summary

This reference implementation demonstrates a novel architecture for achieving deterministic, low-latency performance on general-purpose Linux systems. This needed to be developed for the "Deck-Upad" project—a system enabling real-time dual-screen emulation over consumer Wi-Fi—the architecture addresses critical challenges in industrial control systems, remote telemetry, and edge computing.

By leveraging **container-based network namespace isolation**, **hybrid virtualization for hardware passthrough**, and **hardware-accelerated media pipelines**, the system aims to eliminate the unpredictable latency spikes common in standard OS network stacks. The architecture is designed to support low-latency P2P communication, hardware-accelerated 60fps video transmission, and high-frequency input polling, even when operating alongside standard internet traffic.

---

## 1. Problem Statement

Standard Linux network stacks prioritize connectivity and throughput over latency stability. Background processes—such as NetworkManager scans, DHCP renewals, and OS-level power management—introduce unpredictable jitter. For real-time applications like this very project, as well as remote machine operation or cloud gaming, a latency spike of 100ms is a functional failure.

Furthermore, managing exclusive hardware access (such as Wi-Fi cards or USB controllers) usually requires deep system integration, creating dependency conflicts and reducing portability. This project demonstrates a **Containerized Hardware Management** pattern that isolates these resources, preventing the host OS from interfering with critical communication paths while maintaining system manageability.

---

## 2. Technical Architecture

The architecture is composed of four distinct subsystems, each handling a critical aspect of real-time communication: Network Isolation, Peripheral Virtualization, Media Streaming, and Coordinate Transformation.

### 2.1 Network Namespace Isolation & Traffic Shaping

The core innovation lies in `wifi_container.py`, which implements a pattern for dedicating physical network hardware to latency-sensitive applications.

* **Physical Interface Migration:** The system identifies the physical Wi-Fi interface (PHY) and migrates it entirely out of the host's network namespace and into a privileged container using `iw phy set netns`. This makes the hardware invisible to the host OS, preventing background scanning or power-save operations from causing jitter.
* **VETH Bridge Construction:** Connectivity is restored via a high-speed Virtual Ethernet (VETH) pair (`veth-host` <-> `veth-ctr`), creating a dedicated 10Gbps virtual link between the host and the container.
* **Active Queue Management (AQM):** Inside the isolated namespace, the system applies **FQ_CoDel** (Fair Queuing Controlled Delay) to the wireless interface using `tc qdisc`. This algorithm actively manages bufferbloat, ensuring that bulk data transfers (like a background download) do not degrade the latency of control packets.
* **Power Management Override:** The container explicitly disables hardware power-save modes (`iw dev wlan0 set power_save off`), a common source of micro-stutter in wireless links.

### 2.2 Containerized Peripheral Virtualization

The `usbip_container.py` module solves the problem of sharing physical input devices over a network without installing kernel modules directly on the host or requiring complex driver stacks.

* **Sidecar Architecture:** A "sidecar" container holds the user-space tools (`usbip-utils`), while mounting `/sys` and `/lib/modules` to interact with the host kernel. This keeps the host OS clean while allowing low-level hardware manipulation.
* **Hybrid Device Discovery:** The system implements a unique discovery mechanism. Because containers have limited visibility into host udev events, the script scans the host’s `/sys/bus/usb/devices` directly to identify the target controller (e.g., Valve's "Neptune" controller, VID `28de`). It then instructs the container to bind that specific Bus ID to the USB/IP subsystem.
* **Resilience (WIP):** While the system supports manual attachment of remote devices, work is currently underway on an auto-reconnect agent (`usbip-keepalive.sh`) to automatically restore dropped connections. *Note: This feature is currently in development and not yet fully functional.*

### 2.3 Low-Latency Media Pipeline

Video transmission is handled by a highly optimized GStreamer pipeline orchestrated by `sender.py` (Source) and `receiver.py` (Sink).

* **Zero-Copy Capture:** The system uses `PipeWire` for screen capture, feeding directly into the GStreamer pipeline. This minimizes CPU usage by keeping frame buffers in GPU memory where possible.
* **Hardware Encoding:** The pipeline dynamically selects the best available hardware encoder (`nvh264enc` for NVIDIA, `vaapih264enc` for VAAPI) and applies "ultrafast" and "zerolatency" tuning presets to minimize the encoding buffer window.
* **Jitter Buffering:** On the receiver side, a minimal jitter buffer (`rtpjitterbuffer latency=0`) allows for immediate frame rendering, trading minor packet loss for absolute lowest latency.

### 2.4 Coordinate Transformation Engine

The `receiver.py` module implements a robust input transformation layer capable of mapping inputs across heterogeneous display configurations.

* **Aspect Ratio Normalization:** The system calculates the aspect ratio of both the local window and the remote source. It automatically applies letterbox/pillarbox offsets to the raw input coordinates, ensuring that a touch event on the receiver maps precisely to the correct pixel on the sender, regardless of resolution differences.
* **High-Frequency Polling:** To match the responsiveness of local hardware, the input worker loop operates at approximately **240Hz** (~4.1ms interval), aggregating motion events to prevent network saturation while maintaining high-fidelity control.
* **Virtual Injection:** Normalized coordinates are transmitted via UDP to the host, where a `UInput` virtual device injects them directly into the kernel subsystem as native input events.

---

## 3. Performance Characteristics

Empirical testing of the Deck-Upad implementation yields the following performance metrics:

* **Network Latency:** P2P Round-Trip Time (RTT) is typically **2–5 ms** over standard Wi-Fi hardware.
* **Latency Stability:** The isolated network stack effectively mitigates jitter during bandwidth contention. During active internet speed tests running through the repeater, latency peaks remain controlled at approximately **12 ms**.
* **Input Fidelity:** 240Hz input sampling rate with sub-pixel mapping accuracy.
* **Video Performance:** 60 FPS stable stream at native resolutions (1280x800) using hardware-accelerated H.264.

---

## 4. Operational Considerations & Constraints

While the architecture provides significant latency benefits, deployment in "Repeater Mode" requires careful spectrum management.

* **Spectrum Usage:** The Repeater Mode functionality creates a secondary Access Point on the same physical interface. In dense wireless environments (e.g., apartment buildings), this aggressive use of airtime may cause interference for other devices operating on the same channel.
* **User Discretion:** It is recommended that operators manually select uncongested channels or utilize 5GHz/6GHz bands where available to minimize impact on neighboring networks.

---

## 5. Industrial & Edge Applications

While the reference implementation targets consumer hardware, the underlying architectural patterns are directly applicable to industrial and enterprise scenarios.

| Component | Potential Application | Benefit |
| --- | --- | --- |
| **Network Isolation** | **SCADA / Process Control** | Prevents OS-level background tasks from causing jitter in safety-critical control loops. |
| **Containerized USB/IP** | **Remote Instrumentation** | Allows centralized servers to access distributed USB sensors (e.g., oscilloscopes, medical devices) without driver installation on the collector nodes. |
| **Hybrid Discovery** | **Fleet Management** | Enables "universal" containers that can dynamically identify and bind to varying hardware peripherals across a heterogeneous fleet of devices. |
| **Input Transformation** | **Control Room HMI** | Facilitates the projection of operator interfaces onto tablets or remote screens with differing aspect ratios, maintaining precise touch control. |

---

## 6. Future Directions

The current implementation validates the efficacy of containerized isolation for real-time tasks. Future development focuses on modularization:

* **Resilience:** Finalizing the auto-reconnect logic for USB/IP to ensure "headless" reliability.
* **API Abstraction:** Decoupling the networking logic (`wifi_container.py`) into a standalone "Latency-Critical Network Manager" API for use by third-party applications.
* **Protocol Agnosticism:** Expanding the media pipeline to support AV1 and H.265 for lower bandwidth environments.

## 7. Conclusion

The Deck-Upad project demonstrates that the primary bottleneck in Linux real-time wireless communication is often not the hardware, but the contention within the OS network stack. By leveraging containerization not just for software dependency management, but for **hardware isolation and dedicated resource governance**, it is possible to achieve deterministic, low-latency performance on commodity hardware. This architecture provides a robust blueprint for the next generation of edge computing and remote operation platforms.
