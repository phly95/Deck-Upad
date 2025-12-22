# Deck-Upad

tl;dr: This turns your Steam Deck into a Steam Deck into a Steam Controller 2 you can also use as a Wii U gamepad with a screen. It has wired-like latency, making intense games like Celeste playable. To make necessary wifi tweaks without the system intervening, it uses containers to perform these changes temporarily, to hide WiFi from the Operating System, and make it possible on read-only OSs like SteamOS. Think of this as a tool to overclock your WiFi card and make it easy to make a P2P hotspot. Pro Tip: If you want to use host mode while maintaining internet, plug your phone into your computer and enable USB tethering. If you are here to game, you can feel free to disregard the following paragraphs.

A high-performance, low latency system to transmit controller input and video output over a wireless network. It enables the first practical Linux-compatible implementation of native resolution dual-screen emulation over standard Wi-Fi. The implementation uses the Steam Deck as a controller with a screen for a remote PC, similar to the Wii U gamepad.

While this project is applied to a gaming use-case, the underlying architecture implements a novel containerized network isolation pattern to solve for deterministic latency in real-time wireless systems.
 
👉 Read [the technical overview](https://github.com/phly95/Deck-Upad/blob/main/TECHNICAL_OVERVIEW.md) for a deep-dive into the Network Namespaces, Kernel Isolation, and VETH bridging strategies used to achieve sub-9ms latency.

https://github.com/user-attachments/assets/9d859c82-4915-40b5-b0e8-9d2090256aee


This is a Work In Progress (WIP), but all major functionality is now working. This has only been tested with Bazzite KDE. (on both sides) It's quite likely that this will not work in Gnome or any other desktop environment. You will need to set up a VKMS virtual display before using this. The name will be something like Virtual-1, and you should set it to something like 1280x800 to match the Steam Deck.

## Technical Overview
The project uses **Podman** containers to manage complex, low-level Linux functionality on the Steam Deck, including dedicated network control and virtual hardware binding. **GStreamer** and **PipeWire** are used for low-latency video streaming, and **USB/IP** handles the controller passthrough.

## What is Currently Working

* **Screen Capture:** The sender script prompts for a display or window to share and uses the **PipeWire ScreenCast Portal** to capture the stream.
* **Low-Latency Video:** Pipewire capture works well with virtual displays (VKMS) and is compressed using available hardware encoders (e.g., `nvh264enc` or `vaapih264enc`) via **GStreamer**.
* **Input Injection:** Mouse and touch input from the receiver are correctly normalized, mapped to the streamed display's position, and injected into the host PC using a virtual **`evdev` mouse (`UInput`)**.
    * The receiver supports a high input rate (up to 240Hz).
* **Controller Passthrough (USB/IP):** The physical Steam Deck Controller (Neptune, VID `28de`:PID `1205`) is virtually attached to the remote PC via USB/IP, using a container-based wrapper (`usbip_container.py`) that implements a **hybrid host-side device discovery** method.
* **P2P Low Latency Networking:** Consistently achieves low latency (under 9 ms ping).
* **QoS Optimized Repeater:** Continues to acheive low latency while maintaining a WiFi internet connection on the host with a single WiFi card. QoS allows stable gameplay, even while downloading in the background. Running a Speedtest while performing a ping resulted in about 2-12 ms ping between the Steam Deck and the PC via the direct P2P WiFi connection.

## What Needs Work

* **Simplified Launch Process:** Simplify the launch process to make it easy to get going (perhaps with 3 modes: Host, Client (P2P), Client (external AP). Additionally, help the user create a VKMS display for KDE.
* **Portability/Testing:** More testing is needed to check if the code is portable (Bazzite and Steam OS for testing, currently it's confirmed working when both the desktop and Steam Deck are on Bazzite under a Wayland session).
* **Modularization:** Modularizing the networking components into an API that other scripts can interact with. Perhaps breaking the wifi solution into a separate project for use in other applications.

---

### Note on Networking

It appears that things like network scanning are creating latency issues. This project resolves this by creating a container that takes over a Wi-Fi card and ensures that it behaves correctly to ensure consistently low latency.

The `wifi_container.py` script automatically sets up a root-level Podman container on Alpine Linux that takes control of the physical Wi-Fi chip. The physical Wi-Fi card is moved into the container's namespace.

Traffic flows through a high-speed **VETH network bridge** that connects the host PC to the container. The container passes the internet connection to the host machine via **NAT (Network Address Translation) using `iptables MASQUERADE`**. This setup prevents the host PC from performing any operations that could interfere with Wi-Fi latency.
