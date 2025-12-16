# Deck-Upad
An experiment to turn the steam deck into a controller with a screen for a remote PC similar to the Wii U gamepad

This is a WIP, but all major functionality is now working.

What is currently working:

- The sender script will prompt for a display or window to share. It uses pipewire to capture.
- Pipewire capture works with VKMS displays (virtual displays) with low latency
- Mouse/touch input is working, though it has only been tested with a single monitor and has not been tested with multi monitor
- P2P low latency wifi networking (<9 ms ping)
- Virtually attaching the Steam Deck controls to the remote PC via USB/IP
- Touch input is working with low latency

What needs work:

- Simplify the launch process to make it easy to get going (perhaps with 3 modes: Host, Client (P2P), Client (external AP)


Note on networking: It appears like things like network scanning are creating latency issues. This project resolves this by creating a container that takes over a wifi card and ensures that it behaves correctly to ensure consistently low latency. Regarding the solution to the networking issue, the code automatically sets up a root level podman container on Alpine Linux that takes control of the Wifi chip and ensures that it is managed correctly for low latency. Traffic flows through a veth network bridge that connects the host PC to the wifi network while preventing the host PC from performing any operations involving wifi.


wifi_container.py does just this. It hands over control of the wifi card to the podman container, the container connects to the wifi and passes the internet connection to the host machine via a wireguard VPN. More testing is needed to be done to check if the code is portable (Bazzite and Steam OS for testing), extend functionality to allow for P2P Wifi, and modularizing the code. For example, the wifi container option should be an API that other scripts can interact with.
