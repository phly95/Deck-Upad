# Deck-Upad
An experiment to turn the steam deck into a controller with a screen for a remote PC similar to the Wii U gamepad

This is not ready yet.

What is currently working:

- The sender script will prompt for a display or window to share. It uses pipewire to capture.
- Pipewire capture works with VKMS displays (virtual displays) with low latency
- Mouse/touch input is working, though it has only been tested with a single monitor and has not been tested with multi monitor

What needs work:

- Figuring out how to set up a host PC to have consistent sub 15ms ping by hosting its own 5GHz Wifi network.
- Automating USB/IP setup to link the Steam Deck gamepad to the host PC.
- Ensure that touch input works correctly with multiple displays and floating windows.


Note on networking: It appears like things like network scanning are creating latency issues. The next challenge is to create a container that takes over a wifi card and ensures that it behaves correctly to ensure consistently low latency. The container should act as a VPN to the host OSs on each side.


Regarding the solution to the networking issue, the plan is to set up a root level podman container on Alpine Linux that takes control of the Wifi chip and ensures that it is managed correctly for low latency. Traffic will flow through a wireguard VPN that connects the host PC to the wifi network while preventing the host PC from performing any operations involving wifi.


wifi_container.py does just this. It hands over control of the wifi card to the podman container, the container connects to the wifi and passes the internet connection to the host machine via a wireguard VPN. More testing is needed to be done to check if the code is portable (Bazzite and Steam OS for testing), extend functionality to allow for P2P Wifi, and modularizing the code. For example, the wifi container option should be an API that other scripts can interact with.
