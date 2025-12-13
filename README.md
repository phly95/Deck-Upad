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
