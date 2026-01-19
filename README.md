## Description

Note: Installation instructions later down the Readme.

The goal of this project is to enable turning your Steam Deck into a Steam Controller 2 (yes, touchpads, gyro and haptics work) you can also use as a wireless second touchscreen. The controller functionality has wired-like latency (ping times of 2-5ms have been observed when using the wifi container), making intense games like Celeste playable.

To make low latency gameplay possible, the project leverages USB/IP as well as removing smart features normally performed by Network Manager, without making permanent changes to the system. To make the necessary WiFi and controller tweaks without the system intervening, it uses containers to perform these changes temporarily. It then uses veth to bridge the connection to the host OS after hiding the adapters. This enables using USB/IP and iw (an alternative lightweight WiFi network manager) on read-only OSs like SteamOS. In over-simplified terms, think of the wifi container as a tool to overclock your WiFi card and make it easy to make a P2P hotspot. Think of usbip_container as a preconfigued script to redirect inputs from the Steam Deck's built-in controller to another PC over that WiFi connection. USB/IP relies on a wired-like network connection due to its use of the TCP protocol and the time-sensitivity of the application, and that is why it relies on the tweaks made by WiFi container to introduce that stability.

**Pro Tip**: If you want to use host mode while maintaining internet, plug your phone into your computer and enable USB tethering.

https://github.com/user-attachments/assets/9d859c82-4915-40b5-b0e8-9d2090256aee


This is a Work In Progress (WIP), but all major functionality is now working. This has been tested with Bazzite on Game Mode as well as KDE. (on both sides)

## What is Currently Working

Using the Azahar fork https://github.com/phly95/azahar-upad you can use this to play 3DS games with the touch screen usable on the Steam Deck. The video is reasonably low latency, though improvements could be made on this front with further optimizations. Touch interaction works by simulating touch inputs on the main display, which Azahar recognizes as taps on the bottom screen. Controller passthrough works by using USB/IP. Device discovery is now automatic using the launcher.py GUI.

## Installation instructions


* Go to https://github.com/phly95/Deck-Upad/releases/latest and download the zip file. Extract the files to your home folder. You should now have a folder named "Deck-Upad" in the root of your home folder.

* If you want to play 3DS games with the second screen, go to https://github.com/phly95/azahar-upad/releases/latest and install the flatpak (note: it will replace any existing Azahar flatpak if you have it installed. It won't affect the Appimage preinstalled by Emudeck)

* Add ~/Deck-Upad/launcher.py as a non-Steam game as well as the Azahar flatpak you just installed. (Azahar only if you plan to play 3DS games)
* Rename launcher.py in your Steam Library as "Deck-Upad" Feel free to set the artwork as the items in the "placeholder_logos" folder if you like.

* Go to Game Mode, launch Deck-Upad. Your gaming PC should be set as a Host, your Steam Deck should be set as a client. Feel free to leave the default region and channel if your country allows UNII-3 Channels (North and South America). If you are in Europe or Asia, change the channel to channel 48 and adjust your region settings.
Start the service on the desktop PC first, then start the service on the Steam Deck. They should pair with eachother and the Steam Deck should go black.

**Feel free to play any game you wish. Your Steam Deck is now a Steam Controller.** Ending the service on the Host PC will automatically disconnect any Steam Decks paired to the host PC.

If you wish to play 3DS games with the second screen, launch the Azahar fork **make sure Vulkan** is the rendering backend. Also, make sure to set the screen layout to "Deck-Upad Streaming" Feel free to also enable async shader compilation and disable async presentation in the settings for a better experience. Once you launch your 3DS game, the touch screen should automatically show up on your Steam Deck.

## Acknowledgements

Thanks to the following projects for providing reference material and functionality for making this a reality:

* obs-vkcapture
* kmscube
* podman
* Gemini
* vkcube
* Azahar
* gstreamer
* usbip
* Alpine Linux
* Fedora
* PyOpenGL
* python-evdev
