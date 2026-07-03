# Deck-Upad Rebuild

## Goal

Turn a Steam Deck into a wireless second screen + controller for a PC.
Two machines, each with a USB WiFi dongle, communicate over a dedicated P2P link.
No containers, no USB/IP kernel modules, no NetNS — just native WiFi + UDP.

## Architecture

```
Host PC                                      Steam Deck
────────                                     ──────────
USB WiFi dongle (AP mode)                    USB WiFi dongle (client mode)
  ↓                                            ↓
hostapd (DeckUpad, ch149, 5GHz)             wpa_supplicant (connects to DeckUpad)
  ↓                                            ↓
192.168.50.1                                  DHCP: 192.168.50.10-100
  ↓                                            ↓
UDP :5555 ← controller input ────────────── Neptune controller parser
UDP :5556 → haptic feedback ──────────────→  Neptune rumble forwarder
UDP :5000 → H.64 video ─────────────────→  GStreamer receiver
UDP :5001 ← touch input ──────────────────  Video receiver + touch handler
  ↓                                            ↓
UHID → virtual Steam Controller            GStreamer decode + display
```

## Why This Design

| Old (current codebase) | New (rebuild) |
|---|---|
| 3 Podman containers | Zero containers |
| USB/IP kernel modules | UDP sockets |
| 625-line wifi_manager.py | ~60-line shell scripts |
| perform_aggressive_cleanup | udev pins the interface name |
| Config lost on reboot | /etc configs persist |
| First-run: 5min container build | First-run: instant |
| Linux-only host | Cross-platform potential |

## What SpoofDeck Already Solved

The `spoofdeck-modified` project (sibling repo) provides:
- **Neptune HID report parsing** — complete 64-byte report format (buttons, sticks, triggers, trackpads, IMU)
- **Steam Controller protocol knowledge** — SC2 BLE protocol, GATT services, report descriptors
- **Firmware analysis methodology** — Ghidra/IDA static analysis of nRF52840 binaries
- **Puck firmware** — `firmware/proteus_firmware.bin` for future ESB protocol reverse engineering

## Key Learnings (from testing)

1. **USB reset required when switching modes** — mt7921u driver doesn't clean up properly after AP mode. Must power-cycle via `/sys/bus/usb/devices/2-1.4/authorized` (write 0 then 1).

2. **Never use `killall wpa_supplicant`** — kills the built-in WiFi's wpa_supplicant too. Use `pgrep -f "wpa_supplicant.*$IFACE"` to target only the dongle.

3. **Separate ctrl_interface** — dongle's wpa_supplicant uses `/var/run/wpa_supplicant-upad/` to avoid conflicting with NetworkManager's wpa_supplicant at `/var/run/wpa_supplicant/`.

4. **Power save must be disabled every connection** — NetworkManager re-enables it on reconnect. A dispatcher script at `/etc/NetworkManager/dispatcher.d/99-upad-powersave` auto-disables it.

5. **Country code needed for both AP and client** — AP can't start on `(no IR)` channels without it. Client can't actively scan those channels either. Always set `iw reg set US`.

## Hardware

| Component | Interface | Driver | PHY | Role |
|---|---|---|---|---|
| USB WiFi dongle | wlx90de801c6029 | mt7921u (MediaTek) | phy1 | AP or client |
| Built-in WiFi | wlp2s0 | Qualcomm | phy0 | Internet (untouched) |

USB IDs: `0e8d:7961` (MediaTek MT7921U)
Supports: managed, AP, AP/VLAN, monitor, P2P-client, P2P-GO, P2P-device
Bands: 2.4GHz (ch1-14) + 5GHz (ch36-165)

## Current State

### Completed

- [x] USB WiFi dongle detected and identified (mt7921u)
- [x] AP mode working — hostapd + dnsmasq on channel 149 (5GHz)
- [x] Client mode working — wpa_supplicant connects to any WPA2 AP
- [x] USB reset fix for mode switching
- [x] Power save disabled (iw + NM dispatcher script)
- [x] USB auto-suspend disabled (udev rule)
- [x] NM background scanning disabled
- [x] Built-in WiFi never touched by any script
- [x] Persistent configs: udev rule, NM conf, dispatcher script

### Persistent Files

| File | Purpose |
|---|---|
| `/etc/udev/rules.d/99-upad-usb-power.rules` | Disable USB auto-suspend for dongle |
| `/etc/NetworkManager/conf.d/99-no-scan.conf` | Disable NM background scanning |
| `/etc/NetworkManager/conf.d/99-deck-upad.conf` | Exclude dongle from NM management |
| `/etc/NetworkManager/dispatcher.d/99-upad-powersave` | Auto-disable power save on connect |

### Scripts

| Script | Purpose |
|---|---|
| `rebuild/start-ap.sh` | Turn dongle into AP (hostapd + dnsmasq) |
| `rebuild/stop-ap.sh` | Tear down AP |
| `rebuild/connect-ap.sh` | Connect dongle as client (with USB reset) |
| `rebuild/disconnect-ap.sh` | Disconnect client (without touching built-in WiFi) |

### Not Started

- [ ] UDP protocol for controller input (Deck → Host)
- [ ] UDP protocol for haptic feedback (Host → Deck)
- [ ] Neptune HID parser (port from SpoofDeck's input_handler.py)
- [ ] UHID daemon on host (create virtual Steam Controller)
- [ ] GStreamer video sender (on Deck, send H.264 over UDP)
- [ ] GStreamer video receiver (on Host, display + touch input)
- [ ] Touch input injection (host: evdev/udev, Deck: touch coordinates)
- [ ] Pairing / persistent peer config
- [ ] systemd services for auto-start
- [ ] Cross-platform host client (Windows ViGEmBus / Linux UHID)

## Input Forwarding Plan

### How It Works

The Deck reads its Neptune controller and sends input over UDP to the host.
The host creates a virtual gamepad via UHID and feeds it input.
Haptics flow back over the same UDP connection.

```
Deck                                          Host
────                                          ────
/dev/hidraw3 (Neptune controller)             /dev/uhid
    ↓                                             ↓
Neptune parser (SpoofDeck)                   UHID daemon (~150 lines)
    ↓                                             ↓
UDP socket ─────────────────────────────→    UHID_INPUT2 (kernel)
                                                 ↓
                                             HID subsystem
                                                 ↓
                                             Steam sees gamepad
                                                 ↓
                                             UHID_OUTPUT (haptics)
                                                 ↓
                                             UDP back to Deck
```

### Protocol (over UDP)

**Controller input** (Deck → Host, port 5555):
```python
# ~50 byte packet, sent at 60Hz
struct.pack('<BhhiHHBB',
    report_id,      # 1 byte: report type
    left_x,         # 2 bytes: -32768 to 32767
    left_y,         # 2 bytes
    right_x,        # 2 bytes
    right_y,        # 2 bytes
    left_trigger,   # 1 byte: 0-255
    right_trigger,  # 1 byte: 0-255
    buttons         # 2 bytes: bitmask
)
# + trackpad, gyro data appended
```

**Haptic feedback** (Host → Deck, port 5556):
```python
struct.pack('BB', left_motor, right_motor)  # 0-255 intensity each
```

**Video** (Host → Deck, port 5000): H.264 over RTP/UDP
**Touch input** (Deck → Host, port 5001): JSON `{x, y, type}`

### Why UDP (not TCP)

Each input report is independent. If packet 5 is lost, packet 6 (16ms later) supersedes it.
TCP's retransmission causes head-of-line blocking — stale data arrives late.
UDP delivers the latest state with minimal latency.

### UHID on Linux

UHID (`/dev/uhid`) lets userspace create virtual HID devices. A daemon:
1. Opens `/dev/uhid`
2. Sends `UHID_CREATE2` with a Steam Controller HID report descriptor
3. Receives UDP input from Deck, sends `UHID_INPUT2` to kernel
4. Reads `UHID_OUTPUT` from kernel (haptics), sends back to Deck

The HID report descriptor tells the kernel (and Steam) what the device is.
With Valve's VID `0x28DE` and SC PID, Steam recognizes it as a Steam Controller.

### Windows Equivalent

UHID doesn't exist on Windows. Use **ViGEmBus** (virtual Xbox controller driver)
or a custom virtual HID driver. Same concept — userspace daemon receives UDP,
creates virtual device via Windows HID API.

### Neptune Parser (from SpoofDeck)

SpoofDeck's `input_handler.py` (`/home/philip/spoofdeck-modified/src/input_handler.py`)
already parses the complete 64-byte Neptune HID report:
- Buttons (A/B/X/Y, bumpers, triggers, stick clicks, back, start, steam, etc.)
- Left/right sticks (16-bit X/Y each)
- Left/right triggers (8-bit each)
- Left/right trackpads (X/Y + force sensor each)
- IMU (accelerometer + gyroscope, 3-axis each)
- Timestamp

This parser can be ported directly — just change the output from BLE ATT
notifications to UDP packets.

### Key Files to Reference

| File | What It Has |
|---|---|
| `spoofdeck-modified/src/input_handler.py` | Neptune HID parser (lines 135-396) |
| `spoofdeck-modified/docs/sc2-protocol.md` | SC2 report format, commands |
| `spoofdeck-modified/src/gatt_db.py` | Steam Controller HID descriptor |
| `current/core/input_server.py` | evdev virtual touchscreen (reusable) |
| `current/core/video_receiver.py` | GStreamer pipeline + touch forwarding |

## Video Streaming Plan

### Sender (on Deck)

GStreamer captures frames from a Vulkan/OpenGL app via Unix socket,
encodes to H.264, sends over UDP.

```
App → DMA-BUF fd → EGL import → FBO render → GStreamer encode → UDP :5000
```

Already implemented in `core/video_sender.py` — runs natively,
no container needed. Just needs the container wrapper removed.

### Receiver (on Host)

GStreamer pipeline decodes H.264 and displays in a GTK window.
Touch events on the window are sent back to the host as normalized coordinates.

```
UDP :5000 → rtph264depay → h264parse → decodebin → videoconvert → display
Touch events → JSON → UDP :5001
```

Already implemented in `core/video_receiver.py` — also runs natively.

### Why WiFi Works for Both Input and Video

Input: ~3 KB/s (60 reports/sec × 50 bytes)
Video: ~10-50 Mbps (H.264 stream)

Input is negligible compared to video. WiFi handles both simultaneously
on the same link — different sockets, same radio. No contention because
input packets are tiny and fit in the gaps between video frames.

## Cross-Platform Considerations

### Why Not BLE

BLE HID works cross-platform (no host software needed), but:
- Steam blocks haptics for BLE controllers (5 layers of defense in steamclient.so)
- BLE bandwidth too low for video (~1 Mbps vs ~50 Mbps needed)
- BLE is a different transport entirely — would need separate video link

### Why WiFi

- Full bandwidth for video + input on one link
- Haptics work (no BLE architecture block — virtual device via UHID/ViGEmBus)
- Already proven in current Deck-Upad (2-5ms latency observed)
- Cross-platform: Linux UHID, Windows ViGEmBus, macOS IOKit

### The Xbox Adapter Question

Xbox Wireless Adapter uses 802.11 WiFi hardware with Microsoft's proprietary
protocol. It proves low-latency WiFi HID works on Windows. But the protocol
is not reverse-engineered enough to use as a standard. The Puck (Steam Controller
dongle) is the equivalent for Steam — uses ESB protocol on nRF52840 hardware.
SpoofDeck has the Puck firmware for future reverse engineering.

### Remaining Platform Gap

| Component | Linux | Windows |
|---|---|---|
| WiFi AP | hostapd | Hosted Network / netsh |
| Virtual gamepad | UHID | ViGEmBus |
| Video decoder | GStreamer | GStreamer / mpv |
| Touch injection | evdev | SendInput |
| WiFi client | wpa_supplicant | netsh / NM |

Linux is fully solved with existing tools. Windows needs ViGEmBus + a
host app, but both are mature projects with large user bases.

## Network Config

```
SSID:       DeckUpad
Password:   deckupad123
Channel:    149 (5745 MHz, 5GHz, US regulatory)
Host IP:    192.168.50.1/24
DHCP range: 192.168.50.10 - 192.168.50.100
```

## Debugging

```bash
# Check AP status
iw dev wlx90de801c6029 info
ip addr show wlx90de801c6029

# Check client status
iw dev wlx90de801c6029 link
iw dev wlx90de801c6029 get power_save

# Check processes
ps aux | grep hostapd
ps aux | grep "wpa_supplicant.*wlx90"
ps aux | grep dnsmasq | grep upad

# Check kernel logs for WiFi
sudo dmesg | grep -i "wlx90\|mt7921"

# USB reset (when switching modes)
echo 0 | sudo tee /sys/bus/usb/devices/2-1.4/authorized
echo 1 | sudo tee /sys/bus/usb/devices/2-1.4/authorized
```
