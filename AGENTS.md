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
