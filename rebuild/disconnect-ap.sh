#!/bin/bash
# Disconnect USB WiFi dongle (does not affect built-in WiFi)
# Usage: sudo ./disconnect-ap.sh

set -e

IFACE="wlx90de801c6029"
CTRL_DIR="/var/run/wpa_supplicant-upad"

echo "[1/4] Terminating wpa_supplicant for $IFACE..."
for pid in $(pgrep -f "wpa_supplicant.*$IFACE"); do
    sudo kill "$pid" 2>/dev/null || true
done
sudo rm -f "$CTRL_DIR/$IFACE"

echo "[2/4] Releasing DHCP..."
sudo dhclient -r "$IFACE" 2>/dev/null || true

echo "[3/4] Flushing IP addresses..."
sudo ip addr flush dev "$IFACE" 2>/dev/null || true

echo "[4/4] Bringing down $IFACE..."
sudo ip link set "$IFACE" down 2>/dev/null || true

echo "Disconnected. Built-in WiFi ($([[ "$(nmcli -t -f DEVICE,STATE device)" == *"wlp2s0:connected"* ]] && echo "connected" || echo "unaffected")) not touched."
