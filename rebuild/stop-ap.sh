#!/bin/bash
# Stop Deck-Upad WiFi AP
# Usage: sudo ./stop-ap.sh

set -e

IFACE="wlx90de801c6029"

echo "[1/3] Stopping dnsmasq..."
kill "$(cat /tmp/upad-dnsmasq.pid 2>/dev/null)" 2>/dev/null || true
rm -f /tmp/upad-dnsmasq.pid

echo "[2/3] Stopping hostapd..."
killall hostapd 2>/dev/null || true

echo "[3/3] Tearing down $IFACE..."
ip addr flush dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" down 2>/dev/null || true

echo "AP stopped."
