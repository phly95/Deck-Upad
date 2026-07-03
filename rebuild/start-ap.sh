#!/bin/bash
# Start Deck-Upad WiFi AP on USB dongle
# Usage: sudo ./start-ap.sh

set -e

IFACE="wlx90de801c6029"
SSID="DeckUpad"
PASS="deckupad123"
CHANNEL=149
HOST_IP="192.168.50.1/24"
DHCP_RANGE="192.168.50.10,192.168.50.100,12h"

echo "[1/6] Setting regulatory domain to US..."
iw reg set US

echo "[2/6] Excluding $IFACE from NetworkManager..."
nmcli device set "$IFACE" managed no

echo "[3/6] Bringing up $IFACE..."
ip link set "$IFACE" up

echo "[4/6] Assigning IP $HOST_IP..."
ip addr add "$HOST_IP" dev "$IFACE" 2>/dev/null || true

echo "[5/6] Starting hostapd (SSID: $SSID, channel: $CHANNEL)..."
cat > /tmp/upad-hostapd.conf <<EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=a
ieee80211ac=1
wpa=2
wpa_passphrase=$PASS
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
EOF
hostapd -B /tmp/upad-hostapd.conf

echo "[6/6] Starting DHCP server..."
dnsmasq \
    --interface="$IFACE" \
    --bind-interfaces \
    --dhcp-range="$DHCP_RANGE" \
    --dhcp-option=3,192.168.50.1 \
    --dhcp-option=6,8.8.8.8 \
    --except-interface=lo \
    --pid-file=/tmp/upad-dnsmasq.pid \
    --log-facility=/tmp/upad-dnsmasq.log

echo ""
echo "AP is live."
echo "  SSID:     $SSID"
echo "  Password: $PASS"
echo "  Channel:  $CHANNEL (5 GHz)"
echo "  Host IP:  192.168.50.1"
echo "  DHCP:     192.168.50.10 - 192.168.50.100"
