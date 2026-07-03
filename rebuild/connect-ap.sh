#!/bin/bash
# Connect USB WiFi dongle to an AP with optimized low-latency settings
# Usage: sudo ./connect-ap.sh <SSID> <PASSWORD>
# Example: sudo ./connect-ap.sh WiFive 4KxGdSFET

set -e

IFACE="wlx90de801c6029"
SSID="${1:?Usage: $0 <SSID> <PASSWORD>}"
PASS="${2:?Usage: $0 <SSID> <PASSWORD>}"
CTRL_DIR="/var/run/wpa_supplicant-upad"
USB_VID="0e8d"
USB_PID="7961"

echo "[1/8] Cleaning up previous wpa_supplicant for $IFACE..."
# Only kill wpa_supplicant instances for our interface, not the built-in WiFi
for pid in $(pgrep -f "wpa_supplicant.*$IFACE"); do
    sudo kill "$pid" 2>/dev/null || true
done
sudo rm -f "$CTRL_DIR/$IFACE"
mkdir -p "$CTRL_DIR"

echo "[2/8] USB reset to ensure clean state..."
USB_PATH=$(for dev in /sys/bus/usb/devices/*; do
    if [ -f "$dev/idVendor" ] && [ "$(cat "$dev/idVendor" 2>/dev/null)" = "$USB_VID" ] && [ -f "$dev/idProduct" ] && [ "$(cat "$dev/idProduct" 2>/dev/null)" = "$USB_PID" ]; then
        echo "$dev"
        break
    fi
done)

if [ -n "$USB_PATH" ]; then
    echo 0 | sudo tee "$USB_PATH/authorized" > /dev/null
    sleep 1
    echo 1 | sudo tee "$USB_PATH/authorized" > /dev/null
    echo "  Waiting for interface to reappear..."
    for i in $(seq 1 10); do
        if ip link show "$IFACE" > /dev/null 2>&1; then
            echo "  Interface $IFACE ready"
            break
        fi
        sleep 1
    done
else
    echo "  USB device not found, skipping reset"
fi

echo "[3/8] Setting regulatory domain to US..."
iw reg set US

echo "[4/8] Excluding $IFACE from NetworkManager..."
nmcli device set "$IFACE" managed no 2>/dev/null || true

echo "[5/8] Bringing up $IFACE..."
sudo ip link set "$IFACE" up
sleep 1

echo "[6/8] Writing WPA config..."
cat > /tmp/upad-wpa.conf <<EOF
ctrl_interface=$CTRL_DIR
ctrl_interface_group=0
update_config=1
country=US
network={
    ssid="$SSID"
    psk="$PASS"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
EOF

echo "[7/8] Connecting with wpa_supplicant..."
sudo wpa_supplicant -B -i "$IFACE" -c /tmp/upad-wpa.conf -D nl80211

echo -n "  Waiting for association"
for i in $(seq 1 30); do
    STATUS=$(sudo wpa_cli -p "$CTRL_DIR" -i "$IFACE" status 2>/dev/null | grep "wpa_state" || true)
    if echo "$STATUS" | grep -q "COMPLETED"; then
        echo " connected!"
        break
    fi
    echo -n "."
    sleep 0.5
done

if ! sudo wpa_cli -p "$CTRL_DIR" -i "$IFACE" status 2>/dev/null | grep -q "COMPLETED"; then
    echo " FAILED to connect to $SSID"
    exit 1
fi

echo "[8/8] Getting IP via DHCP..."
sudo dhclient -v "$IFACE" 2>&1 | tail -3

echo ""
echo "Connected to $SSID."
echo "  Interface: $IFACE"
IP=$(ip -4 addr show "$IFACE" | grep inet | awk '{print $2}')
echo "  IP:        $IP"
echo "  Frequency: $(iw dev "$IFACE" link 2>/dev/null | grep freq | awk '{print $2}') MHz"
echo "  Signal:    $(iw dev "$IFACE" link 2>/dev/null | grep signal | awk '{print $2, $3}')"
