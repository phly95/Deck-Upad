#!/bin/bash

# --- CONFIGURATION ---
DESKTOP_NAME="Default"
MODE="AUTO" # Default mode
FINAL_RES_ARG="" # Store the resolution argument (e.g. H+1600)
SENDER_IP="127.0.0.1" # Default IP
TMP_REG="/tmp/proton_desktop_config.reg"

# --- HELPER FUNCTION: SHOW MESSAGE ---
show_message() {
    local title="$1"
    local text="$2"

    if command -v kdialog &> /dev/null; then
        kdialog --msgbox "$text" --title "$title"
    elif command -v zenity &> /dev/null; then
        zenity --warning --title="$title" --text="$text" --width=500
    elif command -v xterm &> /dev/null; then
        xterm -hold -e echo -e "$title\n\n$text"
    else
        echo -e "$title\n$text" > ~/Desktop/proton_error.txt
    fi
}

# --- HELPER FUNCTION: SHOW HELP ---
show_help() {
    HELP_TEXT="PROTON DYNAMIC RESOLUTION HELP
-----------------------------------
Usage: script.sh [OPTIONS] [IP_ADDRESS] %command%

ARGUMENTS (Any Order):
  192.168.1.50  Set Receiver IP (Default: 127.0.0.1)
  off           Disable Virtual Desktop.
  1920x1080     Force resolution.
  H+1600        Auto-detect + add height.
  W+1920        Auto-detect + add width.

EXAMPLES:
  script.sh H+1600 192.168.86.42 %command%
"
    show_message "Proton Resolution Help" "$HELP_TEXT"
    exit 0
}

# --- PARSE ARGUMENTS LOOP ---
while [[ $# -gt 0 ]]; do
    ARG="$1"
    SANITIZED_ARG=$(echo "$ARG" | tr -d '\r')

    if [[ "${SANITIZED_ARG,,}" == "help" || "${SANITIZED_ARG,,}" == "-h" ]]; then
        show_help
    elif [[ "${SANITIZED_ARG,,}" == "off" || "${SANITIZED_ARG,,}" == "disable" ]]; then
        MODE="DISABLE"
        shift
    elif [[ "$SANITIZED_ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SENDER_IP="$SANITIZED_ARG"
        shift
    elif [[ "$SANITIZED_ARG" =~ ^[0-9]+x[0-9]+$ ]]; then
        MODE="ENABLE"
        FINAL_RES_ARG="$SANITIZED_ARG"
        shift
    elif [[ "$SANITIZED_ARG" =~ [WH][+-][0-9]+ ]]; then
        MODE="ENABLE"
        FINAL_RES_ARG="$SANITIZED_ARG"
        shift
    else
        break
    fi
done

# --- SAFETY CHECK: DETECT PROTON/WINE ---
# We scan the remaining arguments to find the runtime binary.
PROTON_BIN=""
for arg in "$@"; do
    # Check for standard Proton paths or strict 'wine' command
    if [[ "$arg" == *"/proton" || "$arg" == *"wine" || "$arg" == *"wine64" ]]; then
        PROTON_BIN="$arg"
        break
    fi
done

if [ -z "$PROTON_BIN" ]; then
    show_message "Runtime Error" "CRITICAL ERROR:\n\nThis script detected that you are NOT running with Proton or Wine.\n\nTo use this script, you must enable a Compatibility Tool:\n1. Go to Steam -> Library -> Right Click Game -> Properties.\n2. Select 'Compatibility'.\n3. Check 'Force the use of a specific Steam Play compatibility tool'.\n4. Select a Proton version (e.g., GE-Proton or Proton Experimental)."
    exit 1
fi

# --- CALCULATE RESOLUTION ---
FINAL_RES_STRING=""
if [[ "$MODE" == "ENABLE" ]]; then
    if [[ "$FINAL_RES_ARG" =~ ^[0-9]+x[0-9]+$ ]]; then
        FINAL_RES_STRING="$FINAL_RES_ARG"
    else
        RAW_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
        if [ -z "$RAW_RES" ]; then
            RAW_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
        fi

        WIDTH=$(echo "$RAW_RES" | cut -d'x' -f1)
        HEIGHT=$(echo "$RAW_RES" | cut -d'x' -f2)

        if [[ -n "$FINAL_RES_ARG" ]]; then
            if [[ "$FINAL_RES_ARG" =~ W([-+][0-9]+) ]]; then
                CHANGE=${BASH_REMATCH[1]}
                WIDTH=$((WIDTH + CHANGE))
            fi
            if [[ "$FINAL_RES_ARG" =~ H([-+][0-9]+) ]]; then
                CHANGE=${BASH_REMATCH[1]}
                HEIGHT=$((HEIGHT + CHANGE))
            fi
        fi
        FINAL_RES_STRING="${WIDTH}x${HEIGHT}"
    fi
fi

# --- CONFIGURE AZAHAR LAYOUT & LAUNCH SENDER ---
# We rely on Steam setting STEAM_COMPAT_DATA_PATH when running under Proton
AZAHAR_CONFIG="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Roaming/AzaharPlus/config/qt-config.ini"

if [[ "$MODE" == "ENABLE" && -f "$AZAHAR_CONFIG" ]]; then

    # 1. Get Dimensions
    TOTAL_WIDTH=$(echo "$FINAL_RES_STRING" | cut -d'x' -f1)
    TOTAL_HEIGHT=$(echo "$FINAL_RES_STRING" | cut -d'x' -f2)

    # Get Native Monitor Height
    NATIVE_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
    if [ -z "$NATIVE_RES" ]; then
        NATIVE_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
    fi
    NATIVE_H=$(echo "$NATIVE_RES" | cut -d'x' -f2)

    if [ "$TOTAL_HEIGHT" -lt "$NATIVE_H" ]; then NATIVE_H=$TOTAL_HEIGHT; fi

    # 2. Calculate Layout Coordinates
    # --- TOP SCREEN ---
    T_H=$NATIVE_H
    T_Y=$(( (TOTAL_HEIGHT - NATIVE_H) / 2 ))
    T_W=$(awk -v h="$T_H" 'BEGIN {printf "%.0f", h * 5 / 3}')
    T_X=$(awk -v tw="$TOTAL_WIDTH" -v w="$T_W" 'BEGIN {printf "%.0f", (tw - w) / 2}')
    if [ "$T_X" -lt 0 ]; then T_X=0; fi

    # --- BOTTOM SCREEN ---
    B_H=$(( TOTAL_HEIGHT - (T_Y + T_H) ))
    if [ "$B_H" -le 0 ]; then B_H=100; fi
    B_W=$(awk -v h="$B_H" 'BEGIN {printf "%.0f", h * 4 / 3}')
    B_Y=$(( T_Y + T_H ))
    B_X=0

    # 3. Update qt-config.ini
    update_ini() {
        local key=$1; local val=$2; local file=$3
        sed -i "s|^$key=.*|$key=$val|" "$file"
        sed -i "s|^${key}\\\\default=.*|${key}\\\\default=false|" "$file"
    }

    update_ini "layout_option" "6" "$AZAHAR_CONFIG"

    update_ini "custom_top_x" "$T_X" "$AZAHAR_CONFIG"
    update_ini "custom_top_y" "$T_Y" "$AZAHAR_CONFIG"
    update_ini "custom_top_width" "$T_W" "$AZAHAR_CONFIG"
    update_ini "custom_top_height" "$T_H" "$AZAHAR_CONFIG"

    update_ini "custom_bottom_x" "$B_X" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_y" "$B_Y" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_width" "$B_W" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_height" "$B_H" "$AZAHAR_CONFIG"

    # --- LAUNCH VK SENDER ---
    SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
    SENDER_SCRIPT="$SCRIPT_DIR/sender-vk.py"

    pkill -f "sender-vk.py" || true

    if [ -f "$SENDER_SCRIPT" ]; then
        echo "Launching Sender to $SENDER_IP with Crop: $B_X,$B_Y,$B_W,$B_H"
        python3 "$SENDER_SCRIPT" "$SENDER_IP" --crop "$B_X,$B_Y,$B_W,$B_H" > /tmp/vk-sender.log 2>&1 &
    else
        echo "WARNING: sender-vk.py not found at $SENDER_SCRIPT"
    fi

elif [[ "$MODE" == "DISABLE" ]]; then
    pkill -f "sender-vk.py" || true
fi

# --- APPLY REGISTRY CHANGES ---
if [ "$MODE" == "DISABLE" ]; then
    cat > "$TMP_REG" <<EOF
REGEDIT4

[HKEY_CURRENT_USER\Software\Wine\Explorer]
"Desktop"=-
EOF
    "$PROTON_BIN" run regedit /S "$TMP_REG"
else
    cat > "$TMP_REG" <<EOF
REGEDIT4

[HKEY_CURRENT_USER\Software\Wine\Explorer]
"Desktop"="$DESKTOP_NAME"

[HKEY_CURRENT_USER\Software\Wine\Explorer\Desktops]
"$DESKTOP_NAME"="$FINAL_RES_STRING"
EOF
    "$PROTON_BIN" run regedit /S "$TMP_REG"
fi
rm -f "$TMP_REG"

# --- LAUNCH GAME ---
exec "$@"
