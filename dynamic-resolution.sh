#!/bin/bash

# --- CONFIGURATION ---
DESKTOP_NAME="Default"
MODE="AUTO" # Default mode
FINAL_RES_ARG="" # Store the resolution argument (e.g. H+1600)
SENDER_IP="127.0.0.1" # Default IP
TMP_REG="/tmp/proton_desktop_config.reg"
VERBOSE=false # Default to silent (console only)

# Internal Variables
CALC_MODE="STANDARD" # Can be STANDARD or S_PLUS
S_VAL=0

# --- HELPER FUNCTION: SHOW MESSAGE ---
show_message() {
    local title="$1"
    local text="$2"

    if [[ "$VERBOSE" == "true" ]]; then
        # GUI MODE
        if command -v kdialog &> /dev/null; then
            kdialog --msgbox "$text" --title "$title"
        elif command -v zenity &> /dev/null; then
            zenity --warning --title="$title" --text="$text" --width=500
        elif command -v xterm &> /dev/null; then
            xterm -hold -e echo -e "$title\n\n$text"
        else
            echo -e "[$title]\n$text"
        fi
    else
        # CONSOLE MODE (Silent)
        echo "---------------------------------------------------"
        echo "[$title]"
        echo -e "$text"
        echo "---------------------------------------------------"
    fi
}

# --- HELPER FUNCTION: SHOW HELP ---
show_help() {
    HELP_TEXT="PROTON DYNAMIC RESOLUTION HELP
-----------------------------------
Usage: script.sh [OPTIONS] [IP_ADDRESS] %command%

ARGUMENTS (Any Order):
  verbose       Enable popup windows (Default: silent/console).
  192.168.1.50  Set Receiver IP (Default: 127.0.0.1)
  off           Disable Virtual Desktop.
  1920x1080     Force resolution.
  H+1600        Auto-detect + add height (Standard Center).
  W+1920        Auto-detect + add width.
  S+400         Split Mode: Adds 400px bottom screen + 408px top void.

EXAMPLES:
  script.sh verbose S+400 192.168.86.42 %command%
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
    elif [[ "${SANITIZED_ARG,,}" == "verbose" || "${SANITIZED_ARG,,}" == "-v" ]]; then
        VERBOSE=true
        shift
    elif [[ "${SANITIZED_ARG,,}" == "off" || "${SANITIZED_ARG,,}" == "disable" ]]; then
        MODE="DISABLE"
        shift
    elif [[ "$SANITIZED_ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SENDER_IP="$SANITIZED_ARG"
        shift
    elif [[ "$SANITIZED_ARG" =~ ^[0-9]+x[0-9]+$ ]]; then
        MODE="ENABLE"
        CALC_MODE="MANUAL"
        FINAL_RES_ARG="$SANITIZED_ARG"
        shift
    elif [[ "$SANITIZED_ARG" =~ S\+([0-9]+) ]]; then
        MODE="ENABLE"
        CALC_MODE="S_PLUS"
        S_VAL="${BASH_REMATCH[1]}"
        shift
    elif [[ "$SANITIZED_ARG" =~ [WH][+-][0-9]+ ]]; then
        MODE="ENABLE"
        CALC_MODE="STANDARD"
        FINAL_RES_ARG="$SANITIZED_ARG"
        shift
    else
        break
    fi
done

# --- SAFETY CHECK: DETECT PROTON/WINE ---
PROTON_BIN=""
for arg in "$@"; do
    if [[ "$arg" == *"/proton" || "$arg" == *"wine" || "$arg" == *"wine64" ]]; then
        PROTON_BIN="$arg"
        break
    fi
done

if [ -z "$PROTON_BIN" ]; then
    show_message "Runtime Error" "CRITICAL ERROR:\n\nThis script detected that you are NOT running with Proton or Wine.\n\nTo use this script, you must enable a Compatibility Tool in Steam Properties."
    exit 1
fi

# --- CALCULATE RESOLUTION ---
FINAL_RES_STRING=""

if [[ "$MODE" == "ENABLE" ]]; then
    # 1. Get Native Dimensions
    RAW_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
    if [ -z "$RAW_RES" ]; then
        RAW_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
    fi
    NATIVE_W=$(echo "$RAW_RES" | cut -d'x' -f1)
    NATIVE_H=$(echo "$RAW_RES" | cut -d'x' -f2)

    # 2. Branch Logic based on CALC_MODE
    if [[ "$CALC_MODE" == "MANUAL" ]]; then
        FINAL_RES_STRING="$FINAL_RES_ARG"

    elif [[ "$CALC_MODE" == "S_PLUS" ]]; then
        # S+ Logic:
        # TopVoid = S + 8 (To balance the 20px top vs 28px bottom bars)
        # VulkanHeight = TopVoid + NativeH + S
        # RegistryHeight = VulkanHeight + 48 (Menu bars)

        TOP_VOID=$((S_VAL + 8))
        VULKAN_H=$((TOP_VOID + NATIVE_H + S_VAL))
        REG_H=$((VULKAN_H + 48))

        FINAL_RES_STRING="${NATIVE_W}x${REG_H}"

        show_message "S+ Mode Calculated" "Native: ${NATIVE_W}x${NATIVE_H}\nS Value: $S_VAL\nTop Void: $TOP_VOID\n\nFinal Virtual Desktop: ${NATIVE_W}x${REG_H}"

    else
        # STANDARD (H+/W+) Logic
        WIDTH=$NATIVE_W
        HEIGHT=$NATIVE_H

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
ROAMING_BASE="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Roaming"
PATH_PLUS="$ROAMING_BASE/AzaharPlus/config/qt-config.ini"
PATH_STD="$ROAMING_BASE/Azahar/config/qt-config.ini"

AZAHAR_CONFIG=""

# Check logic: Prioritize Plus, fallback to Standard
if [ -f "$PATH_PLUS" ]; then
    AZAHAR_CONFIG="$PATH_PLUS"
elif [ -f "$PATH_STD" ]; then
    AZAHAR_CONFIG="$PATH_STD"
else
    AZAHAR_CONFIG="$PATH_PLUS"
fi

# --- CONFIG STATUS CHECK ---
if [ -f "$AZAHAR_CONFIG" ]; then
    show_message "Azahar Config Status" "SUCCESS: File Found!\n\nUsing Path:\n$AZAHAR_CONFIG"
else
    show_message "Azahar Config Status" "WARNING: File NOT Found.\n\nChecked locations:\n1. $PATH_PLUS\n2. $PATH_STD"
fi
# ---------------------------

if [[ "$MODE" == "ENABLE" && -f "$AZAHAR_CONFIG" ]]; then

    TOTAL_WIDTH=$(echo "$FINAL_RES_STRING" | cut -d'x' -f1)

    # Initialize variables
    T_X=0; T_Y=0; T_W=0; T_H=0
    B_X=0; B_Y=0; B_W=0; B_H=0

    if [[ "$CALC_MODE" == "S_PLUS" ]]; then
        # --- S+ COORDINATE MATH ---

        # 1. Top Screen (Native Height, Centered vertically in Vulkan space via TopVoid)
        T_H=$NATIVE_H
        T_Y=$((S_VAL + 8)) # The calculated Top Void

        # Top Width (Standard 5:3 Aspect Ratio logic relative to height)
        T_W=$(awk -v h="$T_H" 'BEGIN {printf "%.0f", h * 5 / 3}')

        # Center Top X
        T_X=$(awk -v tw="$TOTAL_WIDTH" -v w="$T_W" 'BEGIN {printf "%.0f", (tw - w) / 2}')
        if [ "$T_X" -lt 0 ]; then T_X=0; fi

        # 2. Bottom Screen (Fills the 'S' void)
        B_H=$S_VAL
        B_Y=$((T_Y + T_H)) # Starts immediately after top screen

        # Bottom Width (Standard 4:3 Aspect Ratio logic relative to height)
        B_W=$(awk -v h="$B_H" 'BEGIN {printf "%.0f", h * 4 / 3}')
        B_X=0

    else
        # --- STANDARD H+/W+ MATH ---
        # Recalculate based on Final Resolution String
        TOTAL_HEIGHT=$(echo "$FINAL_RES_STRING" | cut -d'x' -f2)

        # Sanity check for Native Height if not set
        if [ -z "$NATIVE_H" ]; then NATIVE_H=$TOTAL_HEIGHT; fi

        # Top Screen
        T_H=$NATIVE_H
        if [ "$TOTAL_HEIGHT" -lt "$NATIVE_H" ]; then T_H=$TOTAL_HEIGHT; fi # Safety

        T_Y=$(( (TOTAL_HEIGHT - NATIVE_H) / 2 ))
        T_W=$(awk -v h="$T_H" 'BEGIN {printf "%.0f", h * 5 / 3}')
        T_X=$(awk -v tw="$TOTAL_WIDTH" -v w="$T_W" 'BEGIN {printf "%.0f", (tw - w) / 2}')
        if [ "$T_X" -lt 0 ]; then T_X=0; fi

        # Bottom Screen
        B_H=$(( TOTAL_HEIGHT - (T_Y + T_H) ))
        if [ "$B_H" -le 0 ]; then B_H=100; fi
        B_W=$(awk -v h="$B_H" 'BEGIN {printf "%.0f", h * 4 / 3}')
        B_Y=$(( T_Y + T_H ))
        B_X=0
    fi

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
