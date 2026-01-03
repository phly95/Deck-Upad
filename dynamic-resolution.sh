#!/bin/bash

# --- SANITIZE INPUT ---
ARG1=$(echo "$1" | tr -d '\r')

# --- CONFIGURATION ---
DESKTOP_NAME="Default"
MODE="AUTO"
FINAL_RES=""
TMP_REG="/tmp/proton_desktop_config.reg"

# --- HELPER FUNCTION: SHOW HELP ---
show_help() {
    HELP_TEXT="PROTON DYNAMIC RESOLUTION HELP
-----------------------------------
Usage in Steam Launch Options:
/path/to/script.sh [OPTION] %command%

OPTIONS:
  (empty)       Auto-detect primary screen size.
  off           Disable Virtual Desktop (Native Fullscreen).
  1920x1080     Force a specific resolution (Width x Height).
  help          Show this popup.

MODIFIERS (Math on Auto-Detected Size):
  W-40          Width minus 40px (Side docks).
  H-60          Height minus 60px (Taskbars).
  H+1600        Height plus 1600px (Vertical multi-monitor).
  W+1920        Width plus 1920px (Horizontal dual-monitor).
  W-20,H-40     Combine modifiers.
"
    if command -v kdialog &> /dev/null; then
        kdialog --msgbox "$HELP_TEXT" --title "Proton Resolution Help"
    elif command -v zenity &> /dev/null; then
        zenity --info --title="Proton Resolution Help" --text="$HELP_TEXT" --width=500
    elif command -v xterm &> /dev/null; then
        xterm -hold -e echo "$HELP_TEXT"
    else
        echo "$HELP_TEXT" > ~/Desktop/proton_help_output.txt
    fi
    exit 0
}

# --- PARSE ARGUMENTS ---
if [[ "${ARG1,,}" == "help" || "${ARG1,,}" == "-h" ]]; then
    show_help

elif [[ "${ARG1,,}" == "off" || "${ARG1,,}" == "disable" ]]; then
    MODE="DISABLE"
    shift

elif [[ "$ARG1" =~ ^[0-9]+x[0-9]+$ ]]; then
    MODE="ENABLE"
    FINAL_RES="$ARG1"
    shift

elif [[ "$ARG1" =~ [WH][+-][0-9]+ ]]; then
    MODE="ENABLE"

    # Get Base Resolution
    RAW_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
    if [ -z "$RAW_RES" ]; then
        RAW_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
    fi

    WIDTH=$(echo "$RAW_RES" | cut -d'x' -f1)
    HEIGHT=$(echo "$RAW_RES" | cut -d'x' -f2)

    # Apply Modifiers
    if [[ "$ARG1" =~ W([-+][0-9]+) ]]; then
        CHANGE=${BASH_REMATCH[1]}
        WIDTH=$((WIDTH + CHANGE))
    fi
    if [[ "$ARG1" =~ H([-+][0-9]+) ]]; then
        CHANGE=${BASH_REMATCH[1]}
        HEIGHT=$((HEIGHT + CHANGE))
    fi

    FINAL_RES="${WIDTH}x${HEIGHT}"
    shift

else
    MODE="ENABLE"
    FINAL_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
    if [ -z "$FINAL_RES" ]; then
        FINAL_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
    fi
fi

# --- CONFIGURE AZAHAR LAYOUT ---
AZAHAR_CONFIG="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Roaming/AzaharPlus/config/qt-config.ini"

if [[ "$MODE" == "ENABLE" && -f "$AZAHAR_CONFIG" ]]; then

    # 1. Get Dimensions
    TOTAL_WIDTH=$(echo "$FINAL_RES" | cut -d'x' -f1)
    TOTAL_HEIGHT=$(echo "$FINAL_RES" | cut -d'x' -f2)

    # Get Native Monitor Height
    NATIVE_RES=$(xrandr --query | grep ' primary ' | grep -oP '\d+x\d+' | head -1)
    if [ -z "$NATIVE_RES" ]; then
        NATIVE_RES=$(xrandr --query | grep ' connected' | grep -oP '\d+x\d+' | head -1)
    fi
    NATIVE_H=$(echo "$NATIVE_RES" | cut -d'x' -f2)

    # Safety fallback
    if [ "$TOTAL_HEIGHT" -lt "$NATIVE_H" ]; then NATIVE_H=$TOTAL_HEIGHT; fi

    # 2. Calculate Layout Coordinates

    # --- TOP SCREEN ---
    # Height = Native Monitor Height
    # Y Position = Center the native height within the total height
    T_H=$NATIVE_H
    T_Y=$(( (TOTAL_HEIGHT - NATIVE_H) / 2 ))

    # Width = Height * (5/3)
    T_W=$(awk -v h="$T_H" 'BEGIN {printf "%.0f", h * 5 / 3}')

    # Center Horizontally
    T_X=$(awk -v tw="$TOTAL_WIDTH" -v w="$T_W" 'BEGIN {printf "%.0f", (tw - w) / 2}')
    if [ "$T_X" -lt 0 ]; then T_X=0; fi

    # --- BOTTOM SCREEN ---
    # Height = The remaining space at the bottom (Total - (Top Y + Top Height))
    B_H=$(( TOTAL_HEIGHT - (T_Y + T_H) ))
    if [ "$B_H" -le 0 ]; then B_H=100; fi

    # Width = Height * (4/3)
    B_W=$(awk -v h="$B_H" 'BEGIN {printf "%.0f", h * 4 / 3}')

    # Y Position = Immediately after the Top Screen
    B_Y=$(( T_Y + T_H ))

    # Left Aligned (X = 0)
    B_X=0

    # 3. Update qt-config.ini

    update_ini() {
        local key=$1
        local val=$2
        local file=$3

        # 1. Update the value
        sed -i "s|^$key=.*|$key=$val|" "$file"

        # 2. DISABLE THE DEFAULT FLAG
        # We must escape the backslash: key\default -> key\\default in regex
        sed -i "s|^${key}\\\\default=.*|${key}\\\\default=false|" "$file"
    }

    # Set to Custom Layout (Option 6)
    update_ini "layout_option" "6" "$AZAHAR_CONFIG"

    # Set Top Screen
    update_ini "custom_top_x" "$T_X" "$AZAHAR_CONFIG"
    update_ini "custom_top_y" "$T_Y" "$AZAHAR_CONFIG"
    update_ini "custom_top_width" "$T_W" "$AZAHAR_CONFIG"
    update_ini "custom_top_height" "$T_H" "$AZAHAR_CONFIG"

    # Set Bottom Screen
    update_ini "custom_bottom_x" "$B_X" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_y" "$B_Y" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_width" "$B_W" "$AZAHAR_CONFIG"
    update_ini "custom_bottom_height" "$B_H" "$AZAHAR_CONFIG"

fi

# --- FIND PROTON ---
PROTON_BIN=""
for arg in "$@"; do
    if [[ "$arg" == *"/proton" ]]; then
        PROTON_BIN="$arg"
        break
    fi
done

if [ -z "$PROTON_BIN" ]; then
    if [[ "${ARG1,,}" != "help" ]]; then
         true
    fi
else
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
"$DESKTOP_NAME"="$FINAL_RES"
EOF
        "$PROTON_BIN" run regedit /S "$TMP_REG"
    fi
    rm -f "$TMP_REG"
fi

# --- LAUNCH GAME ---
if [[ "${ARG1,,}" != "help" ]]; then
    exec "$@"
fi
