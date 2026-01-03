#!/bin/bash

# --- SANITIZE INPUT (Fix Windows copy-paste issues) ---
# Removes invisible carriage returns often caused by copy-pasting
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

EXAMPLES:
  script.sh off %command%
  script.sh H+1080 %command%
"
    # 1. Try KDialog (Native for Bazzite/KDE/Steam Deck Desktop)
    if command -v kdialog &> /dev/null; then
        kdialog --msgbox "$HELP_TEXT" --title "Proton Resolution Help"

    # 2. Try Zenity (Standard Linux fallback)
    elif command -v zenity &> /dev/null; then
        zenity --info --title="Proton Resolution Help" --text="$HELP_TEXT" --width=500

    # 3. Fallback: Force a terminal window if UI fails
    elif command -v konsole &> /dev/null; then
        konsole --hold -e echo "$HELP_TEXT"
    elif command -v xterm &> /dev/null; then
        xterm -hold -e echo "$HELP_TEXT"
    else
        # 4. Last Resort: Dump to a text file on desktop so you can see it worked
        echo "$HELP_TEXT" > ~/Desktop/proton_help_output.txt
    fi

    exit 0
}

# --- PARSE ARGUMENTS ---
# We use case-insensitive matching (${var,,})

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
         # Silent fail protection
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
