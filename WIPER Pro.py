#!/usr/bin/env bash
# wiper_defensive_launcher.sh
# Hardened / improved interactive launcher for WIPER_Pro.py
# Educational / Defensive only.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTOR="WIPER_Pro.py"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"

# Colors (only if output is a TTY)
if [ -t 1 ]; then
  YELLOW=$'\033[1;33m'
  GREEN=$'\033[1;32m'
  RED=$'\033[1;31m'
  RESET=$'\033[0m'
else
  YELLOW="" ; GREEN="" ; RED="" ; RESET=""
fi

# State for cleanup
ORIG_IFACE_STATE=""
IFACE_CHANGED=false
MON_IFACE=""

function die() {
    echo -e "${RED}ERROR:${RESET} $*" >&2
    exit 1
}

function banner() {
    if command -v figlet &>/dev/null; then
        figlet WIPER
    else
        echo "=== WIPER PRO (Defensive Edu Edition) ==="
    fi
    echo "Educational / Defensive Only. Use on your own lab or with permission."
    echo "Logs: $LOG_DIR"
    echo
}

function check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Note: some actions require root. The launcher will call sudo as needed."
    fi
}

function check_tool() {
    local t="$1"
    if ! command -v "$t" &>/dev/null; then
        echo -e "${YELLOW}Warning:${RESET} $t not found in PATH."
        return 1
    fi
    return 0
}

function check_dependencies() {
    local deps=(python3 tcpdump airodump-ng iw ip airmon-ng)
    echo "Checking dependencies..."
    local missing=()
    for d in "${deps[@]}"; do
        if ! check_tool "$d"; then
            missing+=("$d")
        fi
    done
    if [ "${#missing[@]}" -ne 0 ]; then
        echo -e "${YELLOW}Missing tools:${RESET} ${missing[*]}"
        echo "Install them with your package manager (apt/pacman/yum) or from aircrack-ng suite where appropriate."
    else
        echo -e "${GREEN}All required tools appear present.${RESET}"
    fi
}

function detector_exists() {
    if [ ! -f "$SCRIPT_DIR/$DETECTOR" ]; then
        die "Detector script not found: $SCRIPT_DIR/$DETECTOR"
    fi
}

# Attempt to restore interface if we changed anything
function cleanup() {
    local rc=$?
    if $IFACE_CHANGED && [ -n "$MON_IFACE" ]; then
        echo "Attempting to restore $MON_IFACE to managed mode..."
        if command -v iw &>/dev/null; then
            sudo ip link set "$MON_IFACE" down || true
            sudo iw dev "$MON_IFACE" set type managed 2>/dev/null || true
            sudo ip link set "$MON_IFACE" up || true
        elif command -v airmon-ng &>/dev/null; then
            sudo airmon-ng stop "$MON_IFACE" 2>/dev/null || true
        fi
        echo "Restore attempted."
    fi
    exit $rc
}
trap cleanup INT TERM EXIT

function interface_setup() {
    read -r -p "Interface name (default wlan0): " IFACE
    IFACE=${IFACE:-wlan0}

    echo "Checking interface: $IFACE"
    if ! ip link show "$IFACE" &>/dev/null; then
        die "Interface $IFACE does not exist."
    fi

    echo "Attempting to set $IFACE to monitor mode (non-destructive)..."
    # Try airmon-ng first (it handles dependencies)
    if command -v airmon-ng &>/dev/null; then
        echo "Using airmon-ng to start monitor mode (safer for complex drivers)..."
        sudo airmon-ng check kill >/dev/null 2>&1 || true
        # airmon-ng may create interface like wlan0mon
        if sudo airmon-ng start "$IFACE"; then
            # try to find resulting monitor interface
            MON_IFACE=$(iw dev | awk '/Interface/ {print $2}' | grep -E "^${IFACE}|mon" | head -n1 || true)
            IFACE_CHANGED=true
            echo -e "${GREEN}Monitor interface likely: ${MON_IFACE:-$IFACE}${RESET}"
            return 0
        else
            echo "airmon-ng start failed or is not ideal; falling back to iw."
        fi
    fi

    # Fallback to iw
    if command -v iw &>/dev/null; then
        sudo ip link set "$IFACE" down || true
        if sudo iw dev "$IFACE" set type monitor 2>/dev/null; then
            sudo ip link set "$IFACE" up || true
            MON_IFACE="$IFACE"
            IFACE_CHANGED=true
            echo -e "${GREEN}Set $IFACE to monitor mode.${RESET}"
            return 0
        else
            echo "iw failed to set monitor mode (driver may not support it)."
            sudo ip link set "$IFACE" up || true
            return 1
        fi
    fi

    die "No method available to set monitor mode. Install 'airmon-ng' or 'iw'."
}

function passive_scan() {
    read -r -p "Enter monitor interface (e.g., wlan0mon) [default wlan0]: " MON
    MON=${MON:-wlan0}
    if ! ip link show "$MON" &>/dev/null; then
        echo "Interface $MON not found. Try interface_setup first."
        read -n1 -s -r -p "Press any key to continue..."
        return
    fi

    if command -v airodump-ng &>/dev/null; then
        echo "Running airodump-ng on $MON. Press Ctrl+C to stop."
        sudo airodump-ng "$MON"
    else
        echo "airodump-ng not available. Using tcpdump to capture management frames (limited)."
        echo "Capturing 60 seconds of traffic to $LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).pcap"
        sudo timeout 60 tcpdump -i "$MON" -w "${LOG_DIR}/scan_$(date +%Y%m%d_%H%M%S).pcap" || true
    fi
    read -n1 -s -r -p "Press any key to continue..."
}

function run_detector_live() {
    detector_exists
    read -r -p "Monitor interface for live sniff (e.g., wlan0mon) [default wlan0]: " MON
    MON=${MON:-wlan0}
    if ! ip link show "$MON" &>/dev/null; then
        die "Interface $MON not present. Run Interface setup first."
    fi

    read -r -p "Threshold frames to alert [default 10]: " THR
    THR=${THR:-10}
    read -r -p "Time window seconds [default 5]: " WIN
    WIN=${WIN:-5}
    LOG="${LOG_DIR}/wiper_pro_live_$(date +%Y%m%d_%H%M%S).log"
    JSON="${LOG_DIR}/alerts_live_$(date +%Y%m%d_%H%M%S).json"
    echo "Starting detector (live). Logs -> $LOG JSON alerts -> $JSON"

    # Use sudo only when necessary; propagate environment minimally
    sudo -E python3 "$SCRIPT_DIR/$DETECTOR" --iface "$MON" --threshold "$THR" --window "$WIN" --logfile "$LOG" --json-alerts "$JSON"
}

function run_detector_pcap() {
    detector_exists
    read -r -p "Path to PCAP file for offline testing: " PCAP
    if [ ! -f "$PCAP" ]; then
        echo "PCAP not found."
        read -n1 -s -r -p "Press any key to continue..."
        return
    fi
    read -r -p "Threshold frames to alert [default 10]: " THR
    THR=${THR:-10}
    read -r -p "Time window seconds [default 5]: " WIN
    WIN=${WIN:-5}
    LOG="${LOG_DIR}/wiper_pro_offline_$(date +%Y%m%d_%H%M%S).log"
    JSON="${LOG_DIR}/alerts_offline_$(date +%Y%m%d_%H%M%S).json"
    echo "Processing PCAP: $PCAP -> log: $LOG json: $JSON"
    python3 "$SCRIPT_DIR/$DETECTOR" --pcap "$PCAP" --threshold "$THR" --window "$WIN" --logfile "$LOG" --json-alerts "$JSON"
    echo "Done. Check JSON alerts: $JSON"
    read -n1 -s -r -p "Press any key to continue..."
}

function list_logs() {
    ls -lh "$LOG_DIR" 2>/dev/null || echo "Log directory is empty or does not exist."
    read -n1 -s -r -p "Press any key to continue..."
}

function show_menu() {
    check_root
    while true; do
        clear
        banner
        check_dependencies
        echo -e "${YELLOW}Select an action:${RESET}"
        echo "1) Interface setup -> set monitor mode"
        echo "2) Passive scan (airodump / tcpdump) for target discovery"
        echo "3) Run PRO Detector (live sniff)"
        echo "4) Run PRO Detector (offline PCAP test)"
        echo "5) List logs"
        echo "6) Exit"
        read -r -p "Choice: " CH
        case "$CH" in
            1) interface_setup ;;
            2) passive_scan ;;
            3) run_detector_live ;;
            4) run_detector_pcap ;;
            5) list_logs ;;
            6) echo "Bye"; exit 0 ;;
            *) echo "Invalid" ; sleep 1 ;;
        esac
    done
}

# Start
show_menu
