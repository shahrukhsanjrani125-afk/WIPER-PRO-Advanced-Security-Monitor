#!/usr/bin/env bash
# =====================================================================
#  WIPER PRO — Defensive / Educational Wi-Fi Monitor Suite
#  Version: v4.2 (Stable Clean Edition)
#  Author: Muhammad Shahrukh
#  Mode: Defensive | Educational | Non-offensive
#  License: MIT-style (educational, non-commercial)
# =====================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"
DETECTOR_VERSION="WIPER_PRO_v4.2"

# ---------- COLORS ----------
if [ -t 1 ]; then
  YELLOW=$'\033[1;33m'; GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; RESET=$'\033[0m'
else
  YELLOW=""; GREEN=""; RED=""; RESET=""
fi

# ---------- UTILS ----------
die(){ echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }
info(){ echo -e "${GREEN}$*${RESET}"; }
warn(){ echo -e "${YELLOW}$*${RESET}"; }

check_tool(){ command -v "$1" >/dev/null 2>&1; }

ensure_root_prompt(){
  if [ "$(id -u)" -ne 0 ]; then
    warn "Note: Some actions (sniffing, monitor mode) may require sudo privileges."
  fi
}

# ---------- BANNER ----------
banner(){
  clear
  if command -v figlet &>/dev/null; then
    figlet -w 120 -f slant "WIPER PRO"
  else
    echo "=== WIPER PRO (Defensive Edu Edition) ==="
  fi
  echo "Version: $DETECTOR_VERSION"
  echo "Educational / Defensive Use Only (Wi-Fi anomaly monitoring)"
  echo "Logs: $LOG_DIR"
  echo
}

# ---------- DEPENDENCY CHECK ----------
check_dependencies(){
  local deps=(python3 ip iw airmon-ng tcpdump airodump-ng)
  local missing=()
  for d in "${deps[@]}"; do
    if ! check_tool "$d"; then missing+=("$d"); fi
  done

  if [ "${#missing[@]}" -ne 0 ]; then
    warn "Missing tools: ${missing[*]}"
    warn "Offline PCAP analysis will still work (requires python3 + scapy)."
  else
    info "All required tools found."
  fi
}

# ---------- CLEANUP STATE AND TRAP (ADDED FOR SAFETY) ----------
MON_IFACE_TO_RESTORE=""

restore_managed_mode(){
  local IFACE="$1"
  if check_tool iw; then
    sudo ip link set "$IFACE" down || true
    sudo iw dev "$IFACE" set type managed 2>/dev/null || true
    sudo ip link set "$IFACE" up || true
    info "Restored $IFACE to managed mode."
  elif check_tool airmon-ng; then
    sudo airmon-ng stop "$IFACE" >/dev/null 2>&1 || true
    info "Stopped monitor interface via airmon-ng."
  fi
}

cleanup_on_exit() {
    local rc=$?
    # Ensure this runs only once or when necessary
    if [ -n "$MON_IFACE_TO_RESTORE" ]; then
        warn "Script interrupted. Attempting to restore $MON_IFACE_TO_RESTORE."
        restore_managed_mode "$MON_IFACE_TO_RESTORE" || true
    fi
    # Only if the script ends via trap (INT/TERM), then exit
    # EXIT signal is handled by the main flow or the shell itself, 
    # but we trap INT/TERM for the cleanup function.
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}
trap cleanup_on_exit INT TERM

# ---------- NETWORK HELPERS ----------
default_iface(){
  ip -o link show | awk -F': ' '{print $2}' | grep -E 'wl|wlan' | head -n1 || echo "wlan0"
}

set_monitor_mode(){
  local IFACE="$1"
  if ! ip link show "$IFACE" >/dev/null 2>&1; then die "Interface $IFACE not found."; fi

  local MON
  if check_tool airmon-ng; then
    sudo airmon-ng check kill >/dev/null 2>&1 || true
    sudo airmon-ng start "$IFACE" >/dev/null 2>&1 || warn "airmon-ng failed; using iw fallback."
    MON=$(iw dev | awk '/Interface/ {print $2}' | grep -E "^${IFACE}mon|mon0" | head -n1 || true)
    if [ -n "$MON" ]; then
        MON_IFACE_TO_RESTORE="$MON" # <--- NEW: Set the interface to be cleaned up
        echo "$MON"
        return 0
    fi
  fi

  if check_tool iw; then
    sudo ip link set "$IFACE" down || true
    if sudo iw dev "$IFACE" set type monitor 2>/dev/null; then
      sudo ip link set "$IFACE" up || true
      MON_IFACE_TO_RESTORE="$IFACE" # <--- NEW: Set the interface to be cleaned up
      echo "$IFACE"; return 0
    fi
    sudo ip link set "$IFACE" up || true
    warn "Monitor mode not supported."
  fi
  return 1
}

# ---------- MENU OPTIONS ----------
menu_interface_setup(){
  local def=$(default_iface)
  read -r -p "Interface name [default: ${def}]: " IFACE
  IFACE=${IFACE:-$def}
  info "Enabling monitor mode on $IFACE..."
  local MON
  MON=$(set_monitor_mode "$IFACE" || true)
  if [ -n "$MON" ]; then
    info "Monitor interface active: $MON"
  else
    warn "Monitor mode setup failed."
  fi
  read -n1 -s -r -p "Press any key to return..."
}

menu_passive_scan(){
  read -r -p "Monitor interface [default: wlan0]: " MON
  MON=${MON:-wlan0}

  if ! ip link show "$MON" >/dev/null 2>&1; then
    warn "Interface $MON not found. Run setup first."
    read -n1 -s -r -p "Press any key..."
    return
  fi

  if check_tool airodump-ng; then
    info "Launching airodump-ng on $MON (Ctrl+C to stop)"
    # Pass the interface to trap, so it cleans up if interrupted during scan
    MON_IFACE_TO_RESTORE="$MON" # <--- Safety Check: Ensure trap variable is set
    sudo airodump-ng "$MON"
  else
    local PCAP="${LOG_DIR}/scan_$(date +%Y%m%d_%H%M%S).pcap"
    info "Capturing traffic for 60s -> $PCAP"
    sudo timeout 60 tcpdump -i "$MON" -w "$PCAP" || true
    info "Saved capture to: $PCAP"
  fi
  MON_IFACE_TO_RESTORE="" # <--- Clear the trap variable after scan finishes normally
  read -n1 -s -r -p "Press any key to return..."
}

menu_analyze_pcap(){
  read -r -p "Path to PCAP file: " PCAP
  [ ! -f "$PCAP" ] && die "PCAP file not found."

  local LOG="${LOG_DIR}/analysis_$(date +%Y%m%d_%H%M%S).log"
  local JSON="${LOG_DIR}/alerts_$(date +%Y%m%d_%H%M%S).json"

  info "Analyzing $PCAP..."
  python3 - "$PCAP" "$LOG" "$JSON" <<'PYCODE'
# =====================================================================
# Embedded Python Analyzer (Defensive Only)
# Detects beacon flood or excessive management anomalies
# =====================================================================
import sys, os, json, logging, time
from collections import defaultdict, deque

try:
    from scapy.all import rdpcap, Dot11, Dot11Elt, Dot11Beacon
except ImportError:
    print("Scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

pcap, logf, jsonf = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(os.path.dirname(logf), exist_ok=True)

logging.basicConfig(filename=logf, level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")
print(f"Analyzing {pcap} ...")

AP_STATE = defaultdict(dict)
RECENT = deque(maxlen=5000)

def get_ssid(pkt):
    try:
        el = pkt.getlayer(Dot11Elt)
        while el:
            if el.ID == 0:
                return el.info.decode(errors="ignore")
            el = el.payload.getlayer(Dot11Elt)
    except Exception:
        return "<hidden>"
    return "<hidden>"

def analyze(pkt):
    if not pkt.haslayer(Dot11Beacon): return
    ssid = get_ssid(pkt)
    bssid = pkt.addr3
    if not bssid: return

    AP_STATE[ssid][bssid] = {"seen": time.time()}
    RECENT.append((time.time(), ssid, bssid))

    # Simple detection: repeated beacon bursts
    # Note: Time check here is based on local system time, which is not precise for PCAP analysis
    # but serves as a placeholder logic for the embedded script example.
    recent = [x for x in RECENT if x[0] > time.time() - 5 and x[2] == bssid] 
    if len(recent) > 20:
        alert = {"time": time.time(), "type": "beacon_flood",
                 "ssid": ssid, "bssid": bssid}
        logging.warning(f"Beacon flood suspected: {ssid} ({bssid})")
        with open(jsonf, "a") as f:
            f.write(json.dumps(alert) + "\n")

pkts = rdpcap(pcap)
for p in pkts: analyze(p)
print(f"Done. Alerts written to {jsonf}")
# =====================================================================
PYCODE

  read -n1 -s -r -p "Press any key to return..."
}

menu_list_logs(){
  ls -lh "$LOG_DIR" 2>/dev/null || echo "No logs yet."
  read -n1 -s -r -p "Press any key..."
}

menu_exit(){
  # Restore all active monitor interfaces before final exit
  info "Restoring all monitored interfaces before exit..."
  for i in $(iw dev | awk '/Interface/{print $2}'); do
    restore_managed_mode "$i" || true
  done
  info "Goodbye!"
  exit 0
}

# ---------- MAIN MENU ----------
show_menu(){
  ensure_root_prompt
  while true; do
    banner
    check_dependencies
    echo -e "${YELLOW}Select an action:${RESET}"
    echo "1) Setup monitor mode"
    echo "2) Passive scan"
    echo "3) Analyze PCAP (offline mode)"
    echo "4) View logs"
    echo "5) Exit"
    read -r -p "Choice [1-5]: " CH
    case "$CH" in
      1) menu_interface_setup ;;
      2) menu_passive_scan ;;
      3) menu_analyze_pcap ;;
      4) menu_list_logs ;;
      5) menu_exit ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

# ---------- START ----------
show_menu
