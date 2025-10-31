#!/usr/bin/env python3
"""
wiper_pro_monitor.py
WIPER Pro — Advanced Defensive Wi-Fi Anomaly Monitor (Single file, fixed & hardened)

Notes:
- Defensive-only: NO packet injection, NO deauth sending.
- Works in two modes: live sniff (requires scapy & monitor-mode iface) or PCAP analysis.
- Optional simple Flask web UI (install flask to enable).
- Whitelist managed via JSON file. Alerts stored in JSON rotating list file.

Run examples:
  python3 wiper_pro_monitor_fixed.py --pcap capture.pcap
  sudo python3 wiper_pro_monitor_fixed.py --iface wlan0mon --web

"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque, Counter
from logging.handlers import RotatingFileHandler
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

# Optional dependencies
try:
    from flask import Flask, jsonify, request, send_file, abort
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

try:
    from scapy.all import sniff, rdpcap, RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ----------------------
# Configuration / Defaults
# ----------------------
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

DEFAULT_LOGFILE = os.path.join(LOG_DIR, "wiper_pro.log")
DEFAULT_JSON_ALERTS = os.path.join(LOG_DIR, "wiper_pro_alerts.json")
DEFAULT_WHITELIST = os.path.join(SCRIPT_DIR, "trusted_macs.json")

# Thresholds & windows
DEFAULT_FRAME_WINDOW = 5.0
DEFAULT_FRAME_THRESHOLD = 10
PROBE_THRESHOLD = 40
AUTH_THRESHOLD = 20
MAC_RANDOM_WINDOW = 10.0
MAC_RANDOM_THRESHOLD = 30
ALERT_SUPPRESSION_SECONDS = 30.0

# Channel hopping defaults
DEFAULT_CHANNELS = [1, 6, 11]
DEFAULT_HOP_INTERVAL = 2.0

# Logging rotation
LOG_MAX_BYTES = 5_000_000
LOG_BACKUP_COUNT = 5

# ----------------------
# Utilities / Logging
# ----------------------

def setup_logging(logfile: str = DEFAULT_LOGFILE) -> None:
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # prevent duplicate handlers
    logger.handlers = []
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt))
    fh = RotatingFileHandler(logfile, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    fh.setFormatter(logging.Formatter(fmt))
    logger.addHandler(ch)
    logger.addHandler(fh)
    logging.info("Logging initialized -> %s", logfile)


def now_ts() -> float:
    return time.time()


# ----------------------
# JSON alerts & whitelist helpers
# ----------------------

def init_json_alert_file(path: Optional[str]) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump([], f)


def append_json_alert(path: Optional[str], alert: Dict[str, Any], max_items: int = 1000) -> None:
    if not path:
        return
    try:
        with open(path, "r+") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
            data.append(alert)
            # keep only latest max_items to avoid unbounded growth
            if len(data) > max_items:
                data = data[-max_items:]
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
    except FileNotFoundError:
        try:
            with open(path, "w") as f:
                json.dump([alert], f, indent=2)
        except Exception:
            logging.exception("Failed to write JSON alert to %s", path)
    except Exception:
        logging.exception("Failed to write JSON alert to %s", path)


def read_json_alerts(path: str, limit: int = 100) -> List[Dict[str, Any]]:
    try:
        if not os.path.exists(path):
            return []
        with open(path, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                return []
            return data[-limit:]
    except Exception:
        logging.exception("Failed to read alerts %s", path)
        return []


def load_whitelist(path: Optional[str]) -> set:
    if not path:
        return set()
    try:
        if not os.path.exists(path):
            # initialize an empty whitelist file
            with open(path, "w") as f:
                json.dump([], f)
            return set()
        with open(path, "r") as f:
            data = json.load(f)
            return set(x.lower() for x in data if isinstance(x, str))
    except Exception:
        logging.exception("Failed to load whitelist %s", path)
        return set()


def save_whitelist(path: str, macs: Iterable[str]) -> None:
    try:
        with open(path, "w") as f:
            json.dump(list(macs), f, indent=2)
    except Exception:
        logging.exception("Failed to save whitelist %s", path)


# ----------------------
# Detection state & thread-safety
# ----------------------

class DetectionState:
    def __init__(self, frame_window: float = DEFAULT_FRAME_WINDOW):
        self.frame_window = float(frame_window)
        # keyed by (anomaly_type, src_mac) -> deque[timestamps]
        self.windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        # recent macs deque for randomization detection: deque[(ts, mac)]
        self.recent_macs: Deque[Tuple[float, str]] = deque()
        # association mapping client -> set of AP MACs (recent)
        self.associations: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        # last alert times for suppression
        self.last_alert_time: Dict[Tuple[str, str], float] = {}
        # lock for multi-threaded access
        self.lock = threading.Lock()

    def push(self, key: Tuple[str, str], ts: float) -> int:
        with self.lock:
            q = self.windows[key]
            q.append(ts)
            cutoff = ts - self.frame_window
            while q and q[0] < cutoff:
                q.popleft()
            return len(q)

    def clear_key(self, key: Tuple[str, str]) -> None:
        with self.lock:
            if key in self.windows:
                self.windows[key].clear()

    def push_mac_seen(self, mac: str, ts: float, window: float = MAC_RANDOM_WINDOW) -> int:
        with self.lock:
            self.recent_macs.append((ts, mac.lower()))
            cutoff = ts - window
            while self.recent_macs and self.recent_macs[0][0] < cutoff:
                self.recent_macs.popleft()
            unique = len(set(m for _, m in self.recent_macs))
            return unique

    def should_alert(self, anomaly_type: str, src: str, suppression_seconds: float = ALERT_SUPPRESSION_SECONDS) -> bool:
        key = (anomaly_type, src.lower())
        with self.lock:
            now = now_ts()
            last = self.last_alert_time.get(key, 0.0)
            if now - last >= suppression_seconds:
                self.last_alert_time[key] = now
                return True
            return False

    def push_association(self, client_mac: str, ap_mac: str, ts: float, window: float = DEFAULT_FRAME_WINDOW) -> set:
        """Record an association event (client -> ap). Returns set of current APs seen for client in window."""
        client = client_mac.lower()
        ap = ap_mac.lower()
        with self.lock:
            dq = self.associations[client]
            dq.append((ts, ap))
            cutoff = ts - window
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return set(a for _, a in dq)

    def clear_associations(self):
        with self.lock:
            self.associations.clear()


# ----------------------
# Packet helpers & classification
# ----------------------

def get_dot11_fields(pkt) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str], Optional[str]]:
    try:
        if not SCAPY_AVAILABLE or not pkt.haslayer(Dot11):
            return (None, None, None, None, None)
        dot11 = pkt.getlayer(Dot11)
        t = getattr(dot11, "type", None)
        s = getattr(dot11, "subtype", None)
        a1 = getattr(dot11, "addr1", None)
        a2 = getattr(dot11, "addr2", None)
        a3 = getattr(dot11, "addr3", None)
        return (t, s, a1, a2, a3)
    except Exception:
        return (None, None, None, None, None)


def classify_packet_type(pkt) -> Optional[str]:
    """Return a high-level type: DEAUTH/DISASSOC/AUTH/PROBE_REQ/BEACON/ASSOC_REQ/ASSOC_RESP or None."""
    try:
        if not SCAPY_AVAILABLE or not pkt.haslayer(Dot11):
            return None
        dot11 = pkt.getlayer(Dot11)
        t = getattr(dot11, "type", None)
        s = getattr(dot11, "subtype", None)
        # Management frames
        if t == 0:
            if s == 12:
                return "DEAUTH"
            if s == 10:
                return "DISASSOC"
            if s == 4:
                return "PROBE_REQ"
            if s == 11:
                return "AUTH"
            if s == 8:
                return "BEACON"
            # assoc req / resp / reassoc
            if s == 0:
                return "ASSOC_REQ"
            if s == 1:
                return "ASSOC_RESP"
            if s == 2:
                return "REASSOC_REQ"
            if s == 3:
                return "REASSOC_RESP"
    except Exception:
        pass
    return None


# ----------------------
# Main Detector class
# ----------------------

class WiperProDetector:
    def __init__(self,
                 frame_threshold: int = DEFAULT_FRAME_THRESHOLD,
                 frame_window: float = DEFAULT_FRAME_WINDOW,
                 json_alerts_path: Optional[str] = DEFAULT_JSON_ALERTS,
                 whitelist_path: Optional[str] = DEFAULT_WHITELIST):
        self.frame_threshold = int(frame_threshold)
        self.frame_window = float(frame_window)
        self.json_alerts_path = json_alerts_path
        init_json_alert_file(self.json_alerts_path)
        self.whitelist_path = whitelist_path
        self.whitelist = load_whitelist(whitelist_path) if whitelist_path else set()
        self.state = DetectionState(frame_window=self.frame_window)
        self.counters = Counter()
        self.lock = threading.Lock()

    def reload_whitelist(self):
        if self.whitelist_path:
            self.whitelist = load_whitelist(self.whitelist_path)
            logging.info("Whitelist reloaded: %d entries", len(self.whitelist))

    def in_whitelist(self, mac: str) -> bool:
        if not mac:
            return False
        return mac.lower() in self.whitelist

    def _alert(self, anom_type: str, src: str, extra: Optional[Dict[str, Any]] = None) -> None:
        src_norm = (src or "<unknown>").lower()
        if self.in_whitelist(src_norm):
            logging.debug("Skipping alert for whitelisted MAC %s", src_norm)
            return
        if not self.state.should_alert(anom_type, src_norm):
            logging.debug("Suppressed duplicate alert: %s from %s", anom_type, src_norm)
            return
        ts = now_ts()
        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "type": anom_type,
            "source": src_norm,
            "message": f"Detected {anom_type}",
            "window_seconds": self.frame_window,
            "os": platform.system(),
        }
        if extra:
            alert.update(extra)
        logging.warning("ALERT: %s from %s -- %s", anom_type, src_norm, extra or {})
        append_json_alert(self.json_alerts_path, alert)
        with self.lock:
            self.counters["alerts"] += 1

    def process_packet(self, pkt) -> None:
        try:
            ttype = classify_packet_type(pkt)
            if not ttype:
                return
            t, s, a1, a2, a3 = get_dot11_fields(pkt)
            src = a2 or "<unknown>"
            ts = now_ts()

            # always count management frame seen
            self.counters[f"seen_{ttype}"] += 1

            # track macs for randomization detection
            unique_macs = self.state.push_mac_seen(src, ts)

            # association tracking: assoc-req/resp and reassoc
            if ttype in ("ASSOC_REQ", "ASSOC_RESP", "REASSOC_REQ", "REASSOC_RESP"):
                client = a2 or "<unknown>"
                ap = a1 or "<unknown>"
                current_aps = self.state.push_association(client, ap, ts, window=self.frame_window * 6)
                logging.info("Association: client=%s -> ap=%s (recent APs=%s)", client, ap, list(current_aps))
                if len(current_aps) > 1:
                    self._alert("CLIENT_FAST_ROAMING_OR_SPOOF", client, extra={"recent_aps": list(current_aps)})
                return

            # disassociation and deauth floods
            threshold_map = {
                "DEAUTH": max(3, self.frame_threshold),
                "DISASSOC": max(3, self.frame_threshold),
                "PROBE_REQ": PROBE_THRESHOLD,
                "AUTH": AUTH_THRESHOLD,
                "BEACON": max(10, self.frame_threshold),
            }

            threshold = threshold_map.get(ttype, self.frame_threshold)
            key = (ttype, src)
            count = self.state.push(key, ts)
            logging.info("Detected %s from %s (count=%d/%d)", ttype, src, count, threshold)

            # Beacon heuristics
            if ttype == "BEACON":
                try:
                    pkt_len = len(pkt)
                    if pkt_len > 300 and self.state.should_alert("BEACON_ANOMALY", src):
                        self._alert("BEACON_ANOMALY", src, extra={"pkt_len": pkt_len})
                except Exception:
                    pass

            # Flood detection
            if count >= threshold:
                extra = {"count": count, "threshold": threshold}
                # capture SSID on beacon or probe (best effort)
                try:
                    if SCAPY_AVAILABLE and pkt.haslayer(Dot11Beacon):
                        info = pkt.getlayer(Dot11Beacon).network_stats().get('ssid') if hasattr(pkt.getlayer(Dot11Beacon), 'network_stats') else None
                        if info:
                            extra["ssid"] = info
                    elif SCAPY_AVAILABLE and pkt.haslayer(Dot11ProbeReq):
                        # probe req SSID may be in info field
                        info = getattr(pkt.getlayer(Dot11ProbeReq), 'info', b'')
                        if info:
                            extra["ssid"] = info.decode(errors='ignore') if isinstance(info, (bytes, bytearray)) else str(info)
                except Exception:
                    logging.debug("Failed to read SSID from packet")

                self._alert(f"{ttype}_FLOOD", src, extra=extra)
                self.state.clear_key(key)

            # MAC randomization detection (global)
            if unique_macs >= MAC_RANDOM_THRESHOLD:
                if self.state.should_alert("MAC_RANDOMIZATION", "<multiple>"):
                    self._alert("MAC_RANDOMIZATION", "<multiple>", extra={"unique_macs": unique_macs})
                with self.state.lock:
                    self.state.recent_macs.clear()

        except Exception:
            logging.exception("Error processing packet")

    def process_packets_iterable(self, packets: Iterable[Any]) -> None:
        for pkt in packets:
            self.process_packet(pkt)

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            return {"counters": dict(self.counters), "whitelist_count": len(self.whitelist)}


# ----------------------
# Channel Hopper (Linux only)
# ----------------------

class ChannelHopper(threading.Thread):
    def __init__(self, iface: str, channels: List[int], interval: float = DEFAULT_HOP_INTERVAL):
        super().__init__(daemon=True)
        self.iface = iface
        self.channels = list(channels)
        self.interval = float(interval)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        if platform.system() != "Linux":
            logging.info("Channel hopping is only supported on Linux in this implementation.")
            return
        logging.info("Channel hopper started on iface=%s channels=%s interval=%.1fs", self.iface, self.channels, self.interval)
        idx = 0
        while not self._stop.is_set():
            ch = self.channels[idx % len(self.channels)]
            try:
                # Use iw to set channel; user must ensure interface is in monitor mode and has privileges
                subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logging.debug("Set channel %s on %s", ch, self.iface)
            except Exception:
                logging.exception("Channel hop command failed")
            idx += 1
            self._stop.wait(self.interval)
        logging.info("Channel hopper stopped.")


# ----------------------
# Web UI (Flask)
# ----------------------

WEB_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>WIPER Pro Dashboard</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; margin: 16px; background:#0f1720; color:#e6eef8; }
.card { background:#111827; padding:12px; border-radius:8px; margin-bottom:12px; }
table { width:100%; border-collapse:collapse; }
th,td { padding:8px; text-align:left; border-bottom:1px solid #233141; }
.muted { color:#9aa7b8; font-size:0.9em; }
</style>
</head>
<body>
<h2>WIPER Pro Dashboard</h2>
<div class="card">
<div class="muted">Status</div>
<div id="status">Loading...</div>
</div>
<div class="card">
<div class="muted">Recent Alerts</div>
<table id="alerts_table"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Info</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
<div class="muted">Counters</div>
<pre id="counters">Loading...</pre>
</div>
<script>
async function fetchJSON(path){ let r=await fetch(path); if(!r.ok) return null; return r.json(); }
async function refresh(){
let alerts = await fetchJSON('/api/alerts?limit=50');
let counters = await fetchJSON('/api/counters');
let status = await fetchJSON('/api/status');
let tb = document.querySelector('#alerts_table tbody');
tb.innerHTML = '';
if(alerts && alerts.alerts){
for(let a of alerts.alerts.reverse()){
let tr = document.createElement('tr');
tr.innerHTML = `<td>${a.timestamp}</td><td>${a.type}</td><td>${a.source}</td><td>${JSON.stringify(a.message || a.ssid || a.count || '')}</td>`;
tb.appendChild(tr);
}
}
document.getElementById('counters').textContent = counters ? JSON.stringify(counters, null, 2) : '—';
document.getElementById('status').textContent = status ? status : '—';
}
setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""


class WebServer:
    def __init__(self, detector: WiperProDetector, json_alerts_path: str, host: str = "127.0.0.1", port: int = 8080):
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask is not installed. Install with: python3 -m pip install flask")
        self.app = Flask("wiper_pro_dashboard")
        self.detector = detector
        self.json_alerts_path = json_alerts_path
        self.host = host
        self.port = port
        self._register_routes()

    def _read_alerts_tail(self, limit: int = 100) -> List[Dict[str, Any]]:
        return read_json_alerts(self.json_alerts_path, limit=limit)

    def _register_routes(self):
        @self.app.route('/')
        def index():
            return WEB_TEMPLATE

        @self.app.route('/api/alerts')
        def api_alerts():
            try:
                limit = int(request.args.get('limit', '100'))
            except Exception:
                limit = 100
            alerts = self._read_alerts_tail(limit=limit)
            return jsonify({'alerts': alerts})

        @self.app.route('/api/counters')
        def api_counters():
            return jsonify(self.detector.summary())

        @self.app.route('/api/status')
        def api_status():
            return jsonify({'status': 'running', 'os': platform.system()})

        @self.app.route('/api/whitelist', methods=['GET', 'POST', 'PUT'])
        def api_whitelist():
            if request.method == 'GET':
                return jsonify({'whitelist': list(self.detector.whitelist)})
            try:
                data = request.get_json(force=True)
                macs = set(x.lower() for x in data.get('whitelist', []))
                save_whitelist(self.json_alerts_path.replace('alerts.json', 'trusted_macs.json') if False else self.detector.whitelist_path or DEFAULT_WHITELIST, macs)
                # reload into detector
                self.detector.reload_whitelist()
                return jsonify({'ok': True, 'whitelist': list(self.detector.whitelist)})
            except Exception:
                return jsonify({'ok': False}), 400

    def run(self):
        # Note: in production do not use flask builtin server; use a proper WSGI server.
        self.app.run(host=self.host, port=self.port, debug=False)


# ----------------------
# CLI / Orchestration
# ----------------------

def sniff_worker(detector: WiperProDetector, iface: str, packet_limit: Optional[int] = None, stop_event: Optional[threading.Event] = None):
    if not SCAPY_AVAILABLE:
        logging.error("Scapy not available, cannot sniff live")
        return

    def callback(pkt):
        try:
            detector.process_packet(pkt)
        except Exception:
            logging.exception("Error in packet callback")
        if packet_limit is not None:
            # we can't stop easily from here without global counters; rely on stop_event
            pass

    # sniff blocking; user must run with privileges and monitor-mode interface
    sniff(iface=iface, prn=callback, store=False)


def pcap_worker(detector: WiperProDetector, pcap_path: str):
    if not SCAPY_AVAILABLE:
        logging.error("Scapy not available, cannot read pcap")
        return
    try:
        pkts = rdpcap(pcap_path)
        logging.info("Loaded %d packets from %s", len(pkts), pcap_path)
        detector.process_packets_iterable(pkts)
    except Exception:
        logging.exception("Failed to process pcap %s", pcap_path)


def main():
    parser = argparse.ArgumentParser(description='WIPER Pro — Defensive Wi-Fi Anomaly Monitor')
    parser.add_argument('--iface', help='Interface in monitor mode for live sniffing (e.g. wlan0mon)')
    parser.add_argument('--pcap', help='Path to PCAP file to analyze')
    parser.add_argument('--web', action='store_true', help='Run local web dashboard (requires flask)')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host')
    parser.add_argument('--port', default=8080, type=int, help='Web server port')
    parser.add_argument('--whitelist', default=DEFAULT_WHITELIST, help='Trusted MAC whitelist JSON file')
    parser.add_argument('--alerts', default=DEFAULT_JSON_ALERTS, help='JSON alerts output file')
    parser.add_argument('--channels', nargs='+', type=int, default=DEFAULT_CHANNELS, help='Channels to hop (Linux)')
    parser.add_argument('--hop-interval', type=float, default=DEFAULT_HOP_INTERVAL, help='Channel hop interval seconds')
    args = parser.parse_args()

    setup_logging()

    detector = WiperProDetector(frame_threshold=DEFAULT_FRAME_THRESHOLD,
                                frame_window=DEFAULT_FRAME_WINDOW,
                                json_alerts_path=args.alerts,
                                whitelist_path=args.whitelist)

    # optional channel hopper
    hopper = None
    if args.iface and platform.system() == 'Linux':
        try:
            hopper = ChannelHopper(args.iface, args.channels, interval=args.hop_interval)
            hopper.start()
        except Exception:
            logging.exception("Failed to start channel hopper")

    websrv = None
    web_thread = None
    if args.web:
        if not FLASK_AVAILABLE:
            logging.error("Flask is not installed. Install with: python3 -m pip install flask")
        else:
            try:
                websrv = WebServer(detector, json_alerts_path=args.alerts, host=args.host, port=args.port)
                web_thread = threading.Thread(target=websrv.run, daemon=True)
                web_thread.start()
                logging.info("Web UI started on http://%s:%d", args.host, args.port)
            except Exception:
                logging.exception("Failed to start web UI")

    try:
        if args.pcap:
            pcap_worker(detector, args.pcap)
        elif args.iface:
            if not SCAPY_AVAILABLE:
                logging.error("Scapy not installed. Live sniffing unavailable. Install scapy: python3 -m pip install scapy")
            else:
                logging.info("Starting live sniff on iface=%s (monitor mode required)", args.iface)
                sniff_worker(detector, args.iface)
        else:
            logging.info("No input selected. Use --pcap or --iface. Exiting.")
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
    finally:
        if hopper:
            hopper.stop()
        logging.info("Exiting")


if __name__ == '__main__':
    main()
