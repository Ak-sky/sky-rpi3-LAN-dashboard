#!/usr/bin/env python3
"""Minimal stdlib-only LAN device dashboard: nmap scan in a background
thread, cached results served as JSON + a live-refreshing HTML page."""
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8000
SUBNET = "192.168.1.0/24"
SCAN_INTERVAL = 90  # seconds; a full /24 sweep takes ~20-25s on a Pi 3
DB_PATH = os.path.expanduser("~/lan-dashboard-data/devices.json")

WIFI_IFACE = "wlan0"
INTERNET_CHECK_HOST = "8.8.8.8"
INTERNET_CHECK_PORT = 53
INTERNET_CHECK_INTERVAL = 20  # seconds
ALARM_WAV = os.path.expanduser("~/police_s.wav")

PUBLIC_IP_CACHE_TTL = 1800  # public IP rarely changes; don't hit the external service often

# nmap's bundled OUI DB (esp. on older versions) misses a lot of consumer
# gear -- this is just a tiny supplement for prefixes we know matter here,
# not an attempt at a full vendor database.
VENDOR_HINTS = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "28:cd:c1": "Raspberry Pi Trading",
}

_lock = threading.Lock()
_devices_db = {}
_last_scan = {"at": None, "at_epoch": None, "duration_s": None, "hosts_up": None, "error": None}

_internet_state = {"up": None, "latency_ms": None, "last_checked": None}
_internet_events = []
_public_ip_cache = {"ip": None, "ts": 0}


def get_self_identity():
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show", WIFI_IFACE],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"link/ether ([0-9a-fA-F:]+)", out)
        mac = m.group(1).upper() if m else None
    except Exception:
        mac = None
    try:
        ip_out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", WIFI_IFACE],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_out)
        ip = m.group(1) if m else None
    except Exception:
        ip = None
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    return {"ip": ip, "mac": mac, "hostname": hostname}


def run_vcgencmd(*args):
    try:
        return subprocess.run(
            ["vcgencmd", *args], capture_output=True, text=True, timeout=3
        ).stdout.strip()
    except Exception as e:
        return f"error: {e}"


def get_self_wifi():
    try:
        with open("/proc/net/wireless") as f:
            for line in f:
                if line.strip().startswith(WIFI_IFACE):
                    fields = line.split()
                    quality = float(fields[2].rstrip("."))
                    level = float(fields[3].rstrip("."))
                    return {"rssi_dbm": level, "link_quality_pct": round(quality / 70 * 100, 1)}
    except Exception as e:
        return {"error": str(e)}
    return {"rssi_dbm": None, "link_quality_pct": None}


def get_self_ssid():
    """This Pi runs plain wpa_supplicant, not NetworkManager (nmcli errors
    with "NetworkManager is not running"), so query wpa_cli directly."""
    try:
        out = subprocess.run(
            ["sudo", "wpa_cli", "-i", WIFI_IFACE, "status"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for line in out.splitlines():
            if line.startswith("ssid="):
                return line.split("=", 1)[1]
    except Exception as e:
        return {"error": str(e)}
    return None


def get_self_temp():
    raw = run_vcgencmd("measure_temp")
    m = re.search(r"temp=([\d.]+)", raw)
    return float(m.group(1)) if m else raw


def get_self_voltage():
    raw = run_vcgencmd("measure_volts")
    m = re.search(r"volt=([\d.]+)V", raw)
    return float(m.group(1)) if m else raw


def get_self_throttled():
    raw = run_vcgencmd("get_throttled")
    m = re.search(r"throttled=0x([0-9a-fA-F]+)", raw)
    if not m:
        return {"raw": raw}
    val = int(m.group(1), 16)
    return {
        "raw": hex(val),
        "under_voltage_now": bool(val & (1 << 0)),
        "under_voltage_occurred": bool(val & (1 << 16)),
        "throttling_occurred": bool(val & (1 << 18)),
    }


def get_self_uptime():
    try:
        with open("/proc/uptime") as f:
            seconds = int(float(f.read().split()[0]))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        parts = ([f"{days}d"] if days else []) + [f"{hours}h", f"{minutes}m"]
        return " ".join(parts)
    except Exception as e:
        return {"error": str(e)}




def get_public_ip():
    """Cached hard -- this is the one call in the whole dashboard that
    depends on an external service, so we hit it as rarely as possible."""
    now = time.time()
    if now - _public_ip_cache["ts"] > PUBLIC_IP_CACHE_TTL:
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
                _public_ip_cache["ip"] = resp.read().decode().strip()
        except Exception as e:
            _public_ip_cache["ip"] = {"error": str(e)}
        _public_ip_cache["ts"] = now
    return _public_ip_cache["ip"]


def check_internet():
    start = time.time()
    try:
        s = socket.create_connection((INTERNET_CHECK_HOST, INTERNET_CHECK_PORT), timeout=3)
        s.close()
        return {"up": True, "latency_ms": round((time.time() - start) * 1000, 1)}
    except Exception as e:
        return {"up": False, "latency_ms": None, "error": str(e)}


def play_alarm():
    try:
        subprocess.Popen(
            ["aplay", ALARM_WAV], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


def internet_check_loop():
    global _internet_state
    while True:
        result = check_internet()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _lock:
            prev_up = _internet_state.get("up")
            _internet_state = {
                "up": result["up"],
                "latency_ms": result.get("latency_ms"),
                "last_checked": now,
            }
            if prev_up is not None and prev_up != result["up"]:
                _internet_events.append({
                    "time": now,
                    "event": "Internet came back UP" if result["up"] else "Internet went DOWN",
                })
                del _internet_events[:-20]
            went_down = prev_up is True and result["up"] is False
        if went_down:
            threading.Thread(target=play_alarm, daemon=True).start()
        time.sleep(INTERNET_CHECK_INTERVAL)


_speedtest_state = {"running": False, "at": None, "ping_ms": None, "download_mbps": None, "upload_mbps": None, "error": None}


def run_speedtest():
    """speedtest-cli (apt package, real Ookla infra + server selection) --
    not a DIY download-a-file approximation. Takes ~30-40s, so this only
    ever runs on manual trigger, never on a timer."""
    with _lock:
        if _speedtest_state["running"]:
            return
        _speedtest_state["running"] = True
    try:
        out = subprocess.run(
            ["speedtest-cli", "--simple"],
            capture_output=True, text=True, timeout=90,
        ).stdout
        ping = re.search(r"Ping:\s*([\d.]+)", out)
        down = re.search(r"Download:\s*([\d.]+)", out)
        up = re.search(r"Upload:\s*([\d.]+)", out)
        with _lock:
            _speedtest_state.update({
                "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ping_ms": float(ping.group(1)) if ping else None,
                "download_mbps": float(down.group(1)) if down else None,
                "upload_mbps": float(up.group(1)) if up else None,
                "error": None if (ping and down and up) else "could not parse speedtest-cli output",
            })
    except Exception as e:
        with _lock:
            _speedtest_state.update({
                "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e),
            })
    finally:
        with _lock:
            _speedtest_state["running"] = False


def trigger_speedtest():
    with _lock:
        if _speedtest_state["running"]:
            return {"ok": False, "error": "a speed test is already running"}
    threading.Thread(target=run_speedtest, daemon=True).start()
    return {"ok": True}


def get_self_vitals():
    self_id = get_self_identity()
    wifi = get_self_wifi()
    return {
        "hostname": self_id["hostname"],
        "ip": self_id["ip"],
        "ssid": get_self_ssid(),
        "rssi_dbm": wifi.get("rssi_dbm"),
        "link_quality_pct": wifi.get("link_quality_pct"),
        "temp_c": get_self_temp(),
        "voltage": get_self_voltage(),
        "throttled": get_self_throttled(),
        "uptime": get_self_uptime(),
        "clock": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "public_ip": get_public_ip(),
    }


def parse_nmap_output(output, self_id):
    devices = []
    current = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Nmap scan report for"):
            if current:
                devices.append(current)
            rest = line[len("Nmap scan report for "):]
            m = re.match(r"^(.*) \((\d+\.\d+\.\d+\.\d+)\)$", rest)
            if m:
                hostname, ip = m.group(1), m.group(2)
            else:
                hostname, ip = None, rest.strip()
            current = {"ip": ip, "hostname": hostname, "mac": None, "vendor": None, "latency_ms": None, "ports": []}
        elif line.startswith("Host is up") and current:
            m = re.search(r"\(([\d.]+)s latency\)", line)
            if m:
                current["latency_ms"] = round(float(m.group(1)) * 1000, 1)
        elif line.startswith("MAC Address:") and current:
            m = re.match(r"MAC Address: ([0-9A-Fa-f:]+) \(([^)]*)\)", line)
            if m:
                current["mac"] = m.group(1)
                current["vendor"] = m.group(2)
        elif current is not None:
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                current["ports"].append({"port": int(m.group(1)), "service": m.group(2)})
    if current:
        devices.append(current)

    for d in devices:
        if self_id["ip"] and d["ip"] == self_id["ip"]:
            # nmap's own local-resolver guess for the scanning host is
            # unreliable (mDNS/DNS cache artifacts) -- we know this one
            # authoritatively, so it always wins.
            d["mac"] = d["mac"] or self_id["mac"]
            d["hostname"] = self_id["hostname"]
        if d["mac"]:
            prefix = d["mac"][:8].lower()
            if prefix in VENDOR_HINTS:
                d["vendor"] = VENDOR_HINTS[prefix]

    # A MAC answering ARP for more than one IP in the same scan is a
    # WiFi extender/repeater proxy-ARPing for the devices behind it --
    # we can't see those devices' real MACs, only the extender's.
    mac_counts = {}
    for d in devices:
        if d["mac"]:
            mac_counts[d["mac"]] = mac_counts.get(d["mac"], 0) + 1
    for d in devices:
        group_size = mac_counts.get(d["mac"], 1) if d["mac"] else 1
        d["link"] = "via_extender" if group_size > 1 else "direct"
        d["shared_mac_count"] = group_size

    return devices


def run_scan():
    start = time.time()
    try:
        out = subprocess.run(
            ["sudo", "nmap", "-T4", "--top-ports", "30", SUBNET],
            capture_output=True, text=True, timeout=90,
        ).stdout
        devices = parse_nmap_output(out, get_self_identity())
        _last_scan.update({
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "at_epoch": time.time(),
            "duration_s": round(time.time() - start, 1),
            "hosts_up": len(devices),
            "error": None,
        })
        return devices
    except Exception as e:
        _last_scan.update({
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "at_epoch": time.time(),
            "duration_s": round(time.time() - start, 1),
            "hosts_up": None,
            "error": str(e),
        })
        return None


def load_db():
    global _devices_db
    try:
        with open(DB_PATH) as f:
            _devices_db = json.load(f)
    except Exception:
        _devices_db = {}


def save_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_devices_db, f, indent=2)
    os.replace(tmp, DB_PATH)


def update_db(scanned_devices):
    """Keyed by IP, not MAC: a WiFi repeater/mesh node on this network
    (RE305) answers ARP for several IPs under one MAC, and keying by MAC
    collapsed those into a single overwritten row -- exactly the kind of
    wrong-IP bug this dashboard exists to avoid."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    seen_keys = set()
    with _lock:
        for d in scanned_devices:
            key = d["ip"]
            seen_keys.add(key)
            rec = _devices_db.get(key, {"first_seen": now})
            rec["ip"] = d["ip"]
            rec["mac"] = d["mac"]
            rec["hostname"] = d["hostname"] or rec.get("hostname")
            if d["vendor"] and d["vendor"] != "Unknown":
                rec["vendor"] = d["vendor"]
            else:
                rec.setdefault("vendor", d["vendor"])
            rec["latency_ms"] = d["latency_ms"]
            rec["link"] = d["link"]
            rec["shared_mac_count"] = d["shared_mac_count"]
            rec["ports"] = d["ports"]
            rec["last_seen"] = now
            rec["online"] = True
            _devices_db[key] = rec
        for key, rec in _devices_db.items():
            if key not in seen_keys:
                rec["online"] = False
                rec["latency_ms"] = None
        save_db()


_scan_trigger = threading.Event()
_scan_in_progress = threading.Event()


def trigger_scan():
    if _scan_in_progress.is_set():
        return {"ok": False, "error": "a scan is already in progress"}
    _scan_trigger.set()
    return {"ok": True}


def scan_loop():
    load_db()
    while True:
        _scan_in_progress.set()
        scanned = run_scan()
        if scanned is not None:
            update_db(scanned)
        _scan_in_progress.clear()
        _scan_trigger.wait(timeout=SCAN_INTERVAL)
        _scan_trigger.clear()


DASHBOARD_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAN Devices</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #fafafa; --fg: #1a1a1a;
    --card-bg: #fff; --card-border: #e5e5e5;
    --label: rgba(0,0,0,.55); --updated: rgba(0,0,0,.4);
    --pill-ok-bg: #e6f7ea; --pill-ok-fg: #1a7a34;
    --pill-bad-bg: #fbe6e6; --pill-bad-fg: #b31f1f;
    --warn-fg: #9a6b00;
    --row-hover: #f5f5f5;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #121212; --fg: #e8e8e8;
      --card-bg: #1e1e1e; --card-border: #333;
      --label: rgba(255,255,255,.55); --updated: rgba(255,255,255,.4);
      --pill-ok-bg: #123a1f; --pill-ok-fg: #7ee08a;
      --pill-bad-bg: #3a1212; --pill-bad-fg: #ff8a8a;
      --warn-fg: #e0b34d;
      --row-hover: #262626;
    }
  }
  html, body { height: 100%; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    width: 100%; margin: 0; padding: 1.1rem;
    color: var(--fg); background: var(--bg);
    box-sizing: border-box; height: 100vh;
    display: flex; flex-direction: column; gap: .7rem;
    overflow-y: auto; overflow-x: hidden;
  }
  .header-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
  h1 { font-size: 1.05rem; font-weight: 600; margin: 0; color: var(--label); }
  .scan-btn {
    font-size: .78rem; font-weight: 600; padding: .4rem .9rem;
    border-radius: 8px; border: 1px solid var(--card-border); background: var(--card-bg);
    color: var(--fg); cursor: pointer;
  }
  .scan-btn:hover { background: var(--row-hover); }
  .scan-btn:disabled { opacity: .5; cursor: not-allowed; }
  .stats { display: flex; gap: .7rem; }
  .stat-card {
    flex: 1; background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 12px; padding: .7rem 1rem;
  }
  .stat-card .num { font-size: 1.6rem; font-weight: 700; font-variant-numeric: tabular-nums; }
  .stat-card .label { font-size: .75rem; color: var(--label); }
  .stat-card.online .num { color: var(--pill-ok-fg); }
  .stat-card.offline .num { color: var(--pill-bad-fg); }
  .table-card {
    flex: 1; min-height: 0; background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 12px; padding: .7rem 1rem; display: flex; flex-direction: column;
  }
  .table-wrap { flex: 1; min-height: 0; overflow: auto; }
  table { width: 100%; border-collapse: collapse; font-size: .82rem; }
  thead th {
    position: sticky; top: 0; background: var(--card-bg); text-align: left;
    color: var(--label); font-weight: 600; font-size: .74rem; padding: .4rem .5rem;
    border-bottom: 1px solid var(--card-border);
  }
  tbody td { padding: .4rem .5rem; border-bottom: 1px solid var(--card-border); white-space: nowrap; }
  tbody tr:hover { background: var(--row-hover); }
  tbody tr.offline { opacity: .5; }
  .mac { font-variant-numeric: tabular-nums; }
  .pill { font-size: .68rem; padding: .18rem .5rem; border-radius: 999px; white-space: nowrap; }
  .pill.ok { background: var(--pill-ok-bg); color: var(--pill-ok-fg); }
  .pill.bad { background: var(--pill-bad-bg); color: var(--pill-bad-fg); }
  .status-bar { display: flex; justify-content: center; align-items: baseline; gap: 1.2rem; font-size: .72rem; color: var(--updated); flex-wrap: wrap; }
  .status-bar b { color: var(--label); font-weight: 600; }
  .scroll-list { list-style: none; margin: .3rem 0 0; padding: 0; font-size: .75rem; overflow-y: auto; flex: 1; min-height: 0; }
  .scroll-list li { display: flex; justify-content: space-between; gap: .5rem; padding: .2rem 0; border-top: 1px solid var(--card-border); color: var(--label); }
  .scroll-list li:first-child { border-top: none; }
  .scroll-list .item-name { color: var(--fg); }
  .no-events { font-size: .75rem; color: var(--label); margin-top: .2rem; }
  .vitals-card {
    background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
    padding: .7rem 1rem; display: flex; flex-wrap: wrap; gap: 0 1.5rem;
  }
  .vitals-card .card-title { flex-basis: 100%; font-size: .78rem; color: var(--label); font-weight: 600; margin-bottom: .2rem; }
  .vmetric { display: flex; align-items: baseline; gap: .4rem; padding: .15rem 0; }
  .vmetric .label { color: var(--label); font-size: .74rem; }
  .vmetric .value { color: var(--fg); font-size: .88rem; font-weight: 600; font-variant-numeric: tabular-nums; }
  .vmetric .value.ok { color: var(--pill-ok-fg); }
  .vmetric .value.warn { color: var(--warn-fg); }
  .vmetric .value.bad { color: var(--pill-bad-fg); }
</style>
</head>
<body>
<div class="header-row">
  <h1>LAN Devices — <span id="page-hostname">&mdash;</span></h1>
  <button id="scan-btn" class="scan-btn">Scan Now</button>
</div>

<div class="vitals-card">
  <div class="vmetric"><span class="label">IP</span><span class="value" id="self-ip">&mdash;</span></div>
  <div class="vmetric"><span class="label">SSID</span><span class="value" id="self-ssid">&mdash;</span></div>
  <div class="vmetric"><span class="label">RSSI</span><span class="value" id="self-rssi">&mdash;</span></div>
  <div class="vmetric"><span class="label">Quality</span><span class="value" id="self-quality">&mdash;</span></div>
  <div class="vmetric"><span class="label">Public IP</span><span class="value" id="sys-public-ip">&mdash;</span></div>
  <div class="vmetric"><span class="label">Voltage</span><span class="value" id="self-voltage">&mdash;</span></div>
  <div class="vmetric"><span class="label">Temp</span><span class="value" id="self-temp">&mdash;</span></div>
  <div class="vmetric"><span class="label">Under-voltage</span><span class="value" id="self-uv">&mdash;</span></div>
  <div class="vmetric"><span class="label">Uptime</span><span class="value" id="self-uptime">&mdash;</span></div>
  <div class="vmetric"><span class="label">Clock</span><span class="value" id="self-clock">&mdash;</span></div>
</div>

<div class="table-card" style="flex: 0 0 auto; max-height: 11rem;">
  <div class="header-row">
    <div class="card-title">Internet Status</div>
    <button id="speedtest-btn" class="scan-btn">Speed Test</button>
  </div>
  <div class="vmetric"><span class="label">Last speed test</span><span class="value" id="speedtest-result" style="font-size:.8rem;">never run</span></div>
  <ul class="scroll-list" id="internet-events"></ul>
</div>

<div class="stats">
  <div class="stat-card"><div class="num" id="stat-total">&mdash;</div><div class="label">Known devices</div></div>
  <div class="stat-card online"><div class="num" id="stat-online">&mdash;</div><div class="label">Online now</div></div>
  <div class="stat-card offline"><div class="num" id="stat-offline">&mdash;</div><div class="label">Offline</div></div>
  <div class="stat-card" id="extender-card"><div class="num" id="stat-extender">&mdash;</div><div class="label" id="extender-label">Extender</div></div>
  <div class="stat-card" id="internet-card"><div class="num" id="stat-internet">&mdash;</div><div class="label">Internet</div></div>
</div>

<div class="table-card">
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>#</th><th>Status</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Link</th><th>Latency</th><th>Open Ports</th><th>First Seen</th><th>Last Seen</th></tr>
      </thead>
      <tbody id="device-rows"></tbody>
    </table>
  </div>
</div>

<div class="status-bar" id="status-bar">loading&hellip;</div>
<script>
async function refresh() {
  try {
    const r = await fetch('/devices');
    const d = await r.json();
    const devices = d.devices || [];

    document.getElementById('stat-total').textContent = devices.length;
    document.getElementById('stat-online').textContent = devices.filter(x => x.online).length;
    document.getElementById('stat-offline').textContent = devices.filter(x => !x.online).length;

    const rows = document.getElementById('device-rows');
    rows.innerHTML = '';
    let extenderOnline = null, extenderLatency = null, behindExtender = 0;
    let rowNum = 0;
    for (const dev of devices) {
      rowNum++;
      const tr = document.createElement('tr');
      tr.className = dev.online ? '' : 'offline';
      const pill = '<span class="pill ' + (dev.online ? 'ok">online' : 'bad">offline') + '</span>';
      const isExtenderHost = dev.hostname && dev.hostname.toUpperCase().includes('RE305');
      const linkLabel = dev.link === 'via_extender'
        ? (isExtenderHost ? 'Extender' : 'Via Extender')
        : 'Direct';
      const linkPill = '<span class="pill ' + (dev.link === 'via_extender' ? 'bad' : 'ok') + '">' + linkLabel + '</span>';
      if (isExtenderHost) { extenderOnline = dev.online; extenderLatency = dev.latency_ms; }
      if (dev.link === 'via_extender' && !isExtenderHost) behindExtender++;
      const ports = (dev.ports || []).map(p => p.port + '/' + p.service).join(', ') || '—';
      tr.innerHTML =
        '<td>' + rowNum + '</td>' +
        '<td>' + pill + '</td>' +
        '<td>' + (dev.ip || '—') + '</td>' +
        '<td class="mac">' + (dev.mac || '—') + '</td>' +
        '<td>' + (dev.hostname || '—') + '</td>' +
        '<td>' + (dev.vendor || 'Unknown') + '</td>' +
        '<td>' + linkPill + '</td>' +
        '<td>' + (dev.latency_ms != null ? dev.latency_ms + ' ms' : '—') + '</td>' +
        '<td>' + ports + '</td>' +
        '<td>' + (dev.first_seen || '—') + '</td>' +
        '<td>' + (dev.last_seen || '—') + '</td>';
      rows.appendChild(tr);
    }

    const extCard = document.getElementById('extender-card');
    const extNum = document.getElementById('stat-extender');
    if (extenderOnline === null) {
      extNum.textContent = 'not seen';
      extCard.className = 'stat-card';
    } else {
      extNum.textContent = (extenderOnline ? 'online' : 'offline') + (extenderLatency != null ? ' · ' + extenderLatency + 'ms' : '');
      extCard.className = 'stat-card ' + (extenderOnline ? 'online' : 'offline');
    }
    document.getElementById('extender-label').textContent = 'RE305 · ' + behindExtender + ' behind it';

    const sv = d.self_vitals || {};
    document.getElementById('page-hostname').textContent = sv.hostname || 'unknown';
    document.getElementById('self-ssid').textContent = sv.ssid || 'unknown';

    const rssiEl = document.getElementById('self-rssi');
    rssiEl.textContent = (sv.rssi_dbm != null ? sv.rssi_dbm + ' dBm' : '—');
    rssiEl.className = 'value ' + (sv.rssi_dbm >= -60 ? 'ok' : sv.rssi_dbm >= -70 ? 'warn' : 'bad');

    const qEl = document.getElementById('self-quality');
    const q = sv.link_quality_pct;
    qEl.textContent = (q != null ? q + '%' : '—');
    qEl.className = 'value ' + (q == null ? '' : q >= 70 ? 'ok' : q >= 40 ? 'warn' : 'bad');

    document.getElementById('self-voltage').textContent = (sv.voltage != null ? sv.voltage + ' V' : '—');

    const tempEl = document.getElementById('self-temp');
    tempEl.textContent = (sv.temp_c != null ? sv.temp_c + ' °C' : '—');
    tempEl.className = 'value ' + (sv.temp_c == null ? '' : sv.temp_c < 60 ? 'ok' : sv.temp_c < 70 ? 'warn' : 'bad');

    const uvEl = document.getElementById('self-uv');
    const uvNow = sv.throttled && sv.throttled.under_voltage_now;
    uvEl.textContent = uvNow ? 'yes' : 'no';
    uvEl.className = 'value ' + (uvNow ? 'bad' : 'ok');

    document.getElementById('self-ip').textContent = sv.ip || '—';
    document.getElementById('self-uptime').textContent = sv.uptime || '—';
    document.getElementById('self-clock').textContent = sv.clock || '—';

    const pubIp = sv.public_ip;
    document.getElementById('sys-public-ip').textContent = (pubIp && !pubIp.error) ? pubIp : '—';

    const net = d.internet || {};
    const netCard = document.getElementById('internet-card');
    const netStat = document.getElementById('stat-internet');
    if (net.up === null || net.up === undefined) {
      netStat.textContent = 'checking…';
      netCard.className = 'stat-card';
    } else {
      netStat.textContent = net.up ? ('up · ' + net.latency_ms + 'ms') : 'DOWN';
      netCard.className = 'stat-card ' + (net.up ? 'online' : 'offline');
    }

    const netEventsEl = document.getElementById('internet-events');
    netEventsEl.innerHTML = '';
    const netEvents = d.internet_events || [];
    if (netEvents.length === 0) {
      netEventsEl.innerHTML = '<div class="no-events">No internet up/down transitions logged yet.</div>';
    } else {
      for (const ev of netEvents.slice().reverse()) {
        const li = document.createElement('li');
        li.innerHTML = '<span class="item-name">' + ev.event + '</span><span>' + ev.time + '</span>';
        netEventsEl.appendChild(li);
      }
    }

    const scan = d.last_scan || {};
    const statusBar = document.getElementById('status-bar');
    statusBar.innerHTML = scan.error
      ? '<span><b>Last scan failed:</b> ' + scan.error + '</span>'
      : '<span><b>Last scan:</b> ' + scan.at + '</span>' +
        '<span><b>Took:</b> ' + scan.duration_s + 's</span>' +
        '<span><b>Found:</b> ' + scan.hosts_up + ' devices</span>' +
        '<span><b>Next scan:</b> ' + (d.scan_in_progress ? 'running now' : (d.next_scan_in_s != null ? 'in ' + d.next_scan_in_s + 's' : '—')) + '</span>';

    const scanBtn = document.getElementById('scan-btn');
    if (d.scan_in_progress) {
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning…';
    } else {
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan Now';
    }

    const st = d.speedtest || {};
    const stBtn = document.getElementById('speedtest-btn');
    const stResult = document.getElementById('speedtest-result');
    if (st.running) {
      stBtn.disabled = true;
      stBtn.textContent = 'Testing… (~35s)';
    } else {
      stBtn.disabled = false;
      stBtn.textContent = 'Speed Test';
    }
    if (st.error) {
      stResult.textContent = 'failed: ' + st.error + (st.at ? ' (' + st.at + ')' : '');
    } else if (st.at) {
      stResult.textContent = 'Ping ' + st.ping_ms + 'ms · Down ' + st.download_mbps + ' Mbps · Up ' + st.upload_mbps + ' Mbps (' + st.at + ')';
    } else {
      stResult.textContent = 'never run';
    }
  } catch (e) {
    document.getElementById('status-bar').textContent = 'fetch failed: ' + e;
  }
}

document.getElementById('scan-btn').addEventListener('click', async () => {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Starting…';
  try {
    await fetch('/scan', { method: 'POST' });
  } catch (e) {
    // ignore -- next refresh() will reconcile actual state
  }
  refresh();
});

document.getElementById('speedtest-btn').addEventListener('click', async () => {
  const btn = document.getElementById('speedtest-btn');
  btn.disabled = true;
  btn.textContent = 'Starting…';
  try {
    await fetch('/speedtest', { method: 'POST' });
  } catch (e) {
    // ignore -- next refresh() will reconcile actual state
  }
  refresh();
});

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/devices":
            self.send_response(404)
            self.end_headers()
            return
        with _lock:
            devices = sorted(
                _devices_db.values(),
                key=lambda r: (not r.get("online"), r.get("ip") or ""),
            )
            scan_info = dict(_last_scan)
        next_in_s = None
        if scan_info["at_epoch"] and not _scan_in_progress.is_set():
            next_in_s = max(0, round(SCAN_INTERVAL - (time.time() - scan_info["at_epoch"])))
        del scan_info["at_epoch"]
        with _lock:
            internet = dict(_internet_state)
            internet_events = list(_internet_events[-10:])
            speedtest = dict(_speedtest_state)
        body = json.dumps({
            "devices": devices,
            "last_scan": scan_info,
            "next_scan_in_s": next_in_s,
            "scan_interval_s": SCAN_INTERVAL,
            "scan_in_progress": _scan_in_progress.is_set(),
            "self_vitals": get_self_vitals(),
            "internet": internet,
            "internet_events": internet_events,
            "speedtest": speedtest,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/scan":
            result = trigger_scan()
        elif self.path == "/speedtest":
            result = trigger_speedtest()
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(result).encode()
        self.send_response(200 if result.get("ok") else 409)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=internet_check_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
