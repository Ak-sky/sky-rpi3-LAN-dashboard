#!/usr/bin/env python3
"""Minimal stdlib-only LAN device dashboard: nmap scan in a background
thread, cached results served as JSON + a live-refreshing HTML page."""
import csv
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8000
SUBNET = "192.168.1.0/24"
PRESENCE_INTERVAL = 15    # seconds between arp-scan sweeps (~3s each); drives online/offline
FULL_SCAN_INTERVAL = 600  # seconds between nmap port/hostname scans + mDNS/SSDP discovery
OFFLINE_AFTER = 90        # seconds unseen (then a failed ping) before a device is marked offline
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

# IEEE's registry (https://standards-oui.ieee.org/oui/oui.csv); nmap 7.80's
# bundled list is from 2019 and misses most current phones/TVs.
OUI_PATH = os.path.expanduser("~/lan-dashboard-data/oui.csv")
_oui = None


def lookup_vendor(mac):
    global _oui
    if int(mac[1], 16) & 0x2:
        return "Private (randomized MAC)"
    if _oui is None:
        _oui = {}
        try:
            with open(OUI_PATH, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    _oui[row["Assignment"].upper()] = row["Organization Name"].strip()
        except OSError:
            pass
    return _oui.get(mac.replace(":", "")[:6].upper(), "Unknown")


def vendor_for(mac, nmap_vendor=None):
    hint = VENDOR_HINTS.get(mac[:8].lower())
    if hint:
        return hint
    if nmap_vendor and nmap_vendor != "Unknown":
        return nmap_vendor
    return lookup_vendor(mac)


def mark_shared_macs(devices):
    """One MAC answering ARP for several IPs in the same sweep (proxy ARP)
    can't identify a single device -- _upsert keeps such rows out of the
    stale-row auto-merge."""
    counts = {}
    for d in devices:
        if d["mac"]:
            counts[d["mac"]] = counts.get(d["mac"], 0) + 1
    for d in devices:
        d["shared_mac_count"] = counts.get(d["mac"], 1) if d["mac"] else 1

_lock = threading.Lock()
_devices_db = {}
_last_scan = {"at": None, "at_epoch": None, "duration_s": None, "hosts_up": None, "error": None}
_presence_state = {"at": None, "hosts_up": None, "error": None}

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


_last_down_epoch = None


def internet_check_loop():
    global _internet_state, _last_down_epoch
    while True:
        result = check_internet()
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        now_epoch = time.time()
        with _lock:
            prev_up = _internet_state.get("up")
            _internet_state = {
                "up": result["up"],
                "latency_ms": result.get("latency_ms"),
                "last_checked": now,
            }
            if prev_up is not None and prev_up != result["up"]:
                event = {"time": now, "type": "up" if result["up"] else "down"}
                if result["up"] and _last_down_epoch:
                    event["duration_s"] = round(now_epoch - _last_down_epoch)
                if not result["up"]:
                    _last_down_epoch = now_epoch
                _internet_events.append(event)
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
                "at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "ping_ms": float(ping.group(1)) if ping else None,
                "download_mbps": float(down.group(1)) if down else None,
                "upload_mbps": float(up.group(1)) if up else None,
                "error": None if (ping and down and up) else "could not parse speedtest-cli output",
            })
    except Exception as e:
        with _lock:
            _speedtest_state.update({
                "at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
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


def trigger_reboot():
    """Reboots this Pi. Fires 1s after responding so the HTTP response
    actually reaches the browser before the box goes down -- calling
    `sudo reboot` synchronously in the request handler would kill the
    process mid-write."""
    def _do_reboot():
        time.sleep(1)
        subprocess.run(["sudo", "reboot"])
    threading.Thread(target=_do_reboot, daemon=True).start()
    return {"ok": True}


IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def ping_host(ip):
    """On-demand ping for a single IP, triggered from the table. Argument
    list form of subprocess.run (no shell=True) means the ip value can't
    inject extra shell commands, but we still validate the format so a
    bogus value fails fast with a clear error instead of a confusing
    'unknown host' from ping itself."""
    if not ip or not IP_RE.match(ip):
        return {"ok": False, "error": "invalid IP address"}
    try:
        out = subprocess.run(
            ["ping", "-c", "3", "-W", "2", ip],
            capture_output=True, text=True, timeout=10,
        ).stdout
        m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
        if not m:
            return {"ok": False, "error": "could not parse ping output"}
        sent, received = int(m.group(1)), int(m.group(2))
        result = {
            "ok": True, "ip": ip, "sent": sent, "received": received,
            "loss_pct": round(100 * (sent - received) / sent) if sent else 100,
        }
        rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+ ms", out)
        if rtt:
            result.update({
                "min_ms": float(rtt.group(1)),
                "avg_ms": float(rtt.group(2)),
                "max_ms": float(rtt.group(3)),
            })
        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}


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
        "clock": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
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
            d["vendor"] = vendor_for(d["mac"], d["vendor"])

    mark_shared_macs(devices)

    return devices


def run_scan():
    start = time.time()
    try:
        out = subprocess.run(
            # --system-dns: nmap's own async resolver randomly drops PTR
            # answers from the router here; the system resolver doesn't.
            ["sudo", "nmap", "-T4", "--system-dns", "--top-ports", "30", SUBNET],
            capture_output=True, text=True, timeout=90,
        ).stdout
        devices = parse_nmap_output(out, get_self_identity())
        if not devices:
            # nmap always reports this Pi itself, so zero hosts means our own
            # network is down (e.g. WiFi not up yet at boot). Counting it as
            # a real scan would mark every device offline.
            raise RuntimeError("no hosts found -- this Pi's network looks down")
        _last_scan.update({
            "at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "at_epoch": time.time(),
            "duration_s": round(time.time() - start, 1),
            "hosts_up": len(devices),
            "error": None,
        })
        return devices
    except Exception as e:
        _last_scan.update({
            "at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "at_epoch": time.time(),
            "duration_s": round(time.time() - start, 1),
            "hosts_up": None,
            "error": str(e),
        })
        return None


_mac_ip_history = {}  # mac -> list of every distinct IP ever seen for it
_aliases = {}         # mac -> name set by hand in the dashboard
_dhcp_info = {}       # mac -> {"hostname", "vendor_class"} heard in DHCP requests


def load_db():
    global _devices_db, _mac_ip_history, _aliases, _dhcp_info
    try:
        with open(DB_PATH) as f:
            loaded = json.load(f)
    except Exception:
        _devices_db = {}
        _mac_ip_history = {}
        return
    if "devices" in loaded and "mac_ip_history" in loaded:
        _devices_db = loaded["devices"]
        _mac_ip_history = loaded["mac_ip_history"]
        _aliases = loaded.get("aliases", {})
        _dhcp_info = loaded.get("dhcp_info", {})
    else:
        # Old on-disk format: a flat {ip: record} dict. Seed history from
        # the current rows so nothing existing looks like a "move" the
        # first time this runs post-upgrade.
        _devices_db = loaded
        _mac_ip_history = {}
        for rec in _devices_db.values():
            if rec.get("mac"):
                _mac_ip_history.setdefault(rec["mac"], [])
                if rec["ip"] not in _mac_ip_history[rec["mac"]]:
                    _mac_ip_history[rec["mac"]].append(rec["ip"])


def save_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"devices": _devices_db, "mac_ip_history": _mac_ip_history,
                   "aliases": _aliases, "dhcp_info": _dhcp_info}, f, indent=2)
    os.replace(tmp, DB_PATH)


def forget_device(ip):
    """Manually drop a device's row, e.g. after reassigning it a static IP
    elsewhere (router UI) -- the dashboard has no way to know that happened
    on its own, so the stale offline row lingers until told to go."""
    if not ip or not IP_RE.match(ip):
        return {"ok": False, "error": "invalid IP address"}
    with _lock:
        if ip not in _devices_db:
            return {"ok": False, "error": "no such device"}
        del _devices_db[ip]
        save_db()
    return {"ok": True}


def _quick_ping_ok(ip):
    """Fallback liveness check for a device the presence sweep missed.
    Some WiFi clients (e.g. IP cameras) sporadically miss an ARP reply
    under load/power-save but still answer ICMP a moment later."""
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
        return bool(m and int(m.group(2)) > 0)
    except Exception:
        return False


def _now():
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S"), time.time()


def _seen_epoch(rec):
    if "last_seen_epoch" in rec:
        return rec["last_seen_epoch"]
    try:
        return datetime.strptime(rec["last_seen"], "%d/%m/%Y %H:%M:%S").timestamp()
    except (KeyError, ValueError):
        return 0


def _upsert(d, now, now_epoch):
    """Record one sighting of d (ip, mac, vendor, shared_mac_count). Caller
    holds _lock. Returns (row, changed) -- changed means something worth
    persisting happened (new/reset/merged row, offline->online).

    Rows are keyed by IP, not MAC: some gear on this network proxy-ARPs
    several IPs under one MAC, and keying by MAC collapsed those into one
    overwritten row."""
    key = d["ip"]
    changed = False

    # Auto-retire a stale row when a MAC with a clean single-IP history
    # shows up at a new IP -- a real device move (e.g. switched to a static
    # IP). A MAC ever seen at 2+ IPs (shared or moved before) is excluded
    # for good, since the TP-Link gear here reuses/shifts MACs and could
    # merge unrelated devices.
    if d["mac"]:
        prior_ips = _mac_ip_history.get(d["mac"], [])
        old = _devices_db.get(prior_ips[0]) if len(prior_ips) == 1 else None
        # old["mac"] check: that IP may already belong to another device
        # processed earlier in this same sweep.
        if (d["shared_mac_count"] == 1 and old is not None
                and prior_ips[0] != key and old.get("mac") == d["mac"]):
            del _devices_db[prior_ips[0]]
            changed = True
        if key not in prior_ips:
            _mac_ip_history.setdefault(d["mac"], []).append(key)
            changed = True

    rec = _devices_db.get(key)
    # A different MAC at this IP is a different device (DHCP handed the IP
    # on) -- don't let it inherit the old one's name/vendor/discovery data.
    if rec is None or (rec.get("mac") and d["mac"] and rec["mac"] != d["mac"]):
        rec = {"first_seen": now}
        changed = True
    if not rec.get("online"):
        changed = True
    rec["ip"] = key
    rec["mac"] = d["mac"] or rec.get("mac")
    if d.get("vendor") and d["vendor"] != "Unknown":
        rec["vendor"] = d["vendor"]
    else:
        rec.setdefault("vendor", d.get("vendor") or "Unknown")
    rec["last_seen"] = now
    rec["last_seen_epoch"] = now_epoch
    rec["online"] = True
    for stale_field in ("miss_streak", "link", "shared_mac_count"):
        rec.pop(stale_field, None)
    _devices_db[key] = rec
    return rec, changed


def apply_full_scan(devices):
    """nmap results: adds hostnames and open ports. Online/offline is left
    to the presence sweep, which runs far more often."""
    now, now_epoch = _now()
    with _lock:
        for d in devices:
            rec, _ = _upsert(d, now, now_epoch)
            rec["hostname"] = d["hostname"] or rec.get("hostname")
            rec["ports"] = d["ports"]
            if d["latency_ms"] is not None:
                rec["latency_ms"] = d["latency_ms"]
        save_db()


def apply_presence(devices):
    now, now_epoch = _now()
    self_ip = get_self_identity()["ip"]
    changed = False
    with _lock:
        seen = set()
        for d in devices:
            rec, row_changed = _upsert(d, now, now_epoch)
            changed = changed or row_changed
            if d["latency_ms"] is not None:
                rec["latency_ms"] = d["latency_ms"]
            seen.add(d["ip"])
        # arp-scan can't see the host it runs on.
        if self_ip in _devices_db:
            _devices_db[self_ip].update(online=True, last_seen=now, last_seen_epoch=now_epoch)
            seen.add(self_ip)
        overdue = [ip for ip, rec in _devices_db.items()
                   if ip not in seen and rec.get("online")
                   and now_epoch - _seen_epoch(rec) >= OFFLINE_AFTER]
        unnamed = [ip for ip in seen if not _devices_db[ip].get("hostname")
                   and not _devices_db[ip].get("dns_checked")]

    # Outside _lock: pings and DNS lookups block, and /devices reads
    # shouldn't stall on them.
    for ip in overdue:
        alive = _quick_ping_ok(ip)
        with _lock:
            rec = _devices_db.get(ip)
            if rec is None:
                continue
            if alive:
                rec.update(last_seen=now, last_seen_epoch=now_epoch)
            else:
                rec["online"] = False
                rec["latency_ms"] = None
                changed = True
    for ip in unnamed:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            name = None
        with _lock:
            rec = _devices_db.get(ip)
            if rec is not None:
                rec["dns_checked"] = True
                if name:
                    rec["hostname"] = name
                changed = True

    if changed:
        with _lock:
            save_db()


ARP_LINE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\t([0-9a-fA-F:]{17})\t.*?(?:RTT=([\d.]+) ms)?$")


def run_presence_sweep():
    try:
        out = subprocess.run(
            ["sudo", "arp-scan", "-I", WIFI_IFACE, "--localnet", "--plain",
             "--rtt", "--retry=3", "--ignoredups"],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception as e:
        _presence_state.update(at=_now()[0], hosts_up=None, error=str(e))
        return None
    devices = []
    for line in out.splitlines():
        m = ARP_LINE_RE.match(line)
        if m:
            mac = m.group(2).upper()
            devices.append({
                "ip": m.group(1), "mac": mac, "vendor": vendor_for(mac),
                "latency_ms": round(float(m.group(3)), 1) if m.group(3) else None,
            })
    if not devices:
        # The router always answers ARP, so silence means our own network
        # is down -- don't let that mark every device offline.
        _presence_state.update(at=_now()[0], hosts_up=0, error="no ARP replies -- this Pi's network looks down")
        return None
    mark_shared_macs(devices)
    _presence_state.update(at=_now()[0], hosts_up=len(devices), error=None)
    return devices


def presence_loop():
    while True:
        # Skipped while nmap runs: both ARP-sweep the subnet, and the
        # overlap just adds noise on a Pi 3's WiFi.
        if not _scan_in_progress.is_set():
            devices = run_presence_sweep()
            if devices is not None:
                apply_presence(devices)
        time.sleep(PRESENCE_INTERVAL)


MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
# Which TXT key holds the model depends on the service: "md" is the model
# for Cast devices but "supported metadata types" for AirPlay audio (_raop).
MDNS_MODEL_KEYS = (
    ("_airplay._tcp", "model"),
    ("_device-info._tcp", "model"),
    ("_raop._tcp", "am"),
    ("_googlecast._tcp", "md"),
    ("_ipp._tcp", "ty"),
    ("_printer._tcp", "ty"),
)


def _multicast_socket(ttl):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    self_ip = get_self_identity()["ip"]
    if self_ip:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self_ip))
    sock.bind(("", 0))
    return sock


def _collect(sock, timeout):
    replies, deadline = [], time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            return replies
        sock.settimeout(left)
        try:
            buf, addr = sock.recvfrom(9000)
        except OSError:
            return replies
        replies.append((buf, addr[0]))


def _dns_labels(buf, off):
    """Decode a (possibly compressed) DNS name -> (labels, next offset)."""
    labels, end = [], None
    for _ in range(64):  # bounded: a malicious pointer loop just stops here
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            continue
        labels.append(buf[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return labels, (end if end is not None else off)


def _dns_records(buf):
    """All answer/authority/additional records as (labels, type, rdata_off, rdlen).
    Malformed packets yield whatever parsed before the damage."""
    out = []
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", buf[4:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_labels(buf, off)
            off += 4
        for _ in range(an + ns + ar):
            labels, off = _dns_labels(buf, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            out.append((labels, rtype, off, rdlen))
            off += rdlen
    except (IndexError, struct.error):
        pass
    return out


def _mdns_ask(sock, names, timeout):
    questions = b"".join(
        b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 12, 1)
        for name in names
    )
    try:
        sock.sendto(struct.pack(">6H", 1, 0, len(names), 0, 0, 0) + questions, MDNS_GROUP)
    except OSError:
        return []
    return _collect(sock, timeout)


def _txt(data):
    out, i = {}, 0
    while i < len(data):
        n = data[i]
        entry = data[i + 1:i + 1 + n].decode("utf-8", "replace")
        i += 1 + n
        if "=" in entry:
            k, v = entry.split("=", 1)
            out.setdefault(k, v)
    return out


def _clean_instance_name(name):
    name = name.split("@", 1)[-1]           # _raop: "A1B2C3D4E5F6@Living Room"
    name = re.sub(r"\s*\[[0-9a-fA-F:]+\]$", "", name)  # _workstation: "host [aa:bb:..]"
    if re.fullmatch(r"[0-9a-fA-F-]{12,}", name) or re.search(r"-[0-9a-f]{16,}$", name):
        return None                          # bare UUID / "Chromecast-<hex>"
    return name.strip() or None


def mdns_discover(timeout=2.0):
    """Ask every mDNS responder what services it offers. Sent from an
    ephemeral port, so responders reply unicast straight to us (RFC 6762
    legacy unicast) and we never have to share 5353 with avahi.
    Returns {ip: {"name", "model", "services"}}."""
    try:
        sock = _multicast_socket(255)
    except OSError:
        return {}
    with sock:
        meta = "_services._dns-sd._udp.local"
        types = set()
        for buf, _ip in _mdns_ask(sock, [meta], timeout):
            for labels, rtype, off, _ in _dns_records(buf):
                if rtype == 12 and ".".join(labels) == meta:
                    types.add(".".join(_dns_labels(buf, off)[0]))
        types = sorted(t for t in types if t.endswith(".local"))[:40]

        per_ip = {}
        for i in range(0, len(types), 10):
            for buf, ip in _mdns_ask(sock, types[i:i + 10], timeout):
                info = per_ip.setdefault(ip, {"names": [], "services": set(), "txt": {}})
                for labels, rtype, off, rdlen in _dns_records(buf):
                    if rtype == 12 and ".".join(labels) in types:
                        info["services"].add(".".join(labels[:2]))
                        instance = _dns_labels(buf, off)[0]
                        if instance:
                            info["names"].append(instance[0])
                    elif rtype == 16 and len(labels) >= 3:
                        # TXT owner is "<instance>.<_svc>.<_proto>.local"
                        service = ".".join(labels[-3:-1])
                        info["txt"].setdefault(service, {}).update(_txt(buf[off:off + rdlen]))

    self_ip = get_self_identity()["ip"]
    found = {}
    for ip, info in per_ip.items():
        if ip == self_ip:
            continue  # Samba advertises this Pi as "MacSamba"; we know what it is
        txt = info["txt"]
        name = (txt.get("_googlecast._tcp", {}).get("fn")
                or next(filter(None, map(_clean_instance_name, info["names"])), None))
        model = next((txt[svc][key] for svc, key in MDNS_MODEL_KEYS if txt.get(svc, {}).get(key)), None)
        found[ip] = {"name": name, "model": model, "services": sorted(info["services"])}
    return found


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# No env proxies, no redirects: description fetches must only ever reach
# the LAN device that answered the M-SEARCH.
_lan_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _upnp_description(ip, url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname != ip:
        return None
    try:
        with _lan_opener.open(url, timeout=2) as resp:
            data = resp.read(65536)
    except Exception:
        return None
    if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.IGNORECASE):
        return None  # refuse entity declarations outright (billion-laughs etc.)
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    def first(tag):
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1] == tag and el.text and el.text.strip():
                return el.text.strip()
        return None

    name = first("friendlyName")
    model = " ".join(x for x in (first("manufacturer"), first("modelName")) if x) or None
    return {"name": name, "model": model} if (name or model) else None


def ssdp_discover(timeout=3.0):
    """M-SEARCH for UPnP devices (TVs, media boxes, consoles), then read
    each one's description XML for a friendly name and model.
    Returns {ip: {"name", "model"}}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    try:
        sock = _multicast_socket(2)
    except OSError:
        return {}
    locations = {}
    with sock:
        try:
            sock.sendto(msg, SSDP_GROUP)
            sock.sendto(msg, SSDP_GROUP)  # UDP over WiFi drops; a second copy is cheap
        except OSError:
            return {}
        for buf, ip in _collect(sock, timeout):
            for line in buf.decode("latin-1").split("\r\n"):
                if line.lower().startswith("location:"):
                    locations.setdefault(ip, set()).add(line.split(":", 1)[1].strip())
    found = {}
    for ip, locs in locations.items():
        for loc in sorted(locs):
            info = _upnp_description(ip, loc)
            if info:
                found[ip] = info
                break
    return found


def apply_discovery(mdns, ssdp):
    with _lock:
        for field, results in (("mdns", mdns), ("upnp", ssdp)):
            for ip, info in results.items():
                if ip in _devices_db:
                    _devices_db[ip][field] = info
        save_db()


DHCP_REQUEST_RE = re.compile(r"Request from ([0-9a-fA-F:]{17})")
DHCP_OPTION_RE = re.compile(r'(Hostname|Vendor-Class)\s*(?:Option\s*)?\(?(?:12|60)\)?,\s*length \d+: "(.*)"')


def _record_dhcp(mac, field, value):
    value = value[:64]
    with _lock:
        info = _dhcp_info.setdefault(mac, {})
        if info.get(field) != value:
            info[field] = value
            save_db()


def dhcp_listener_loop():
    """Passively picks up the hostname and OS hint (Vendor-Class, e.g.
    "android-dhcp-13", "MSFT 5.0") devices send when they join the WiFi.
    DHCP requests are broadcast, so this Pi hears other clients' too."""
    while True:
        try:
            proc = subprocess.Popen(
                ["sudo", "tcpdump", "-l", "-n", "-v", "-i", WIFI_IFACE, "udp and (port 67 or port 68)"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
            )
            mac = None
            for line in proc.stdout:
                if not line[:1].isspace():  # unindented line = next packet's header
                    mac = None
                    continue
                m = DHCP_REQUEST_RE.search(line)
                if m:
                    mac = m.group(1).upper()
                    continue
                if mac:
                    m = DHCP_OPTION_RE.search(line)
                    if m:
                        _record_dhcp(mac, "hostname" if m.group(1) == "Hostname" else "vendor_class", m.group(2))
            proc.wait()
        except Exception as e:
            print(f"dhcp listener: {e}", flush=True)
        time.sleep(30)


MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def set_alias(mac, name):
    mac = (mac or "").upper()
    if not MAC_RE.match(mac):
        return {"ok": False, "error": "invalid MAC address"}
    name = (name or "").strip()[:64]
    with _lock:
        if name:
            _aliases[mac] = name
        else:
            _aliases.pop(mac, None)
        save_db()
    return {"ok": True}


DHCP_OS_HINTS = (("android-dhcp", "Android"), ("MSFT", "Windows"), ("dhcpcd", "Linux"), ("udhcp", "Embedded Linux"))
MDNS_KINDS = {
    "_googlecast._tcp": "Chromecast / Cast device",
    "_androidtvremote2._tcp": "Android TV",
    "_amzn-wplay._tcp": "Amazon Fire TV",
    "_airplay._tcp": "AirPlay device",
    "_companion-link._tcp": "Apple device",
    "_hap._tcp": "HomeKit accessory",
    "_ipp._tcp": "Printer",
    "_printer._tcp": "Printer",
    "_spotify-connect._tcp": "Spotify Connect speaker",
    "_workstation._tcp": "Computer",
}


def device_view(rec):
    """Row + best-guess display name and model. Caller holds _lock."""
    mac = rec.get("mac")
    dhcp = _dhcp_info.get(mac, {}) if mac else {}
    mdns = rec.get("mdns") or {}
    upnp = rec.get("upnp") or {}
    alias = _aliases.get(mac) if mac else None
    vendor_class = dhcp.get("vendor_class") or ""
    os_hint = next((os_name for prefix, os_name in DHCP_OS_HINTS if vendor_class.startswith(prefix)), None)
    kind = next((MDNS_KINDS[s] for s in mdns.get("services", []) if s in MDNS_KINDS), None)
    return dict(
        rec,
        alias=alias,
        name=alias or upnp.get("name") or mdns.get("name") or dhcp.get("hostname") or rec.get("hostname"),
        model=upnp.get("model") or mdns.get("model") or kind or os_hint,
        dhcp=dhcp or None,
    )


_scan_trigger = threading.Event()
_scan_in_progress = threading.Event()


def trigger_scan():
    if _scan_in_progress.is_set():
        return {"ok": False, "error": "a scan is already in progress"}
    _scan_trigger.set()
    return {"ok": True}


def scan_loop():
    while True:
        _scan_in_progress.set()
        scanned = run_scan()
        if scanned is not None:
            apply_full_scan(scanned)
            apply_discovery(mdns_discover(), ssdp_discover())
        _scan_in_progress.clear()
        _scan_trigger.wait(timeout=FULL_SCAN_INTERVAL)
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
  .ping-btn {
    font-size: .7rem; font-weight: 600; padding: .2rem .55rem; min-width: 3.6rem;
    border-radius: 6px; border: 1px solid var(--card-border); background: transparent;
    color: var(--label); cursor: pointer;
  }
  .ping-btn:hover { background: var(--row-hover); color: var(--fg); }
  .ping-btn:disabled { cursor: wait; opacity: .6; }
  .ping-btn.ping-ok { border-color: var(--pill-ok-fg); color: var(--pill-ok-fg); }
  .ping-btn.ping-bad { border-color: var(--pill-bad-fg); color: var(--pill-bad-fg); }
  .reboot-btn {
    margin-left: auto; font-size: .78rem; font-weight: 600; padding: .4rem .9rem;
    border-radius: 8px; border: 1px solid var(--pill-bad-fg); background: var(--pill-bad-bg);
    color: var(--pill-bad-fg); cursor: pointer;
  }
  .reboot-btn:disabled { opacity: .5; cursor: not-allowed; }
  .filter-bar { display: flex; align-items: center; gap: .6rem; margin-bottom: .6rem; flex-wrap: wrap; }
  .filter-search, .filter-select {
    font-size: .8rem; padding: .4rem .6rem; border-radius: 8px;
    border: 1px solid var(--card-border); background: var(--bg); color: var(--fg);
  }
  .filter-search { flex: 1; min-width: 12rem; }
  .filter-search:focus, .filter-select:focus { outline: 1px solid var(--label); }
  .filter-count { font-size: .75rem; color: var(--label); white-space: nowrap; margin-left: auto; }
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
  thead th[data-field] { cursor: pointer; user-select: none; }
  thead th[data-field]:hover { color: var(--fg); }
  thead th[data-field]::after { content: ''; display: inline-block; width: .6em; }
  thead th.sort-asc::after { content: '▲'; font-size: .65em; margin-left: .2em; }
  thead th.sort-desc::after { content: '▼'; font-size: .65em; margin-left: .2em; }
  tbody td { padding: .4rem .5rem; border-bottom: 1px solid var(--card-border); white-space: nowrap; }
  tbody tr:hover { background: var(--row-hover); }
  tbody tr.offline { opacity: .5; }
  .mac { font-variant-numeric: tabular-nums; }
  .pill { font-size: .68rem; padding: .18rem .5rem; border-radius: 999px; white-space: nowrap; }
  .sub { display: block; font-size: .7rem; color: var(--label); }
  .pill.ok { background: var(--pill-ok-bg); color: var(--pill-ok-fg); }
  .pill.bad { background: var(--pill-bad-bg); color: var(--pill-bad-fg); }
  .status-bar { display: flex; justify-content: center; align-items: baseline; gap: 1.2rem; font-size: .72rem; color: var(--updated); flex-wrap: wrap; }
  .status-bar b { color: var(--label); font-weight: 600; }
  .scroll-list { list-style: none; margin: .3rem 0 0; padding: 0; font-size: .75rem; overflow-y: auto; flex: 1; min-height: 0; }
  .scroll-list li { display: flex; justify-content: space-between; gap: .5rem; padding: .2rem 0; border-top: 1px solid var(--card-border); color: var(--label); }
  .scroll-list li:first-child { border-top: none; }
  .scroll-list .item-name { color: var(--fg); }
  .no-events { font-size: .75rem; color: var(--label); margin-top: .2rem; }
  .net-event { border-left: 2px solid transparent; padding-left: .5rem !important; margin-left: -.5rem; }
  .net-event-up { border-left-color: var(--pill-ok-fg); }
  .net-event-down { border-left-color: var(--pill-bad-fg); }
  .net-event .event-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: .45rem; vertical-align: middle; }
  .net-event-up .event-dot { background: var(--pill-ok-fg); }
  .net-event-down .event-dot { background: var(--pill-bad-fg); }
  .net-event-up .item-name { color: var(--pill-ok-fg); }
  .net-event-down .item-name { color: var(--pill-bad-fg); }
  .duration-badge { margin-left: .5rem; font-size: .68rem; color: var(--label); font-weight: 400; }
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
  <button id="reboot-btn" class="reboot-btn">Reboot Pi</button>
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
  <div class="stat-card" id="internet-card"><div class="num" id="stat-internet">&mdash;</div><div class="label">Internet</div></div>
</div>

<div class="table-card">
  <div class="filter-bar">
    <input type="text" id="filter-search" class="filter-search" placeholder="Search IP, MAC, name, vendor, model…">
    <select id="filter-status" class="filter-select">
      <option value="all">All statuses</option>
      <option value="online">Online</option>
      <option value="offline">Offline</option>
    </select>
    <span class="filter-count" id="filter-count"></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th data-field="online" data-type="bool">Status</th>
          <th data-field="ip" data-type="ip">IP</th>
          <th data-field="mac" data-type="string">MAC</th>
          <th data-field="name" data-type="string">Name</th>
          <th data-field="vendor" data-type="string">Vendor</th>
          <th data-field="model" data-type="string">Model / Type</th>
          <th data-field="latency_ms" data-type="number">Latency</th>
          <th data-field="ports" data-type="number">Open Ports</th>
          <th data-field="first_seen" data-type="string">First Seen</th>
          <th data-field="last_seen" data-type="string">Last Seen</th>
          <th>Ping</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="device-rows"></tbody>
    </table>
  </div>
</div>

<div class="status-bar" id="status-bar">loading&hellip;</div>
<script>
function formatDuration(seconds) {
  if (seconds < 60) return seconds + 's';
  const m = Math.floor(seconds / 60), s = seconds % 60;
  if (m < 60) return m + 'm ' + s + 's';
  const h = Math.floor(m / 60);
  return h + 'h ' + (m % 60) + 'm';
}

// The device table fully rebuilds every 5s on auto-refresh, which would
// otherwise wipe out an in-flight or just-finished ping's result before
// it's even seen. Keyed cache + expiry survives across rebuilds instead
// of holding state on a specific (soon to be discarded) button element.
let pingResults = {};

function pingButtonHtml(ip) {
  const pr = pingResults[ip];
  const loading = pr && pr.text === '…';
  if (pr && (loading || pr.expiresAt > Date.now())) {
    return '<button class="' + pr.className + '"' + (loading ? ' disabled' : '') +
      ' onclick="pingIp(\\'' + ip + '\\')">' + pr.text + '</button>';
  }
  return '<button class="ping-btn" onclick="pingIp(\\'' + ip + '\\')">Ping</button>';
}

async function pingIp(ip) {
  pingResults[ip] = { text: '…', className: 'ping-btn' };
  renderDeviceRows();
  try {
    const res = await fetch('/ping?ip=' + encodeURIComponent(ip), { method: 'POST' });
    const result = await res.json();
    if (result.ok && result.received > 0) {
      pingResults[ip] = {
        text: result.avg_ms != null ? result.avg_ms.toFixed(1) + ' ms' : (result.received + '/' + result.sent),
        className: 'ping-btn ping-ok', expiresAt: Date.now() + 8000,
      };
    } else {
      pingResults[ip] = {
        text: result.received === 0 ? 'timeout' : (result.error || 'failed'),
        className: 'ping-btn ping-bad', expiresAt: Date.now() + 8000,
      };
    }
  } catch (e) {
    pingResults[ip] = { text: 'error', className: 'ping-btn ping-bad', expiresAt: Date.now() + 8000 };
  }
  renderDeviceRows();
  setTimeout(renderDeviceRows, 8100);
}

async function forgetIp(ip) {
  if (!confirm('Remove ' + ip + ' from the device list?\\n\\nUse this for a stale row left behind after reassigning the device a different IP elsewhere (e.g. a static IP change). It comes back on its own if anything ever answers at this IP again.')) {
    return;
  }
  try {
    await fetch('/forget?ip=' + encodeURIComponent(ip), { method: 'POST' });
  } catch (e) {}
  refresh();
}

// Names/models come from DHCP, mDNS and UPnP -- i.e. from whatever any
// device on the network chooses to announce. Never put them in innerHTML raw.
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(v) {
  return String(v).replace(/[&<>"']/g, c => HTML_ESCAPES[c]);
}

async function renameDevice(mac) {
  const dev = lastDevices.find(d => d.mac === mac) || {};
  const name = prompt('Name for ' + mac + ' (leave empty to clear):', dev.alias || dev.name || '');
  if (name === null) return;
  try {
    await fetch('/alias?mac=' + encodeURIComponent(mac) + '&name=' + encodeURIComponent(name), { method: 'POST' });
  } catch (e) {}
  refresh();
}

let lastDevices = [];
// Default to IP-ascending on every fresh page load, not just after a
// manual header click -- previously the table showed raw server order
// until you clicked a column, so a refresh looked "unsorted" each time.
let sortState = { field: 'ip', dir: 1 };

function sortFieldValue(dev, field) {
  if (field === 'ports') return (dev.ports || []).length;
  if (field === 'online') return dev.online ? 1 : 0;
  return dev[field];
}

function compareIp(a, b) {
  const pa = (a || '0.0.0.0').split('.').map(Number);
  const pb = (b || '0.0.0.0').split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

function compareValues(a, b, type) {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  if (type === 'ip') return compareIp(a, b);
  if (type === 'number' || type === 'bool') return a - b;
  return String(a).localeCompare(String(b));
}

document.querySelectorAll('th[data-field]').forEach(th => {
  th.addEventListener('click', () => {
    const field = th.dataset.field;
    sortState.dir = (sortState.field === field) ? sortState.dir * -1 : 1;
    sortState.field = field;
    renderDeviceRows();
  });
});

function renderDeviceRows() {
  // Reflect sortState on the header arrows every render (not just on click)
  // so a default sort applied at load time or by a periodic refresh still
  // shows which column and direction is active.
  document.querySelectorAll('th[data-field]').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
  if (sortState.field) {
    const activeTh = document.querySelector('th[data-field="' + sortState.field + '"]');
    if (activeTh) activeTh.classList.add(sortState.dir === 1 ? 'sort-asc' : 'sort-desc');
  }

  const search = document.getElementById('filter-search').value.trim().toLowerCase();
  const statusFilter = document.getElementById('filter-status').value;

  const filtered = lastDevices.filter(dev => {
    if (statusFilter === 'online' && !dev.online) return false;
    if (statusFilter === 'offline' && dev.online) return false;
    if (search) {
      const haystack = [dev.ip, dev.mac, dev.name, dev.hostname, dev.vendor, dev.model,
        dev.dhcp && dev.dhcp.vendor_class].filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  if (sortState.field) {
    const th = document.querySelector('th[data-field="' + sortState.field + '"]');
    const type = th ? th.dataset.type : 'string';
    filtered.sort((a, b) => sortState.dir * compareValues(
      sortFieldValue(a, sortState.field), sortFieldValue(b, sortState.field), type
    ));
  }

  document.getElementById('filter-count').textContent =
    filtered.length === lastDevices.length
      ? lastDevices.length + ' devices'
      : 'showing ' + filtered.length + ' of ' + lastDevices.length + ' devices';

  const rows = document.getElementById('device-rows');
  rows.innerHTML = '';
  let rowNum = 0;
  for (const dev of filtered) {
    rowNum++;
    const tr = document.createElement('tr');
    tr.className = dev.online ? '' : 'offline';
    const pill = '<span class="pill ' + (dev.online ? 'ok">online' : 'bad">offline') + '</span>';
    const ports = (dev.ports || []).map(p => p.port + '/' + p.service).join(', ') || '—';
    // Show the DNS hostname underneath when a better name replaced it.
    const nameCell = dev.name
      ? esc(dev.name) + (dev.hostname && dev.hostname !== dev.name ? '<span class="sub">' + esc(dev.hostname) + '</span>' : '')
      : '—';
    const osHint = dev.dhcp && dev.dhcp.vendor_class && dev.model !== dev.dhcp.vendor_class
      ? '<span class="sub">' + esc(dev.dhcp.vendor_class) + '</span>' : '';
    tr.innerHTML =
      '<td>' + rowNum + '</td>' +
      '<td>' + pill + '</td>' +
      '<td>' + esc(dev.ip || '—') + '</td>' +
      '<td class="mac">' + esc(dev.mac || '—') + '</td>' +
      '<td>' + nameCell + '</td>' +
      '<td>' + esc(dev.vendor || 'Unknown') + '</td>' +
      '<td>' + (dev.model ? esc(dev.model) : '—') + osHint + '</td>' +
      '<td>' + (dev.latency_ms != null ? dev.latency_ms + ' ms' : '—') + '</td>' +
      '<td>' + esc(ports) + '</td>' +
      '<td>' + esc(dev.first_seen || '—') + '</td>' +
      '<td>' + esc(dev.last_seen || '—') + '</td>' +
      '<td>' + (dev.ip ? pingButtonHtml(dev.ip) : '—') + '</td>' +
      '<td>' +
        (dev.mac ? '<button class="ping-btn" onclick="renameDevice(\\'' + esc(dev.mac) + '\\')">Rename</button> ' : '') +
        (dev.ip && !dev.online ? '<button class="ping-btn ping-bad" onclick="forgetIp(\\'' + esc(dev.ip) + '\\')">Forget</button>' : '') +
      '</td>';
    rows.appendChild(tr);
  }
}

document.getElementById('filter-search').addEventListener('input', renderDeviceRows);
document.getElementById('filter-status').addEventListener('change', renderDeviceRows);

async function refresh() {
  try {
    const r = await fetch('/devices');
    const d = await r.json();
    const devices = d.devices || [];
    lastDevices = devices;

    document.getElementById('stat-total').textContent = devices.length;
    document.getElementById('stat-online').textContent = devices.filter(x => x.online).length;
    document.getElementById('stat-offline').textContent = devices.filter(x => !x.online).length;

    renderDeviceRows();

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
        li.className = 'net-event net-event-' + ev.type;
        const label = ev.type === 'up' ? 'Internet Up' : 'Internet Down';
        const duration = (ev.type === 'up' && ev.duration_s != null)
          ? '<span class="duration-badge">outage lasted ' + formatDuration(ev.duration_s) + '</span>' : '';
        li.innerHTML =
          '<span class="item-name"><span class="event-dot"></span>' + label + duration + '</span>' +
          '<span>' + ev.time + '</span>';
        netEventsEl.appendChild(li);
      }
    }

    const scan = d.last_scan || {};
    const statusBar = document.getElementById('status-bar');
    const pr = d.presence || {};
    const presenceHtml = pr.error
      ? '<span><b>Presence check failed:</b> ' + esc(pr.error) + '</span>'
      : '<span><b>Presence (every ' + d.presence_interval_s + 's):</b> ' + (pr.hosts_up != null ? pr.hosts_up + ' up at ' + esc(pr.at) : '—') + '</span>';
    const nextScan = d.scan_in_progress ? 'running now'
      : (d.next_scan_in_s != null ? 'in ' + formatDuration(d.next_scan_in_s) : '—');
    statusBar.innerHTML = presenceHtml + (scan.error
      ? '<span><b>Last full scan failed:</b> ' + esc(scan.error) + '</span>'
      : '<span><b>Last full scan:</b> ' + esc(scan.at) + ' (' + scan.duration_s + 's, ' + scan.hosts_up + ' found)</span>') +
      '<span><b>Next full scan:</b> ' + nextScan + '</span>';

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

document.getElementById('reboot-btn').addEventListener('click', async () => {
  const hostname = document.getElementById('page-hostname').textContent;
  if (!confirm('Reboot ' + hostname + ' now?\\n\\nThe dashboard will be unreachable for about a minute while it restarts.')) return;
  const btn = document.getElementById('reboot-btn');
  btn.disabled = true;
  btn.textContent = 'Rebooting…';
  try {
    await fetch('/reboot', { method: 'POST' });
  } catch (e) {
    // expected -- the connection drops as the box goes down
  }
  document.getElementById('status-bar').textContent = 'Reboot triggered -- waiting for ' + hostname + ' to come back online…';
  const waitForReboot = setInterval(async () => {
    try {
      const r = await fetch('/devices');
      if (r.ok) {
        clearInterval(waitForReboot);
        location.reload();
      }
    } catch (e) {
      // still down, keep waiting
    }
  }, 3000);
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
            # Numeric octet-by-octet, not string sort -- "192.168.1.2" must
            # come before "192.168.1.11", which plain string comparison
            # gets wrong (compares '2' vs '1' char-by-char).
            def ip_key(r):
                try:
                    return tuple(int(p) for p in (r.get("ip") or "0.0.0.0").split("."))
                except ValueError:
                    return (0, 0, 0, 0)
            devices = [device_view(r) for r in sorted(_devices_db.values(), key=ip_key)]
            scan_info = dict(_last_scan)
            presence = dict(_presence_state)
        next_in_s = None
        if scan_info["at_epoch"] and not _scan_in_progress.is_set():
            next_in_s = max(0, round(FULL_SCAN_INTERVAL - (time.time() - scan_info["at_epoch"])))
        del scan_info["at_epoch"]
        with _lock:
            internet = dict(_internet_state)
            internet_events = list(_internet_events[-10:])
            speedtest = dict(_speedtest_state)
        body = json.dumps({
            "devices": devices,
            "last_scan": scan_info,
            "next_scan_in_s": next_in_s,
            "scan_interval_s": FULL_SCAN_INTERVAL,
            "presence": presence,
            "presence_interval_s": PRESENCE_INTERVAL,
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
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/scan":
            result = trigger_scan()
        elif parsed.path == "/speedtest":
            result = trigger_speedtest()
        elif parsed.path == "/ping":
            ip = urllib.parse.parse_qs(parsed.query).get("ip", [None])[0]
            result = ping_host(ip)
        elif parsed.path == "/reboot":
            result = trigger_reboot()
        elif parsed.path == "/forget":
            ip = urllib.parse.parse_qs(parsed.query).get("ip", [None])[0]
            result = forget_device(ip)
        elif parsed.path == "/alias":
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            result = set_alias(qs.get("mac", [None])[0], qs.get("name", [""])[0])
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
    load_db()  # before any thread touches the DB
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=presence_loop, daemon=True).start()
    threading.Thread(target=dhcp_listener_loop, daemon=True).start()
    threading.Thread(target=internet_check_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
