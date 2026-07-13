#!/usr/bin/env python3
"""Renders Claude usage + local IP directly to the Pi's SPI TFT (fb1),
480x320 RGB565. Runs standalone -- takes over fb1 exclusively, so fbcp
must not be running (it would fight over the same framebuffer)."""
import json
import math
import os
import re
import struct
import subprocess
import time
import urllib.error
import urllib.request
import wave
from datetime import datetime, timezone

import numpy as np
from PIL import Image, ImageDraw, ImageFont

CREDS_PATH = "/home/pi/.claude_oauth_credentials.json"
FB_DEVICE = "/dev/fb1"
WIDTH, HEIGHT = 480, 320
FRAME_INTERVAL = 15       # seconds; cheap redraw (clock/IP) using cached usage
USAGE_POLL_INTERVAL = 120  # seconds; the actual rate-limited API call
USAGE_BACKOFF_DEFAULT = 300  # seconds; fallback wait on 429 if no Retry-After given -- deliberately more conservative than the normal poll interval, so an actual rate-limit hit doesn't get retried at the same aggressive cadence that caused it
WIFI_IFACE = "wlan0"

BEEP_SHORT_WAV = "/home/pi/beep_short.wav"
BEEP_LONG_WAV = "/home/pi/beep_long.wav"
MILESTONE_STEP = 5  # percent

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
font_title = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans-Bold.ttf", 22)
font_pct = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans-Bold.ttf", 40)
font_label = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans.ttf", 16)
font_small = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans.ttf", 14)

BG = (18, 18, 18)
FG = (235, 235, 235)
DIM = (150, 150, 150)
BAR_BG = (50, 50, 50)


def get_local_ip():
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", WIFI_IFACE],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "no IP"
    except Exception:
        return "no IP"


USAGE_CACHE_PATH = "/home/pi/.usage_cache.json"
_usage_cache = {"result": None, "next_allowed_fetch": 0}


def _load_usage_cache():
    """Persisted to disk so a service restart (crash, redeploy, reboot)
    doesn't reset next_allowed_fetch to 0 and immediately fire a fresh API
    call -- an in-memory-only cache defeats the whole point of backing off
    on repeated restarts, which is exactly what happened during iterative
    deploys."""
    global _usage_cache
    try:
        with open(USAGE_CACHE_PATH) as f:
            loaded = json.load(f)
        if isinstance(loaded, dict) and "next_allowed_fetch" in loaded:
            _usage_cache = loaded
    except Exception:
        pass


def _save_usage_cache():
    try:
        tmp = USAGE_CACHE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_usage_cache, f)
        os.replace(tmp, USAGE_CACHE_PATH)
    except Exception:
        pass


def _get_bearer_token():
    """Just reads the current token -- auto-refresh was tried (endpoint and
    client_id verified against the official CLI binary) but the actual
    POST got 403 Forbidden, meaning the real client does something in this
    flow (extra headers, device attestation, PKCE context from the
    original login, etc.) that isn't safely reverse-engineerable. Staying
    fresh is handled externally instead: a launchd job on the Mac re-pushes
    the Keychain-refreshed token to this file every 4 hours."""
    with open(CREDS_PATH) as f:
        return json.load(f)["claudeAiOauth"]["accessToken"]


def _fetch_usage():
    try:
        token = _get_bearer_token()
        req = urllib.request.Request(
            "https://api.anthropic.com/api/oauth/usage",
            headers={"Authorization": "Bearer " + token, "anthropic-beta": "oauth-2025-04-20"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": True, "data": json.loads(resp.read())}, USAGE_POLL_INTERVAL
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = e.headers.get("Retry-After")
            try:
                wait = int(retry_after) if retry_after else USAGE_BACKOFF_DEFAULT
            except ValueError:
                wait = USAGE_BACKOFF_DEFAULT
            return {"ok": False, "error": "HTTP 429 (rate limited)"}, wait
        return {"ok": False, "error": f"HTTP {e.code}"}, USAGE_POLL_INTERVAL
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}, 30  # transient (network etc), retry soon


def get_usage():
    """Cached: only actually calls the API every USAGE_POLL_INTERVAL (longer
    still after a 429, respecting Retry-After) -- this endpoint doesn't need
    to be polled every render frame, and polling it that aggressively is
    exactly what caused the 429s in the first place."""
    now = time.time()
    if now >= _usage_cache["next_allowed_fetch"]:
        result, wait = _fetch_usage()
        _usage_cache["next_allowed_fetch"] = now + wait
        if result["ok"] or _usage_cache["result"] is None:
            _usage_cache["result"] = result
        else:
            # Fetch failed but we have a previous good result -- keep showing
            # it rather than replacing a working display with an error.
            pass
        _save_usage_cache()
    return _usage_cache["result"]


def _generate_tone_wav(path, freq_hz, duration_ms, volume=0.95, sample_rate=22050):
    """Simple sine tone with a short fade in/out (avoids a click at the
    edges), written as a stdlib wave file -- no sound assets to source
    or commit, the script is self-contained."""
    n_samples = int(sample_rate * duration_ms / 1000)
    fade_samples = min(200, n_samples // 4)
    samples = []
    for i in range(n_samples):
        t = i / sample_rate
        amp = volume
        if i < fade_samples:
            amp *= i / fade_samples
        elif i > n_samples - fade_samples:
            amp *= (n_samples - i) / fade_samples
        value = int(amp * 32767 * math.sin(2 * math.pi * freq_hz * t))
        samples.append(struct.pack("<h", value))
    with wave.open(path, "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(sample_rate)
        f.writeframes(b"".join(samples))


def ensure_beep_files():
    # Regenerate unconditionally -- earlier files were at 50% amplitude and
    # too quiet to hear (confirmed by reading back the raw samples), so a
    # stale existing-file check would keep the quiet version around forever.
    _generate_tone_wav(BEEP_SHORT_WAV, freq_hz=1200, duration_ms=250)
    _generate_tone_wav(BEEP_LONG_WAV, freq_hz=500, duration_ms=1000)


def _play_wav(path):
    try:
        subprocess.Popen(["aplay", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def flash_screen(color, text, pulses=2, on_ms=350, off_ms=180):
    """Briefly pulses a solid color + centered message on the LCD, then lets
    the normal render loop resume on its next cycle. Runs synchronously
    (blocks the render loop for ~1s) -- acceptable since this only fires on
    genuinely rare events, not every frame."""
    is_light = sum(color) > 380
    text_color = (20, 20, 20) if is_light else (245, 245, 245)
    for i in range(pulses):
        img = Image.new("RGB", (WIDTH, HEIGHT), color)
        draw = ImageDraw.Draw(img)
        bbox = draw.textbbox((0, 0), text, font=font_title)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((WIDTH - tw) // 2, (HEIGHT - th) // 2), text, font=font_title, fill=text_color)
        try:
            write_to_fb(img)
        except Exception:
            pass
        time.sleep(on_ms / 1000)
        if i < pulses - 1:
            try:
                write_to_fb(Image.new("RGB", (WIDTH, HEIGHT), BG))
            except Exception:
                pass
            time.sleep(off_ms / 1000)


_session_state = {"last_milestone": None, "last_resets_at": None}


def check_session_events(five_hour):
    """Short beep + flash each time session usage crosses a new 5%
    milestone; long beep + flash when the session window itself rolls over
    (detected via resets_at changing to a new value). First observation
    after a service (re)start just establishes a baseline rather than
    firing a notification storm for whatever level usage already happens
    to be at."""
    pct = five_hour.get("utilization")
    resets_at = five_hour.get("resets_at")
    if pct is None:
        return

    current_milestone = int(pct // MILESTONE_STEP) * MILESTONE_STEP
    reset_str = format_reset(resets_at) if resets_at else "?"

    if _session_state["last_resets_at"] is None:
        _session_state["last_resets_at"] = resets_at
        _session_state["last_milestone"] = current_milestone
        return

    if resets_at and resets_at != _session_state["last_resets_at"]:
        _play_wav(BEEP_LONG_WAV)
        flash_screen((90, 140, 235), f"Session reset — next in {reset_str}")
        _session_state["last_resets_at"] = resets_at
        _session_state["last_milestone"] = current_milestone
        return

    if _session_state["last_milestone"] is not None and current_milestone > _session_state["last_milestone"]:
        _play_wav(BEEP_SHORT_WAV)
        flash_screen(color_for_pct(pct), f"{current_milestone}% used — resets in {reset_str}")
    _session_state["last_milestone"] = current_milestone


def format_reset(iso_str):
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        secs = int((dt - datetime.now(timezone.utc)).total_seconds())
        if secs < 0:
            return "now"
        days, rem = divmod(secs, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        if days:
            return f"{days}d {hours}h"
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return "?"


def format_reset_absolute(iso_str):
    """The actual clock time a window resets at (local time), alongside the
    relative countdown from format_reset() -- e.g. "4h 48m" + "20:00"."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00")).astimezone()
        now_local = datetime.now().astimezone()
        if dt.date() == now_local.date():
            return dt.strftime("%H:%M")
        return dt.strftime("%a %H:%M")
    except Exception:
        return "?"


def color_for_pct(pct):
    if pct is None:
        return DIM
    if pct < 50:
        return (70, 200, 110)
    if pct < 80:
        return (235, 190, 60)
    return (235, 90, 90)


def draw_meter(draw, y, label, pct, reset_str, reset_at_str):
    color = color_for_pct(pct)
    draw.text((20, y), label, font=font_label, fill=DIM)
    pct_text = f"{pct:.0f}%" if pct is not None else "--"
    draw.text((20, y + 20), pct_text, font=font_pct, fill=color)

    bar_x, bar_y, bar_w, bar_h = 150, y + 38, 310, 14
    draw.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h], fill=BAR_BG)
    if pct is not None:
        fill_w = max(0, min(bar_w, int(bar_w * pct / 100)))
        if fill_w > 0:
            draw.rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + bar_h], fill=color)

    if reset_str:
        draw.text((150, y + 58), f"Resets in {reset_str}, {reset_at_str}", font=font_small, fill=DIM)


def render_frame(ip, hostname, usage_result):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    draw.text((20, 14), hostname, font=font_title, fill=FG)
    draw.text((20, 42), "IP " + ip, font=font_label, fill=DIM)
    draw.line([(20, 68), (WIDTH - 20, 68)], fill=BAR_BG, width=1)

    if usage_result["ok"]:
        data = usage_result["data"]
        five_hour = data.get("five_hour") or {}
        seven_day = data.get("seven_day") or {}
        session_resets_at = five_hour.get("resets_at")
        weekly_resets_at = seven_day.get("resets_at")
        draw_meter(draw, 90, "SESSION (5 HOUR)", five_hour.get("utilization"),
                   format_reset(session_resets_at), format_reset_absolute(session_resets_at))
        draw_meter(draw, 195, "WEEKLY", seven_day.get("utilization"),
                   format_reset(weekly_resets_at), format_reset_absolute(weekly_resets_at))
    else:
        draw.text((20, 130), "Claude usage unavailable", font=font_label, fill=(235, 90, 90))
        draw.text((20, 155), usage_result["error"], font=font_small, fill=DIM)

    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    draw.text((20, HEIGHT - 26), "updated " + now_str, font=font_small, fill=DIM)

    return img


def write_to_fb(img):
    arr = np.asarray(img, dtype=np.uint8)
    r = (arr[:, :, 0] >> 3).astype(np.uint16)
    g = (arr[:, :, 1] >> 2).astype(np.uint16)
    b = (arr[:, :, 2] >> 3).astype(np.uint16)
    rgb565 = (r << 11) | (g << 5) | b
    with open(FB_DEVICE, "wb") as f:
        f.write(rgb565.astype("<u2").tobytes())


def main():
    ensure_beep_files()
    _load_usage_cache()
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    while True:
        ip = get_local_ip()
        usage_result = get_usage()
        if usage_result["ok"]:
            five_hour = usage_result["data"].get("five_hour") or {}
            check_session_events(five_hour)
        img = render_frame(ip, hostname, usage_result)
        try:
            write_to_fb(img)
        except Exception:
            pass  # framebuffer write failing shouldn't crash the refresh loop
        time.sleep(FRAME_INTERVAL)


if __name__ == "__main__":
    main()
