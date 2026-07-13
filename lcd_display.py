#!/usr/bin/env python3
"""Renders Claude usage + local IP directly to the Pi's SPI TFT (fb1),
480x320 RGB565. Runs standalone -- takes over fb1 exclusively, so fbcp
must not be running (it would fight over the same framebuffer)."""
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
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


_usage_cache = {"result": None, "next_allowed_fetch": 0}


def _fetch_usage():
    try:
        with open(CREDS_PATH) as f:
            token = json.load(f)["claudeAiOauth"]["accessToken"]
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
    return _usage_cache["result"]


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


def color_for_pct(pct):
    if pct is None:
        return DIM
    if pct < 50:
        return (70, 200, 110)
    if pct < 80:
        return (235, 190, 60)
    return (235, 90, 90)


def draw_meter(draw, y, label, pct, reset_str):
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

    reset_text = f"Resets in {reset_str}" if reset_str else ""
    draw.text((150, y + 58), reset_text, font=font_small, fill=DIM)


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
        draw_meter(draw, 90, "SESSION (5 HOUR)", five_hour.get("utilization"), format_reset(five_hour.get("resets_at")))
        draw_meter(draw, 190, "WEEKLY", seven_day.get("utilization"), format_reset(seven_day.get("resets_at")))
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
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    while True:
        ip = get_local_ip()
        usage_result = get_usage()
        img = render_frame(ip, hostname, usage_result)
        try:
            write_to_fb(img)
        except Exception:
            pass  # framebuffer write failing shouldn't crash the refresh loop
        time.sleep(FRAME_INTERVAL)


if __name__ == "__main__":
    main()
