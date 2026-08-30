#!/usr/bin/env python3
"""Renders local IP + connectivity status directly to the Pi's SPI TFT
(fb1), 480x320 RGB565. Runs standalone -- takes over fb1 exclusively, so
fbcp must not be running (it would fight over the same framebuffer)."""
import io
import json
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import numpy as np
from PIL import Image, ImageDraw, ImageFont

FB_DEVICE = "/dev/fb1"
WIDTH, HEIGHT = 480, 320
FULL_FRAME_INTERVAL = 1.0
PREVIEW_FRAME_INTERVAL = 0.2
CAM_FAILURES_BEFORE_OFFLINE = 3
WIFI_IFACE = "wlan0"
CAM_STREAM_URL = "http://192.168.1.8/webcam/?action=stream"
CAM_FETCH_TIMEOUT = 0.25
CAM_PREVIEW_BOX = (8, 76, 464, 234)

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
font_title = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans-Bold.ttf", 22)
font_label = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans.ttf", 16)
font_small = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans.ttf", 14)
font_clock = ImageFont.truetype(f"{FONT_DIR}/DejaVuSans-Bold.ttf", 28)

BG = (18, 18, 18)
FG = (235, 235, 235)
DIM = (150, 150, 150)
BAR_BG = (50, 50, 50)


def log_error(context):
    """Prints to stderr so `journalctl -u lcd-display` shows it -- silent
    `except: pass` blocks were the reason failures required manual SSH
    digging instead of just reading the service log."""
    print(f"[{datetime.now().isoformat()}] ERROR in {context}:", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)


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


PING_INTERVAL = 30  # seconds -- connectivity rarely flips faster than this,
# and back-to-back pings every display frame would just be needless load
PING_INTERNET_TARGET = "1.1.1.1"  # fixed IP, no DNS dependency

_connectivity_state = {"router_ok": None, "internet_ok": None, "last_check": 0}


def get_default_gateway():
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _ping_once(host, timeout=1):
    if not host:
        return False
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            capture_output=True, timeout=timeout + 1,
        )
        return r.returncode == 0
    except Exception:
        return False


def check_connectivity():
    """Pings the local router (default gateway) and a fixed internet host,
    gated to PING_INTERVAL so this doesn't run on every 15s frame redraw."""
    now = time.time()
    if now - _connectivity_state["last_check"] < PING_INTERVAL:
        return
    _connectivity_state["router_ok"] = _ping_once(get_default_gateway())
    _connectivity_state["internet_ok"] = _ping_once(PING_INTERNET_TARGET)
    _connectivity_state["last_check"] = now


# Fixed box the clock always renders into -- big enough for "23:59:59" with
# padding. Sized generously so the digit-width variance of a proportional
# (non-monospace) font never leaves a stale pixel behind between ticks.
CLOCK_BOX = (270, 8, 190, 40)  # x, y, w, h


def render_clock_region():
    x, y, w, h = CLOCK_BOX
    img = Image.new("RGB", (w, h), BG)
    draw = ImageDraw.Draw(img)
    clock_str = datetime.now().strftime("%H:%M:%S")
    bbox = draw.textbbox((0, 0), clock_str, font=font_clock)
    tw = bbox[2] - bbox[0]
    draw.text((w - tw - 6, 4), clock_str, font=font_clock, fill=FG)
    return img


# Sits directly below the clock, in the gap before the divider line at y=68.
CONN_BOX = (270, 49, 190, 18)  # x, y, w, h


def render_conn_region():
    _, _, w, h = CONN_BOX
    img = Image.new("RGB", (w, h), BG)
    draw = ImageDraw.Draw(img)

    def dot_color(ok):
        if ok is None:
            return DIM
        return (70, 200, 110) if ok else (235, 90, 90)

    # Right-aligned to match the clock above it: "RTR o   NET o"
    draw.text((w - 106, 2), "RTR", font=font_small, fill=DIM)
    draw.ellipse([w - 78, 3, w - 66, 15], fill=dot_color(_connectivity_state["router_ok"]))
    draw.text((w - 56, 2), "NET", font=font_small, fill=DIM)
    draw.ellipse([w - 28, 3, w - 16, 15], fill=dot_color(_connectivity_state["internet_ok"]))
    return img


def fetch_webcam_frame(url):
    """Best-effort fetch of the first JPEG frame from an MJPEG stream."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "lan-dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=CAM_FETCH_TIMEOUT) as resp:
            # MJPEG streams are multipart; read the first part headers and then
            # consume exactly the content-length bytes for that JPEG frame.
            first_line = resp.readline()
            if not first_line:
                return None

            headers = {}
            while True:
                line = resp.readline()
                if not line:
                    return None
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.decode("latin1").strip().lower()] = value.decode("latin1").strip()

            content_length = headers.get("content-length")
            if content_length is None:
                return None
            payload = resp.read(int(content_length))
            if not payload:
                return None

            try:
                with Image.open(io.BytesIO(payload)) as im:
                    return im.convert("RGB")
            except Exception:
                return None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def _octoprint_api_key():
    try:
        with open(os.path.expanduser("~/.octoprint/config.yaml")) as f:
            m = re.search(r"^api:\s*\n\s*key:\s*(\S+)", f.read(), re.MULTILINE)
        return m.group(1) if m else None
    except Exception:
        return None


def get_printer_overlay_info():
    api_key = _octoprint_api_key()
    if not api_key:
        return None, None
    try:
        conn_req = urllib.request.Request(
            "http://127.0.0.1:5000/api/connection",
            headers={"X-Api-Key": api_key},
        )
        with urllib.request.urlopen(conn_req, timeout=1) as resp:
            conn = json.loads(resp.read())
        state = (conn.get("current") or {}).get("state") or "UNKNOWN"

        job_req = urllib.request.Request(
            "http://127.0.0.1:5000/api/job",
            headers={"X-Api-Key": api_key},
        )
        with urllib.request.urlopen(job_req, timeout=1) as resp:
            job_data = json.loads(resp.read())
        job_file = ((job_data.get("job") or {}).get("file") or {}).get("display") or ""
        return state, job_file
    except Exception:
        return None, None


def render_preview_layer(cam_frame, x=None, y=None, w=None, h=None):
    if x is None or y is None or w is None or h is None:
        x, y, w, h = CAM_PREVIEW_BOX
    img = Image.new("RGB", (w, h), BG)
    if cam_frame is not None:
        preview = cam_frame.resize((w, h), Image.LANCZOS)
        img.paste(preview, (0, 0))
        ts = datetime.now().strftime("%H:%M:%S")
        draw = ImageDraw.Draw(img)
        ts_bbox = draw.textbbox((0, 0), ts, font=font_small)
        ts_w = ts_bbox[2] - ts_bbox[0]
        ts_h = ts_bbox[3] - ts_bbox[1]
        overlay = Image.new("RGBA", (ts_w + 12, ts_h + 8), (0, 0, 0, 140))
        overlay_draw = ImageDraw.Draw(overlay)
        overlay_draw.text((6, 4), ts, font=font_small, fill=(255, 255, 255, 255))
        img.paste(overlay, (w - ts_w - 18, 8), overlay)
    else:
        draw = ImageDraw.Draw(img)
        draw.text((10, h - 22), "stream offline", font=font_small, fill=DIM)
    return img


def render_frame(ip, hostname, cam_frame=None, preview_only=False):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    draw.text((20, 14), hostname, font=font_title, fill=FG)
    draw.text((20, 42), "IP " + ip, font=font_label, fill=DIM)

    img.paste(render_clock_region(), (CLOCK_BOX[0], CLOCK_BOX[1]))
    img.paste(render_conn_region(), (CONN_BOX[0], CONN_BOX[1]))

    draw.line([(20, 68), (WIDTH - 20, 68)], fill=BAR_BG, width=1)

    x, y, w, h = CAM_PREVIEW_BOX
    draw.rectangle([x, y, x + w - 1, y + h - 1], outline=(95, 95, 95), width=1)

    if not preview_only:
        # Use the same preview renderer for the full refresh as for the
        # partial update.  This keeps the offline label in the bottom-left
        # and never leaves a timestamp over an unavailable stream.
        img.paste(render_preview_layer(cam_frame, x, y, w, h), (x, y))

    return img


def write_to_fb(img):
    arr = np.asarray(img, dtype=np.uint8)
    r = (arr[:, :, 0] >> 3).astype(np.uint16)
    g = (arr[:, :, 1] >> 2).astype(np.uint16)
    b = (arr[:, :, 2] >> 3).astype(np.uint16)
    rgb565 = (r << 11) | (g << 5) | b
    with open(FB_DEVICE, "wb") as f:
        f.write(rgb565.astype("<u2").tobytes())


FB_STRIDE = WIDTH * 2  # bytes/row (matches `fbset`'s LineLength=960 for 480px @ 16bpp)


def write_region_to_fb(img, x0, y0):
    """Partial write -- only touches the rows/columns img covers, instead of
    rewriting the full 307KB frame. Used for the per-second clock tick so
    ticking every second doesn't mean a full redraw every second."""
    arr = np.asarray(img, dtype=np.uint8)
    h = arr.shape[0]
    r = (arr[:, :, 0] >> 3).astype(np.uint16)
    g = (arr[:, :, 1] >> 2).astype(np.uint16)
    b = (arr[:, :, 2] >> 3).astype(np.uint16)
    rgb565 = ((r << 11) | (g << 5) | b).astype("<u2")
    with open(FB_DEVICE, "r+b") as f:
        for row in range(h):
            f.seek((y0 + row) * FB_STRIDE + x0 * 2)
            f.write(rgb565[row].tobytes())


def main():
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    next_full_redraw = 0
    next_preview_redraw = 0
    next_clock_tick = 0
    last_cam_frame = None
    cam_failures = 0
    while True:
        now = time.time()

        if now >= next_clock_tick:
            try:
                write_region_to_fb(render_clock_region(), CLOCK_BOX[0], CLOCK_BOX[1])
            except Exception:
                log_error("write_region_to_fb")
            next_clock_tick = now + 0.25

        if now >= next_preview_redraw:
            try:
                cam_frame = fetch_webcam_frame(CAM_STREAM_URL)
                if cam_frame is not None:
                    last_cam_frame = cam_frame
                    cam_failures = 0
                else:
                    cam_failures += 1
                    if cam_failures >= CAM_FAILURES_BEFORE_OFFLINE:
                        last_cam_frame = None
                preview_img = render_preview_layer(last_cam_frame)
                write_region_to_fb(preview_img, CAM_PREVIEW_BOX[0], CAM_PREVIEW_BOX[1])
            except Exception:
                cam_failures += 1
                if cam_failures >= CAM_FAILURES_BEFORE_OFFLINE:
                    last_cam_frame = None
                log_error("preview update")
            next_preview_redraw = now + PREVIEW_FRAME_INTERVAL

        if now >= next_full_redraw:
            ip = get_local_ip()
            check_connectivity()
            # Keep the most recently decoded frame in the full redraw.  A
            # header refresh must never blank the preview between its own
            # partial framebuffer updates.
            img = render_frame(ip, hostname, last_cam_frame)
            try:
                write_to_fb(img)
            except Exception:
                # A framebuffer write failure shouldn't crash the refresh
                # loop (the display might be mid-reinit, e.g. after a
                # driver reload), but it must not vanish silently either --
                # that's how this system spent a week failing invisibly.
                log_error("write_to_fb")
            next_full_redraw = now + FULL_FRAME_INTERVAL

        time.sleep(0.02)


if __name__ == "__main__":
    main()
