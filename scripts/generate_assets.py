#!/usr/bin/env python3
"""
Generates visual assets for T3-VaultGuard (`t3-build-scale-grant`):
  - logo.png (512x512) and docs/logo.png
  - screenshots/01-overview-console.png (1920x1080)
  - screenshots/02-zero-leak-sandbox.png (1920x1080)
  - screenshots/03-prompt-injection-blocked.png (1920x1080)
  - screenshots/04-smart-vc-and-merkle-audit.png (1920x1080)
  - demo.mp4 (1920x1080, 16-second 30fps H.264 + AAC walkthrough video)
"""
import math
import shutil
import subprocess
import tempfile
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

ROOT = Path("/home/jeff/.gemini/antigravity/scratch/freelancework/t3-build-scale-grant")
DOCS = ROOT / "docs"
SCREENSHOTS = ROOT / "screenshots"


def generate_logo(out_path: Path):
    w, h = 512, 512
    yy, xx = np.meshgrid(np.linspace(-1, 1, h), np.linspace(-1, 1, w), indexing="ij")
    r = np.hypot(xx, yy)
    bg = np.zeros((h, w, 3), dtype=np.uint8)
    bg[..., 0] = np.clip(10 + 18 * (1 - r), 6, 30).astype(np.uint8)
    bg[..., 1] = np.clip(18 + 38 * (1 - r), 10, 60).astype(np.uint8)
    bg[..., 2] = np.clip(36 + 65 * (1 - r), 20, 110).astype(np.uint8)

    img = Image.fromarray(bg, mode="RGB").convert("RGBA")
    draw = ImageDraw.Draw(img)

    # Outer hexagonal TEE Enclave shield
    cx, cy = 256, 256
    hex_outer = [
        (cx + int(195 * math.cos(math.radians(60 * i - 30))),
         cy + int(195 * math.sin(math.radians(60 * i - 30))))
        for i in range(6)
    ]
    hex_inner = [
        (cx + int(158 * math.cos(math.radians(60 * i - 30))),
         cy + int(158 * math.sin(math.radians(60 * i - 30))))
        for i in range(6)
    ]
    draw.polygon(hex_outer, fill=(14, 25, 45, 255), outline=(16, 185, 129, 255), width=6)
    draw.polygon(hex_inner, fill=(8, 15, 28, 255), outline=(99, 102, 241, 255), width=3)

    # Vault keyhole / T3 emblem
    draw.rounded_rectangle([188, 175, 324, 202], radius=8, fill=(16, 185, 129, 255))
    draw.rounded_rectangle([240, 175, 272, 330], radius=8, fill=(16, 185, 129, 255))
    draw.ellipse([226, 232, 286, 292], fill=(8, 15, 28, 255), outline=(245, 158, 11, 255), width=5)

    out_rgb = img.convert("RGB")
    out_rgb.save(out_path, "PNG")
    out_rgb.save(DOCS / "logo.png", "PNG")
    print("Saved logo:", out_path)


def capture_screenshots():
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    index_uri = (DOCS / "index.html").as_uri()

    views = [
        ("01-overview-console.png", f"{index_uri}?view=all&scenario=flight"),
        ("02-zero-leak-sandbox.png", f"{index_uri}?view=sandbox&scenario=stripe"),
        ("03-prompt-injection-blocked.png", f"{index_uri}?view=all&scenario=attack"),
        ("04-smart-vc-and-merkle-audit.png", f"{index_uri}?view=audit"),
    ]

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(args=["--allow-file-access-from-files"])
        except Exception:
            browser = p.chromium.launch(channel="chrome", args=["--allow-file-access-from-files"])
        page = browser.new_page(viewport={"width": 1920, "height": 1080}, device_scale_factor=1)
        for fname, url in views:
            page.goto(url)
            page.wait_for_timeout(300)
            out_file = SCREENSHOTS / fname
            page.screenshot(path=str(out_file), full_page=False)
            shutil.copy(out_file, DOCS / fname)
            print("Captured screenshot:", out_file)
        browser.close()


def generate_demo_video():
    """Renders a 16-second 1920x1080 30fps H.264 + AAC walkthrough video (demo.mp4)."""
    fps = 30
    duration = 16.0
    total_frames = int(fps * duration)
    sr = 48000

    # Synthesize clean ambient electronic score
    n = int(duration * sr)
    t = np.linspace(0, duration, n, endpoint=False)
    sig = (
        0.18 * np.sin(2 * np.pi * 110.0 * t)
        + 0.12 * np.sin(2 * np.pi * 164.81 * t)
        + 0.10 * np.sin(2 * np.pi * 220.0 * t)
        + 0.06 * np.sin(2 * np.pi * 329.63 * t * (1 + 0.002 * np.sin(2 * np.pi * 0.5 * t)))
    ) * np.clip(t / 0.5, 0, 1) * np.clip((duration - t) / 0.8, 0, 1)
    pcm = (np.clip(sig, -0.95, 0.95) * 32767).astype(np.int16)
    stereo = np.column_stack([pcm, pcm])

    tmp_dir = Path(tempfile.mkdtemp(prefix="t3_demo_"))
    wav_path = tmp_dir / "audio.wav"
    with wave.open(str(wav_path), "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(stereo.tobytes())

    slides = [
        Image.open(SCREENSHOTS / "01-overview-console.png").convert("RGB"),
        Image.open(SCREENSHOTS / "02-zero-leak-sandbox.png").convert("RGB"),
        Image.open(SCREENSHOTS / "03-prompt-injection-blocked.png").convert("RGB"),
        Image.open(SCREENSHOTS / "04-smart-vc-and-merkle-audit.png").convert("RGB"),
    ]
    arrs = [np.asarray(im, dtype=np.float32) for im in slides]

    for f in range(total_frames):
        sec = f / fps
        idx = min(3, int(sec // 4.0))
        local_u = (sec - idx * 4.0) / 4.0
        cur = arrs[idx]
        if local_u > 0.85 and idx < 3:
            alpha = (local_u - 0.85) / 0.15
            nxt = arrs[idx + 1]
            blended = (cur * (1 - alpha) + nxt * alpha).astype(np.uint8)
        else:
            blended = cur.astype(np.uint8)
        Image.fromarray(blended, mode="RGB").save(tmp_dir / f"{f:04d}.png", "PNG", compress_level=1)

    for target in [ROOT / "demo.mp4", DOCS / "demo.mp4"]:
        subprocess.run([
            "ffmpeg", "-v", "error", "-y",
            "-framerate", str(fps),
            "-i", str(tmp_dir / "%04d.png"),
            "-i", str(wav_path),
            "-frames:v", str(total_frames),
            "-c:v", "libx264", "-preset", "fast", "-crf", "20", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "128k",
            "-shortest", "-movflags", "+faststart",
            str(target)
        ], check=True)
    shutil.rmtree(tmp_dir)
    print("Saved demo video:", ROOT / "demo.mp4")


if __name__ == "__main__":
    generate_logo(ROOT / "logo.png")
    capture_screenshots()
    generate_demo_video()
