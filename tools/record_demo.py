"""Record the README demo GIF: replay the sample capture at N x speed while
the dashboard is open, screenshot it with headless Chrome, stitch a GIF.

    pip install pillow
    python tools/record_demo.py --chrome "C:/Program Files/Google/Chrome/Application/chrome.exe"

The GIF shows the posture going from OK (five minutes of normal traffic)
to CRITICAL as the intrusion unfolds. Output: screenshots/demo.gif.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = "samples/iot-lab.pcap"  # relative: it is shown on the dashboard


def wait_for(url: str, timeout: float = 20) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"{url} did not come up")


def shoot(chrome: str, url: str, out: Path, size: tuple[int, int]) -> None:
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    f"--window-size={size[0]},{size[1]}", "--virtual-time-budget=2500",
                    f"--screenshot={out}", url], check=True, capture_output=True, timeout=60)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", default=shutil.which("chrome") or shutil.which("google-chrome") or "chrome")
    ap.add_argument("--speed", type=float, default=16)
    ap.add_argument("--port", type=int, default=8097)
    ap.add_argument("--width", type=int, default=960, help="GIF width in pixels")
    ap.add_argument("-o", "--output", default=str(ROOT / "screenshots" / "demo.gif"))
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="iotmon-demo-"))
    db = work / "demo.db"
    py = [sys.executable, "-m", "iotmon"]
    replay = subprocess.Popen([*py, "read", SAMPLE, "-q", "--db", str(db), "--speed", str(args.speed)],
                              cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)  # let the replay create the database
    dash = subprocess.Popen([*py, "dashboard", "--db", str(db), "--port", str(args.port), "--read-only"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{args.port}/?utc"
    frames: list[Path] = []
    try:
        wait_for(url)
        while True:
            done = replay.poll() is not None
            out = work / f"f{len(frames):03d}.png"
            shoot(args.chrome, url, out, (1440, 900))
            frames.append(out)
            print(f"frame {len(frames)}", file=sys.stderr)
            if done:
                break
    finally:
        replay.wait()
        dash.terminate()

    images = []
    for f in frames:
        im = Image.open(f).convert("RGB")
        im = im.resize((args.width, round(im.height * args.width / im.width)), Image.LANCZOS)
        images.append(im.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
    durations = [700] * (len(images) - 1) + [4000]  # hold the final state
    images[0].save(args.output, save_all=True, append_images=images[1:], duration=durations, loop=0,
                   optimize=True)
    print(f"{len(images)} frames -> {args.output} ({Path(args.output).stat().st_size / 1e6:.1f} MB)",
          file=sys.stderr)
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
