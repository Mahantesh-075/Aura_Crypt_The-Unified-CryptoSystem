"""
Automatic Cloudflare Quick Tunnel Manager.
Starts and monitors cloudflared in the background to provide a permanent,
free HTTPS URL without account or credentials, enabling mobile devices
on cellular data to access the encryption/decryption portal worldwide.
"""

import atexit
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Optional

_tunnel_process: Optional[subprocess.Popen] = None
_tunnel_url: Optional[str] = None
_tunnel_lock = threading.Lock()
_stop_event = threading.Event()
_monitor_thread: Optional[threading.Thread] = None

# Base directory for storing tunnel state
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOUDFLARED_BIN = os.path.join(PROJECT_ROOT, "cloudflared.exe")
URL_FILE = os.path.join(PROJECT_ROOT, "storage", "tunnel_url.txt")

CLOUDFLARE_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")


def get_cloudflared_executable() -> Optional[str]:
    """Find cloudflared executable in project root or system PATH."""
    if os.path.isfile(CLOUDFLARED_BIN):
        return CLOUDFLARED_BIN
    system_path = shutil.which("cloudflared")
    if system_path:
        return system_path
    return None


def get_tunnel_url() -> Optional[str]:
    """Return the currently active public Cloudflare HTTPS tunnel URL."""
    with _tunnel_lock:
        return _tunnel_url


def _tunnel_worker(port: int = 8000):
    """Background worker that runs and auto-restarts cloudflared if it ever drops."""
    global _tunnel_process, _tunnel_url

    exe = get_cloudflared_executable()
    if not exe:
        print("[Tunnel] cloudflared.exe not found. Public tunnel disabled.")
        return

    os.makedirs(os.path.dirname(URL_FILE), exist_ok=True)

    while not _stop_event.is_set():
        try:
            print(f"[Tunnel] Starting Cloudflare Quick Tunnel on port {port}...")
            cmd = [
                exe,
                "tunnel",
                "--url",
                f"http://127.0.0.1:{port}",
                "--no-autoupdate",
            ]

            # Windows-specific: CREATE_NO_WINDOW prevents popup console windows
            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NO_WINDOW

            _tunnel_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )

            # Read stream line by line to extract the assigned URL
            for line in iter(_tunnel_process.stdout.readline, ""):
                if _stop_event.is_set():
                    break
                match = CLOUDFLARE_REGEX.search(line)
                if match:
                    found_url = match.group(0).rstrip(".")
                    with _tunnel_lock:
                        _tunnel_url = found_url
                    print(f"[Tunnel] Active public URL: {_tunnel_url}")
                    try:
                        with open(URL_FILE, "w", encoding="utf-8") as f:
                            f.write(_tunnel_url)
                    except Exception:
                        pass

            _tunnel_process.wait()
        except Exception as exc:
            print(f"[Tunnel] Process error: {exc}")

        with _tunnel_lock:
            _tunnel_url = None

        if not _stop_event.is_set():
            print("[Tunnel] Tunnel disconnected. Reconnecting in 3 seconds...")
            time.sleep(3)


def start_tunnel_in_background(port: int = 8000):
    """Start the tunnel manager thread (idempotent)."""
    global _monitor_thread
    if not get_cloudflared_executable():
        print("[Tunnel] cloudflared executable not available, skipping tunnel start.")
        return

    with _tunnel_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return
        _stop_event.clear()
        _monitor_thread = threading.Thread(
            target=_tunnel_worker,
            args=(port,),
            daemon=True,
            name="CloudflareTunnelWorker",
        )
        _monitor_thread.start()


def stop_tunnel():
    """Cleanly terminate tunnel on shutdown."""
    global _tunnel_process
    _stop_event.set()
    with _tunnel_lock:
        if _tunnel_process:
            try:
                _tunnel_process.terminate()
            except Exception:
                pass
            _tunnel_process = None


atexit.register(stop_tunnel)
