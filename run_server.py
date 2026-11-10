"""
Production Launcher for Image Cryptosystem.
Starts FastAPI uvicorn server, launches Cloudflare Quick Tunnel,
detects local network IP, and provides clean links for both PC and mobile devices.
"""

import os
import socket
import sys
import time
import webbrowser

# Ensure Windows terminal doesn't crash on UTF-8 characters / emojis
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import uvicorn
from backend import tunnel


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    print("=" * 70)
    print("  [*] AURA-CRYPT: Digital Image Encryption & Security System")
    print("=" * 70)

    lan_ip = get_lan_ip()
    port = 8000

    print(f"\n[1/3] Local Area Network IP detected: {lan_ip}")
    print("[2/3] Initializing automated Cloudflare Quick Tunnel...")
    tunnel.start_tunnel_in_background(port=port)

    # Wait up to 15 seconds for Cloudflare tunnel to establish
    tunnel_url = None
    for _ in range(30):
        tunnel_url = tunnel.get_tunnel_url()
        if tunnel_url:
            break
        time.sleep(0.5)

    from backend.app import start_port80_forwarder
    start_port80_forwarder(target_port=port)
    from backend.app import PORT_80_ACTIVE

    mobile_lan_url = f"http://{lan_ip}" if PORT_80_ACTIVE else f"http://{lan_ip}:{port}"

    print("[3/3] Ready! Access portals available below:\n")
    print(f"  [PC] Localhost:                     http://localhost:{port}")
    if PORT_80_ACTIVE:
        print(f"  [Mobile] Same Wi-Fi / Hotspot:      {mobile_lan_url} (Clean Port 80, No ':8000')")
    else:
        print(f"  [Mobile] Same Wi-Fi / Hotspot:      {mobile_lan_url}")
    if tunnel_url:
        print(f"  [Mobile] Worldwide (Cellular 5G/4G): {tunnel_url} (Clean HTTPS, No Port)")
    else:
        print("  [Mobile] Worldwide:                 Connecting in background (ready in 2s)...")

    print("\n" + "=" * 70)
    print("  Share the encrypted image link with ANY mobile phone or device!")
    print("  Press Ctrl+C anytime to stop the server.")
    print("=" * 70 + "\n")

    # Automatically open local browser
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    # Run Uvicorn server on all network interfaces
    uvicorn.run("backend.app:app", host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
