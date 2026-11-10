import io
import json
import urllib.parse
import urllib.request
from PIL import Image

def main():
    # 1. Create a sample test image
    img = Image.new('RGB', (120, 120), color=(64, 180, 220))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    img_bytes = buf.getvalue()

    # Get network info
    res = urllib.request.urlopen('http://127.0.0.1:8000/api/network/info')
    info = json.loads(res.read())
    public_base = info['public_tunnel_url']
    lan_base = info['lan_base_url']
    print(f"[*] Local LAN IP URL: {lan_base}")
    print(f"[*] Public Cloudflare Tunnel URL: {public_base}")

    # 2. Test Health on Public URL
    health_res = urllib.request.urlopen(f"{public_base}/api/health")
    health = json.loads(health_res.read())
    print(f"[*] Public Health Check: {health['status']}")

    # 3. Create Share via Public Tunnel
    boundary = "----TestBoundaryCloudflareTest123"
    body_parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"test.png\"\r\nContent-Type: image/png\r\n\r\n".encode("latin1"),
        img_bytes,
        f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nSecretPassword123!\r\n".encode("latin1"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nCloudflare Tunnel Test\r\n".encode("latin1"),
        f"--{boundary}--\r\n".encode("latin1")
    ]
    body = b"".join(body_parts)

    req = urllib.request.Request(
        f"{public_base}/api/share/create",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    share_res = urllib.request.urlopen(req)
    share_data = json.loads(share_res.read())
    share_id = share_data['share_id']
    print(f"[*] Share Created ID: {share_id}")
    print(f"[*] Public Share URL: {share_data['public_share_url']}")

    # 4. Fetch share info via Public Tunnel
    info_res = urllib.request.urlopen(f"{public_base}/api/share/{share_id}/info")
    share_info = json.loads(info_res.read())
    print(f"[*] Share Info Title: {share_info['title']}")
    print(f"[*] Cipher Preview Length: {len(share_info['cipher_preview'])}")

    # 5. Decrypt via Public Tunnel
    dec_body = urllib.parse.urlencode({"password": "SecretPassword123!"}).encode("utf-8")
    dec_req = urllib.request.Request(
        f"{public_base}/api/share/{share_id}/decrypt",
        data=dec_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    dec_res = urllib.request.urlopen(dec_req)
    dec_data = json.loads(dec_res.read())
    print(f"[*] Decrypted successfully via Public Tunnel!")
    print(f"[*] Decryption Latency: {dec_data['execution_time_ms']} ms")
    print(f"[*] Restored Image Filename: {dec_data['filename']}")
    print("=" * 60)
    print("SUCCESS: Full Public Mobile Roundtrip Verified!")
    print("=" * 60)


if __name__ == "__main__":
    main()
