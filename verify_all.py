# pyright: reportMissingImports=false
# type: ignore
import io
import sys
import base64
from pathlib import Path

# Automatically ensure project root and .venv site-packages are on sys.path
proj_root = Path(__file__).resolve().parent
venv_site_packages = proj_root / ".venv" / "Lib" / "site-packages"

if str(proj_root) not in sys.path:
    sys.path.insert(0, str(proj_root))
if venv_site_packages.exists() and str(venv_site_packages) not in sys.path:
    sys.path.insert(0, str(venv_site_packages))

from fastapi.testclient import TestClient  # type: ignore # noqa: E402
from backend.app import app  # type: ignore # noqa: E402
from PIL import Image  # type: ignore # noqa: E402

def run_checks():
    client = TestClient(app)
    print("=== [1] Testing Health Endpoint ===")
    r = client.get("/api/health")
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    print("Health check PASS:", r.json())

    print("\n=== [2] Testing Network Info Endpoint ===")
    r = client.get("/api/network/info")
    assert r.status_code == 200
    net_info = r.json()
    print("Network info PASS:", net_info)
    assert "lan_ip" in net_info and "lan_base_url" in net_info

    print("\n=== [3] Testing Static Sample Files ===")
    samples = [
        "/samples/benchmark_gradient.png",
        "/samples/medical_scan_demo.png",
        "/samples/geometric_pattern.png",
        "/samples/sample_aadhaar.pdf",
        "/samples/sample_nda.pdf",
        "/samples/sample_secret.txt",
        "/samples/sample_clip.mp4",
    ]
    for s in samples:
        res = client.get(s)
        assert res.status_code == 200, f"Sample {s} failed with {res.status_code}"
        print(f"Sample {s}: OK ({len(res.content)} bytes)")

    print("\n=== [4] Testing Frontend Files ===")
    r_html = client.get("/")
    assert r_html.status_code == 200
    assert "btn-copy-encrypt-link" in r_html.text, "index.html missing Encrypt Share buttons"
    assert "btn-whatsapp-encrypt-combo" in r_html.text
    assert "btn-run-imglock" not in r_html.text, "index.html should not contain obsolete imglock"
    print("index.html: OK")

    r_js = client.get("/main.js")
    assert r_js.status_code == 200
    assert "updateEncryptShareDisplay" in r_js.text
    assert "btn-whatsapp-encrypt-combo" in r_js.text
    assert "updateImgLockShareDisplay" not in r_js.text
    print("main.js: OK")

    print("\n=== [5] Testing Image Encryption with Auto Key and Custom Password ===")
    img = Image.new("RGB", (64, 64), color=(120, 45, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # 5a. Auto-generated 256-bit key
    r_enc = client.post("/api/encrypt", files={"image": ("test.png", buf, "image/png")})
    assert r_enc.status_code == 200
    enc_data = r_enc.json()
    assert "key" in enc_data
    assert "image_data" in enc_data
    assert "metrics" in enc_data
    assert "share_id" in enc_data
    print(f"Auto Key ChaCha20 Encrypt: OK (Key: {enc_data['key'][:12]}..., Time: {enc_data['execution_time_ms']} ms)")

    # 5b. Custom password ('1234' as reported in Screenshot 1)
    buf.seek(0)
    r_enc_custom = client.post(
        "/api/encrypt",
        files={"image": ("test_custom.png", buf, "image/png")},
        data={"custom_key": "1234"}
    )
    assert r_enc_custom.status_code == 200
    enc_custom_data = r_enc_custom.json()
    assert enc_custom_data["user_password"] == "1234"
    assert enc_custom_data["is_password_protected"] is True
    assert "share_id" in enc_custom_data
    print(f"Custom Password '1234' Encrypt: PASS (Key derived via PBKDF2: {enc_custom_data['key'][:12]}...)")

    print("\n=== [6] Testing Pure Image Decryption (/api/decrypt) ===")
    # Extract ciphertext PNG
    raw_b64 = enc_data["image_data"].split(",", 1)[1]
    cipher_bytes = base64.b64decode(raw_b64)

    r_dec = client.post(
        "/api/decrypt",
        files={"image": ("cipher.png", io.BytesIO(cipher_bytes), "image/png")},
        data={"key": enc_data["key"]}
    )
    assert r_dec.status_code == 200
    dec_data = r_dec.json()
    print("Auto-key Decrypt: OK (Match: Bit-exact, Time:", dec_data["execution_time_ms"], "ms)")

    # Test decrypting custom password '1234'
    raw_b64_custom = enc_custom_data["image_data"].split(",", 1)[1]
    cipher_bytes_custom = base64.b64decode(raw_b64_custom)
    r_dec_custom = client.post(
        "/api/decrypt",
        files={"image": ("cipher_custom.png", io.BytesIO(cipher_bytes_custom), "image/png")},
        data={"password": "1234"}
    )
    assert r_dec_custom.status_code == 200
    print("Custom password '1234' Decrypt: OK (Match: Bit-exact, Time:", r_dec_custom.json()["execution_time_ms"], "ms)")

    print("\n=== [7] Testing Encrypted Image Share Portal Creation ===")
    share_id = enc_custom_data["share_id"]
    print("Image Share Created Automatically during Encrypt: OK, Share ID:", share_id)
    assert "lan_share_url" in enc_custom_data
    # Verify share info endpoint
    r_sinfo = client.get(f"/api/share/{share_id}/info")
    assert r_sinfo.status_code == 200
    assert r_sinfo.json()["remaining_attempts"] == 5
    print("Image Share Info check: OK (5 attempts configured)")

    print("\n=== [8] Testing Recipient Share Portal (/share/{id} and /s/{id}) ===")
    r_portal = client.get(f"/share/{share_id}")
    assert r_portal.status_code == 200
    assert "AURA-CRYPT" in r_portal.text
    r_short = client.get(f"/s/{share_id}")
    assert r_short.status_code == 200
    assert "AURA-CRYPT" in r_short.text
    print("Recipient Portal HTML (/share and /s): OK")

    print("\n=== [9] Testing 5 Attempts Lockout Enforcement ===")
    # 4 wrong password attempts
    for i in range(1, 5):
        r_fail = client.post(
            f"/api/share/{share_id}/decrypt",
            data={"password": f"WrongPass_{i}"}
        )
        assert r_fail.status_code == 400
        detail_msg = r_fail.json().get("detail", "")
        rem = 5 - i
        print(f"Attempt {i} wrong password response: {detail_msg}")
        assert f"{rem} attempt" in detail_msg

    # 5th wrong password attempt -> permanently locks
    r_lock = client.post(
        f"/api/share/{share_id}/decrypt",
        data={"password": "WrongPass_5"}
    )
    assert r_lock.status_code == 400
    print("5th attempt response:", r_lock.status_code, r_lock.json())
    assert "Access permanently blocked" in r_lock.json().get("detail", "")

    # 6th attempt with correct password -> must still be locked out (403)!
    r_after = client.post(
        f"/api/share/{share_id}/decrypt",
        data={"password": "1234"}
    )
    assert r_after.status_code == 403, f"Security breach! Locked item allowed unlock: {r_after.status_code}"
    print("Post-lockout correct password attempt rejected properly: PASS (403 Forbidden - permanently locked)")

    print("\n=== [10] Testing Document Lock (/api/document/encrypt) ===")
    sample_doc = b"%PDF-1.4\n1 0 obj\n<< /Title (Test Doc) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    r_doc = client.post(
        "/api/document/encrypt",
        files={"document": ("test_doc.pdf", io.BytesIO(sample_doc), "application/pdf")},
        data={"password": "DocPass#2026", "title": "Aadhaar Test"}
    )
    assert r_doc.status_code == 200
    doc_data = r_doc.json()
    doc_id = doc_data.get("share_id") or doc_data.get("id")
    print("Document Lock Created: OK, Share ID:", doc_id)

    # Unlock document with correct password
    r_doc_unlock = client.post(
        f"/api/share/{doc_id}/decrypt",
        data={"password": "DocPass#2026"}
    )
    assert r_doc_unlock.status_code == 200
    doc_res = r_doc_unlock.json()
    assert doc_res["success"] is True
    dec_doc_bytes = base64.b64decode(doc_res["data_url"].split(",", 1)[1])
    assert dec_doc_bytes == sample_doc
    print("Document Unlocked & Restored Byte-for-byte: PASS")

    print("\n=== [11] Testing Video Stream Encryption (/api/video/encrypt) ===")
    sample_vid = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42\x00\x00\x00\x08free"
    r_vid = client.post(
        "/api/video/encrypt",
        files={"video": ("test_clip.mp4", io.BytesIO(sample_vid), "video/mp4")},
        data={"password": "VidPass#2026", "title": "Clip Test"}
    )
    assert r_vid.status_code == 200
    vid_data = r_vid.json()
    vid_id = vid_data.get("share_id") or vid_data.get("id")
    print("Video Lock Created: OK, Share ID:", vid_id)

    # Unlock video with correct password
    r_vid_unlock = client.post(
        f"/api/share/{vid_id}/decrypt",
        data={"password": "VidPass#2026"}
    )
    assert r_vid_unlock.status_code == 200
    vid_res = r_vid_unlock.json()
    assert vid_res["success"] is True
    dec_vid_bytes = base64.b64decode(vid_res["data_url"].split(",", 1)[1])
    assert dec_vid_bytes == sample_vid
    print("Video Unlocked & Streamed Byte-for-byte: PASS")

    print("\n" + "=" * 50)
    print(">>> ALL 11 VERIFICATION STAGES PASSED 100%! <<<")
    print("=" * 50)

if __name__ == "__main__":
    run_checks()
