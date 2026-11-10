"""
Integration Tests for FastAPI Endpoints.

Verifies:
- /api/health returns 200 OK
- /api/encrypt processes image and returns Base64 PNG + key + metrics
- /api/decrypt with correct key returns decrypted image
- /api/decrypt with wrong key returns 400 Bad Request
"""

import io
from fastapi.testclient import TestClient
from PIL import Image
import numpy as np

from backend.app import app

client = TestClient(app)


def create_test_image_bytes(color=(100, 150, 200), size=(60, 60)) -> bytes:
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_encrypt_and_decrypt_roundtrip():
    img_bytes = create_test_image_bytes()
    
    # 1. Encrypt
    enc_resp = client.post(
        "/api/encrypt",
        files={"image": ("test.png", img_bytes, "image/png")},
    )
    assert enc_resp.status_code == 200
    enc_data = enc_resp.json()
    assert enc_data["success"] is True
    assert "key" in enc_data
    assert "metrics" in enc_data
    assert enc_data["metrics"]["entropy"]["encrypted"]["average"] > 7.9

    key = enc_data["key"]
    # Extract base64 image data
    b64_header, b64_payload = enc_data["image_data"].split(",", 1)
    import base64
    cipher_bytes = base64.b64decode(b64_payload)

    # 2. Decrypt with correct key
    dec_resp = client.post(
        "/api/decrypt",
        files={"image": ("encrypted.png", cipher_bytes, "image/png")},
        data={"key": key},
    )
    assert dec_resp.status_code == 200
    dec_data = dec_resp.json()
    assert dec_data["success"] is True
    assert dec_data["lossless"] is True


def test_api_decrypt_wrong_key():
    img_bytes = create_test_image_bytes()
    enc_resp = client.post(
        "/api/encrypt",
        files={"image": ("test.png", img_bytes, "image/png")},
    )
    assert enc_resp.status_code == 200
    enc_data = enc_resp.json()
    b64_header, b64_payload = enc_data["image_data"].split(",", 1)
    import base64
    cipher_bytes = base64.b64decode(b64_payload)

    # Decrypt with wrong key
    wrong_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    dec_resp = client.post(
        "/api/decrypt",
        files={"image": ("encrypted.png", cipher_bytes, "image/png")},
        data={"key": wrong_key},
    )
    assert dec_resp.status_code == 400
    assert "failed" in dec_resp.json()["detail"].lower() or "invalid" in dec_resp.json()["detail"].lower()


def test_api_share_workflow():
    img_bytes = create_test_image_bytes(color=(220, 110, 50), size=(40, 40))
    pwd = "TransferSecret#2026!"

    # 1. Create share link
    share_resp = client.post(
        "/api/share/create",
        files={"image": ("shared_pic.png", img_bytes, "image/png")},
        data={"password": pwd, "title": "Confidential Research Scan"},
    )
    assert share_resp.status_code == 200
    share_data = share_resp.json()
    assert share_data["success"] is True
    assert "share_id" in share_data
    assert "share_url" in share_data
    assert "cipher_preview" in share_data
    share_id = share_data["share_id"]

    # 2. Get share info
    info_resp = client.get(f"/api/share/{share_id}/info")
    assert info_resp.status_code == 200
    info_data = info_resp.json()
    assert info_data["share_id"] == share_id
    assert info_data["title"] == "Confidential Research Scan"
    assert info_data["is_password_protected"] is True

    # 3. Decrypt with wrong password -> 400
    wrong_resp = client.post(
        f"/api/share/{share_id}/decrypt",
        data={"password": "WrongPasswordX9!"},
    )
    assert wrong_resp.status_code == 400
    assert "failed" in wrong_resp.json()["detail"].lower()

    # 4. Decrypt with correct password -> 200
    correct_resp = client.post(
        f"/api/share/{share_id}/decrypt",
        data={"password": pwd},
    )
    assert correct_resp.status_code == 200
    dec_data = correct_resp.json()
    assert dec_data["success"] is True
    assert "image_data" in dec_data
    assert dec_data["lossless"] is True

