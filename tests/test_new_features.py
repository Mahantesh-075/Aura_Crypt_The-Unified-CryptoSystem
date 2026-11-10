import io
import json
import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_document_encryption_and_5_attempts_lockout():
    # 1. Encrypt document
    doc_content = b"%PDF-1.4 confidential aadhaar sample data 123456789"
    files = {"document": ("aadhaar.pdf", doc_content, "application/pdf")}
    data = {"password": "CorrectPassword123!", "title": "Aadhaar Lock Test"}
    
    res = client.post("/api/document/encrypt", files=files, data=data)
    assert res.status_code == 200, res.text
    res_data = res.json()
    assert res_data["success"] is True
    share_id = res_data["share_id"]
    assert res_data["media_type"] == "document"
    
    # 2. Check share info
    info_res = client.get(f"/api/share/{share_id}/info")
    assert info_res.status_code == 200
    info_data = info_res.json()
    assert info_data["media_type"] == "document"
    assert info_data["max_attempts"] == 5
    assert info_data["remaining_attempts"] == 5
    assert info_data["is_locked"] is False
    
    # 3. Test wrong password (Attempt 1)
    bad_res1 = client.post(f"/api/share/{share_id}/decrypt", data={"password": "WrongPassword"})
    assert bad_res1.status_code == 400
    assert "4 attempt" in bad_res1.json()["detail"]
    
    # Check info shows 4 remaining
    info_res = client.get(f"/api/share/{share_id}/info")
    assert info_res.json()["remaining_attempts"] == 4
    
    # Test wrong password 3 more times (Attempts 2, 3, 4)
    for _ in range(3):
        client.post(f"/api/share/{share_id}/decrypt", data={"password": "WrongPassword"})
        
    info_res = client.get(f"/api/share/{share_id}/info")
    assert info_res.json()["remaining_attempts"] == 1
    
    # Attempt 5: Final attempt fails -> Lockout
    bad_res5 = client.post(f"/api/share/{share_id}/decrypt", data={"password": "WrongPassword"})
    assert bad_res5.status_code == 400
    assert "maximum 5 password attempts exceeded" in bad_res5.json()["detail"].lower()
    
    # Now locked! Attempt 6 should return 403 Forbidden
    locked_res = client.post(f"/api/share/{share_id}/decrypt", data={"password": "CorrectPassword123!"})
    assert locked_res.status_code == 403
    assert "lockout" in locked_res.json()["detail"].lower()


def test_video_encryption_and_successful_decryption():
    video_content = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42mockvideo"
    files = {"video": ("sample.mp4", video_content, "video/mp4")}
    data = {"password": "SecretVideoPass#99", "title": "Confidential MP4"}
    
    res = client.post("/api/video/encrypt", files=files, data=data)
    assert res.status_code == 200, res.text
    res_data = res.json()
    assert res_data["success"] is True
    share_id = res_data["share_id"]
    assert res_data["media_type"] == "video"
    
    # Decrypt with correct password
    dec_res = client.post(f"/api/share/{share_id}/decrypt", data={"password": "SecretVideoPass#99"})
    assert dec_res.status_code == 200, dec_res.text
    dec_data = dec_res.json()
    assert dec_data["success"] is True
    assert dec_data["media_type"] == "video"
    assert dec_data["data_url"].startswith("data:video/mp4;base64,")


def test_image_share_with_blur_preview():
    from PIL import Image
    img = Image.new("RGB", (60, 60), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()
    
    files = {"image": ("test.png", img_bytes, "image/png")}
    data = {"password": "PicPassword!", "title": "Blue Square"}
    
    res = client.post("/api/share/create", files=files, data=data)
    assert res.status_code == 200, res.text
    res_data = res.json()
    assert "blur_preview" in res_data
    assert res_data["blur_preview"].startswith("data:image/jpeg;base64,")
    share_id = res_data["share_id"]
    
    info_res = client.get(f"/api/share/{share_id}/info")
    assert info_res.status_code == 200
    info_data = info_res.json()
    assert info_data["blur_preview"].startswith("data:image/jpeg;base64,")
    assert info_data["remaining_attempts"] == 5
    
    # Decrypt
    dec_res = client.post(f"/api/share/{share_id}/decrypt", data={"password": "PicPassword!"})
    assert dec_res.status_code == 200
    assert dec_res.json()["success"] is True
