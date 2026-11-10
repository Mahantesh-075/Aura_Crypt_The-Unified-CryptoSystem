"""
FastAPI Backend Application for Image Encryption and Security Evaluation.

Endpoints:
- POST /api/encrypt: Encrypts image, returns Base64 PNG, key, and real-time security metrics.
- POST /api/decrypt: Validates HMAC tag, restores original lossless image.
- POST /api/metrics: Computes security metrics (Entropy, Correlation, NPCR/UACI, Chi-square).
- POST /api/ablation: Computes Plain vs Shuffle-Only vs Proposed Confusion+Diffusion table.
- GET  /api/health: Service health check.
- Static file mounting: Serves the web frontend at /.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import socket
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image

from backend import crypto_engine, metrics, tunnel

PORT_80_ACTIVE = False
_port80_server_sock = None


def start_port80_forwarder(target_port: int = 8000) -> bool:
    """
    Transparent TCP socket forwarder on standard HTTP Port 80.
    Forwards incoming LAN HTTP connections directly to FastAPI on 127.0.0.1:target_port.
    Omits ':8000' so local links are completely clean (http://10.226.97.149/s/...) with NO port number.
    """
    global PORT_80_ACTIVE, _port80_server_sock
    if PORT_80_ACTIVE:
        return True

    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 80))
        srv.listen(100)
        _port80_server_sock = srv
        PORT_80_ACTIVE = True
    except Exception:
        PORT_80_ACTIVE = False
        return False

    def forward(src: socket.socket, dst: socket.socket):
        try:
            while True:
                buf = src.recv(16384)
                if not buf:
                    break
                dst.sendall(buf)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass

    def accept_loop():
        while PORT_80_ACTIVE and _port80_server_sock:
            try:
                client_sock, _ = _port80_server_sock.accept()
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.connect(("127.0.0.1", target_port))
                t1 = threading.Thread(target=forward, args=(client_sock, target_sock), daemon=True)
                t2 = threading.Thread(target=forward, args=(target_sock, client_sock), daemon=True)
                t1.start()
                t2.start()
            except Exception:
                break

    t = threading.Thread(target=accept_loop, daemon=True, name="port80-forwarder-loop")
    t.start()
    return True


def stop_port80_forwarder():
    global PORT_80_ACTIVE, _port80_server_sock
    PORT_80_ACTIVE = False
    if _port80_server_sock:
        try:
            _port80_server_sock.close()
        except Exception:
            pass
        _port80_server_sock = None


# Auto-start Port 80 forwarder immediately upon import so clean portless LAN links are active right away
try:
    start_port80_forwarder(target_port=8000)
except Exception:
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: Start Cloudflare tunnel and Port 80 forwarder on startup."""
    start_port80_forwarder(target_port=8000)
    tunnel.start_tunnel_in_background(port=8000)
    yield
    stop_port80_forwarder()
    tunnel.stop_tunnel()


app = FastAPI(
    title="Image Encryption API",
    description="Major Project: Digital Image Encryption using ChaCha20 Confusion, Diffusion & HMAC-SHA256",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for development and cross-origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB max image upload limit
MAX_DOC_SIZE = 10 * 1024 * 1024    # 10 MB max document limit (Aadhaar / Doc Lock)
MAX_VIDEO_SIZE = 15 * 1024 * 1024  # 15 MB max video limit

ALLOWED_FORMATS = {"PNG", "JPEG", "JPG", "BMP", "WEBP"}
ALLOWED_DOC_EXTS = {".pdf", ".docx", ".doc", ".pptx", ".ppt", ".txt"}
ALLOWED_VIDEO_EXTS = {".mp4", ".webm", ".mkv", ".mov"}

DOC_MIME_MAP = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".txt": "text/plain",
}

VIDEO_MIME_MAP = {
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".mov": "video/quicktime",
}

# Storage directory for shared encrypted images, documents, and videos
STORAGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "shares")
os.makedirs(STORAGE_DIR, exist_ok=True)


def get_lan_ip() -> str:
    """Detect local area network (LAN) IPv4 address for mobile device access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Using 8.8.8.8 routing check to determine primary local interface IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_lan_base_url(use_domain: bool = False) -> str:
    """
    Return base URL for local LAN / Wi-Fi / Hotspot devices.
    When Port 80 forwarder is active, omits ':8000' completely so the link is clean
    (e.g., http://10.226.97.149) with zero port numbers.
    """
    global PORT_80_ACTIVE
    if not PORT_80_ACTIVE:
        start_port80_forwarder(target_port=8000)
    lan_ip = get_lan_ip()
    port_suffix = "" if PORT_80_ACTIVE else ":8000"
    return f"http://{lan_ip}{port_suffix}"


@app.get("/api/network/info")
async def api_network_info():
    """Return local network LAN IP and dynamic public Cloudflare tunnel URL."""
    global PORT_80_ACTIVE
    if not PORT_80_ACTIVE:
        start_port80_forwarder(target_port=8000)
    lan_ip = get_lan_ip()
    active_tunnel = tunnel.get_tunnel_url()
    lan_base = get_lan_base_url()
    return {
        "status": "online",
        "lan_ip": lan_ip,
        "port": 80 if PORT_80_ACTIVE else 8000,
        "is_port_80": PORT_80_ACTIVE,
        "lan_base_url": lan_base,
        "raw_ip_base_url": lan_base,
        "public_tunnel_url": active_tunnel,
        "is_tunnel_ready": bool(active_tunnel),
        "is_mobile_ready": True,
        "message": "Dual Smart Mode: Clean Public HTTPS (no port) + Clean Port 80 LAN.",
    }


def validate_image_upload(content: bytes) -> Image.Image:
    """Validate uploaded file size, format, and load into Pillow."""
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024 * 1024)} MB.",
        )
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    try:
        img = Image.open(io.BytesIO(content))
        img.load()
        if img.format and img.format.upper() not in ALLOWED_FORMATS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported image format: {img.format}. Supported: PNG, JPEG, BMP, WEBP.",
            )
        return img
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or corrupted image file: {exc}",
        ) from exc


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Image Encryption System",
        "version": "1.0.0",
        "crypto_primitive": "ChaCha20 + HKDF-SHA256 + HMAC-SHA256 + PBKDF2-SHA256",
        "timestamp": time.time(),
    }


@app.post("/api/encrypt")
async def api_encrypt(
    image: UploadFile = File(...),
    custom_key: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
):
    """
    Encrypt an uploaded image.
    Supports either direct 256-bit key or PBKDF2-derived custom password.
    Performs ChaCha20 permutation & diffusion, computes HMAC-SHA256, and calculates real-time metrics.
    """
    contents = await image.read()
    orig_img = validate_image_upload(contents)
    
    clean_pwd = password.strip() if password else None
    clean_key = custom_key.strip() if custom_key else None

    try:
        # 1. Perform encryption
        result = crypto_engine.encrypt_image(orig_img, key_b64=clean_key, password=clean_pwd)
        
        # 2. Serialize encrypted image to PNG bytes with embedded chunk
        png_bytes = crypto_engine.image_to_png_bytes(result.encrypted_image, result.metadata)
        b64_png = base64.b64encode(png_bytes).decode("ascii")
        
        # 3. Compute evaluation metrics
        sec_metrics = metrics.compute_all_metrics(
            plain_image=orig_img,
            encrypted_image=result.encrypted_image,
            key_b64=result.key_b64,
        )
        
        # 4. Generate ablation metrics for report
        ablation = metrics.generate_ablation_comparison(orig_img)

        # 5. Create recipient share entry with 5-attempt security protection
        share_id = secrets.token_urlsafe(9)
        img_path = os.path.join(STORAGE_DIR, f"{share_id}.png")
        with open(img_path, "wb") as f:
            f.write(png_bytes)

        blur_preview = crypto_engine.generate_blur_preview(orig_img)
        meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
        manifest = {
            "share_id": share_id,
            "media_type": "image",
            "title": image.filename or "Encrypted Photo",
            "filename": image.filename or "photo.png",
            "created_at": time.time(),
            "width": orig_img.width,
            "height": orig_img.height,
            "mode": orig_img.mode,
            "file_size": len(png_bytes),
            "is_password_protected": result.is_password_protected,
            "blur_preview": blur_preview,
            "failed_attempts": 0,
            "max_attempts": 5,
            "is_locked": False,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        lan_share_url = f"{get_lan_base_url()}/s/{share_id}"
        active_tunnel = tunnel.get_tunnel_url()
        public_share_url = f"{active_tunnel}/s/{share_id}" if active_tunnel else None

        return {
            "success": True,
            "filename": f"encrypted_{os.path.splitext(image.filename or 'image')[0]}.png",
            "key": result.key_b64,
            "user_password": result.password,
            "is_password_protected": result.is_password_protected,
            "share_id": share_id,
            "share_url": f"/s/{share_id}",
            "lan_share_url": lan_share_url,
            "public_share_url": public_share_url,
            "image_data": f"data:image/png;base64,{b64_png}",
            "execution_time_ms": round(result.time_taken_ms, 2),
            "dimensions": {
                "width": orig_img.width,
                "height": orig_img.height,
                "mode": orig_img.mode,
            },
            "metrics": sec_metrics,
            "ablation": ablation,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(exc)}",
        ) from exc


@app.post("/api/decrypt")
async def api_decrypt(
    image: UploadFile = File(...),
    key: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    fallback_meta: Optional[str] = Form(None),
):
    """
    Decrypt an encrypted PNG image with either key or password.
    Validates HMAC-SHA256 tag before decrypting.
    Returns HTTP 400 if authentication fails.
    """
    contents = await image.read()
    try:
        cipher_img = crypto_engine.bytes_to_image(contents)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read encrypted image: {exc}",
        )

    parsed_fallback = None
    if fallback_meta:
        try:
            parsed_fallback = json.loads(fallback_meta)
        except Exception:
            pass

    clean_key = key.strip() if key else None
    clean_pwd = password.strip() if password else None

    if not clean_key and not clean_pwd:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either a decryption key or password.",
        )

    try:
        decrypted_img, elapsed_ms = crypto_engine.decrypt_image(
            cipher_img,
            key_b64=clean_key,
            password=clean_pwd,
            fallback_meta=parsed_fallback,
        )
        
        # Serialize to lossless PNG
        out_buf = io.BytesIO()
        decrypted_img.save(out_buf, format="PNG")
        dec_bytes = out_buf.getvalue()
        b64_dec = base64.b64encode(dec_bytes).decode("ascii")

        return {
            "success": True,
            "filename": f"decrypted_{os.path.splitext(image.filename or 'image')[0]}.png",
            "image_data": f"data:image/png;base64,{b64_dec}",
            "execution_time_ms": round(elapsed_ms, 2),
            "dimensions": {
                "width": decrypted_img.width,
                "height": decrypted_img.height,
                "mode": decrypted_img.mode,
            },
            "lossless": True,
        }
    except crypto_engine.KeyVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption error: {exc}",
        )


@app.post("/api/share/create")
async def api_share_create(
    image: UploadFile = File(...),
    password: str = Form(...),
    title: Optional[str] = Form(None),
):
    """
    Encrypt an image with custom password and generate a secure shareable recipient link.
    Ciphertext is stored on the server; password and plaintext are NEVER stored.
    Enforces a 5-attempt password verification security lockout.
    """
    contents = await image.read()
    orig_img = validate_image_upload(contents)
    
    clean_password = password.strip()
    if not clean_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be empty.")
        
    try:
        # Encrypt with custom password via PBKDF2 + ChaCha20 + HMAC
        result = crypto_engine.encrypt_image(orig_img, password=clean_password)
        
        # Generate random unique share ID (12 urlsafe chars = 72 bits of entropy)
        share_id = secrets.token_urlsafe(9)
        
        # Save encrypted PNG with embedded chunks to storage
        png_bytes = crypto_engine.image_to_png_bytes(result.encrypted_image, result.metadata)
        img_path = os.path.join(STORAGE_DIR, f"{share_id}.png")
        with open(img_path, "wb") as f:
            f.write(png_bytes)
            
        # Generate glassy/privacy blurred preview for recipient lock screen
        blur_preview = crypto_engine.generate_blur_preview(orig_img)

        # Save non-sensitive metadata manifest (NO password, NO key stored!)
        meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
        manifest = {
            "share_id": share_id,
            "media_type": "image",
            "title": title.strip() if title else (image.filename or "Secret Encrypted Photo"),
            "filename": image.filename or "photo.png",
            "created_at": time.time(),
            "width": orig_img.width,
            "height": orig_img.height,
            "mode": orig_img.mode,
            "file_size": len(png_bytes),
            "is_password_protected": True,
            "blur_preview": blur_preview,
            "failed_attempts": 0,
            "max_attempts": 5,
            "is_locked": False,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
            
        b64_png = base64.b64encode(png_bytes).decode("ascii")
        
        # Calculate real-time security evaluation metrics
        sec_metrics = metrics.compute_all_metrics(
            plain_image=orig_img,
            encrypted_image=result.encrypted_image,
            key_b64=result.key_b64,
        )
        
        lan_ip = get_lan_ip()
        lan_share_url = f"{get_lan_base_url()}/s/{share_id}"
        active_tunnel = tunnel.get_tunnel_url()
        public_share_url = f"{active_tunnel}/s/{share_id}" if active_tunnel else None

        return {
            "success": True,
            "share_id": share_id,
            "share_url": f"/s/{share_id}",
            "lan_ip": lan_ip,
            "lan_share_url": lan_share_url,
            "public_share_url": public_share_url,
            "filename": manifest["filename"],
            "title": manifest["title"],
            "media_type": "image",
            "dimensions": {
                "width": orig_img.width,
                "height": orig_img.height,
                "mode": orig_img.mode,
            },
            "execution_time_ms": round(result.time_taken_ms, 2),
            "cipher_preview": f"data:image/png;base64,{b64_png}",
            "blur_preview": blur_preview,
            "metrics": sec_metrics,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Share creation failed: {exc}",
        ) from exc


@app.post("/api/document/encrypt")
async def api_document_encrypt(
    document: UploadFile = File(...),
    password: str = Form(...),
    title: Optional[str] = Form(None),
):
    """
    Encrypt confidential document (PDF, DOCX, PPT, TXT - max 10MB) with custom password.
    Employs ChaCha20-Poly1305 authenticated encryption and 5-attempts security lockout.
    """
    contents = await document.read()
    if len(contents) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded document is empty.")
    if len(contents) > MAX_DOC_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Document exceeds maximum allowed size of {MAX_DOC_SIZE // (1024 * 1024)} MB.",
        )

    filename = document.filename or "document.pdf"
    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower()
    if ext_lower not in ALLOWED_DOC_EXTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported document format '{ext}'. Supported: PDF, DOCX, PPT, TXT.",
        )

    clean_password = password.strip()
    if not clean_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be empty.")

    payload, elapsed_ms = crypto_engine.encrypt_binary_data(contents, clean_password)
    share_id = secrets.token_urlsafe(9)

    enc_path = os.path.join(STORAGE_DIR, f"{share_id}.enc")
    with open(enc_path, "wb") as f:
        f.write(payload)

    manifest = {
        "share_id": share_id,
        "media_type": "document",
        "title": title.strip() if title else filename,
        "filename": filename,
        "extension": ext_lower,
        "mime_type": DOC_MIME_MAP.get(ext_lower, "application/octet-stream"),
        "created_at": time.time(),
        "file_size": len(payload),
        "orig_size": len(contents),
        "is_password_protected": True,
        "failed_attempts": 0,
        "max_attempts": 5,
        "is_locked": False,
    }
    meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    lan_ip = get_lan_ip()
    lan_share_url = f"{get_lan_base_url()}/s/{share_id}"
    active_tunnel = tunnel.get_tunnel_url()
    public_share_url = f"{active_tunnel}/s/{share_id}" if active_tunnel else None

    return {
        "success": True,
        "share_id": share_id,
        "share_url": f"/s/{share_id}",
        "lan_ip": lan_ip,
        "lan_share_url": lan_share_url,
        "public_share_url": public_share_url,
        "filename": filename,
        "title": manifest["title"],
        "media_type": "document",
        "extension": ext_lower,
        "file_size": len(contents),
        "execution_time_ms": round(elapsed_ms, 2),
    }


@app.post("/api/video/encrypt")
async def api_video_encrypt(
    video: UploadFile = File(...),
    password: str = Form(...),
    title: Optional[str] = Form(None),
):
    """
    Encrypt video file (MP4, WEBM, MKV, MOV - max 15MB) with custom password.
    ChaCha20-Poly1305 authenticated stream encryption with 5-attempts security lockout.
    """
    contents = await video.read()
    if len(contents) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded video file is empty.")
    if len(contents) > MAX_VIDEO_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Video exceeds maximum allowed size of {MAX_VIDEO_SIZE // (1024 * 1024)} MB.",
        )

    filename = video.filename or "video.mp4"
    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower()
    if ext_lower not in ALLOWED_VIDEO_EXTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported video format '{ext}'. Supported: MP4, WEBM, MKV, MOV.",
        )

    clean_password = password.strip()
    if not clean_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be empty.")

    payload, elapsed_ms = crypto_engine.encrypt_binary_data(contents, clean_password)
    share_id = secrets.token_urlsafe(9)

    enc_path = os.path.join(STORAGE_DIR, f"{share_id}.enc")
    with open(enc_path, "wb") as f:
        f.write(payload)

    manifest = {
        "share_id": share_id,
        "media_type": "video",
        "title": title.strip() if title else filename,
        "filename": filename,
        "extension": ext_lower,
        "mime_type": VIDEO_MIME_MAP.get(ext_lower, "video/mp4"),
        "created_at": time.time(),
        "file_size": len(payload),
        "orig_size": len(contents),
        "is_password_protected": True,
        "failed_attempts": 0,
        "max_attempts": 5,
        "is_locked": False,
    }
    meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    lan_ip = get_lan_ip()
    lan_share_url = f"{get_lan_base_url()}/s/{share_id}"
    active_tunnel = tunnel.get_tunnel_url()
    public_share_url = f"{active_tunnel}/s/{share_id}" if active_tunnel else None

    return {
        "success": True,
        "share_id": share_id,
        "share_url": f"/s/{share_id}",
        "lan_ip": lan_ip,
        "lan_share_url": lan_share_url,
        "public_share_url": public_share_url,
        "filename": filename,
        "title": manifest["title"],
        "media_type": "video",
        "extension": ext_lower,
        "file_size": len(contents),
        "execution_time_ms": round(elapsed_ms, 2),
    }


@app.get("/api/share/{share_id}/info")
async def api_share_info(share_id: str):
    """
    Fetch public metadata, attempts counter, and preview for a shared image, document, or video.
    Does NOT contain secret keys or plaintext data.
    """
    meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
    if not os.path.isfile(meta_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted share not found or expired.")
        
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
            
        media_type = manifest.get("media_type", "image")
        failed = manifest.get("failed_attempts", 0)
        max_attempts = manifest.get("max_attempts", 5)
        is_locked = manifest.get("is_locked", False) or (failed >= max_attempts)
        remaining = max(0, max_attempts - failed)

        info = {
            "share_id": share_id,
            "media_type": media_type,
            "title": manifest.get("title", "Encrypted Transmission"),
            "filename": manifest.get("filename", "file"),
            "file_size": manifest.get("file_size", 0),
            "created_at": manifest.get("created_at", time.time()),
            "max_attempts": max_attempts,
            "remaining_attempts": remaining,
            "is_locked": is_locked,
            "is_password_protected": True,
            "extension": manifest.get("extension", ""),
            "mime_type": manifest.get("mime_type", ""),
        }

        if media_type == "image":
            img_path = os.path.join(STORAGE_DIR, f"{share_id}.png")
            if os.path.isfile(img_path):
                with open(img_path, "rb") as f:
                    png_bytes = f.read()
                b64_png = base64.b64encode(png_bytes).decode("ascii")
                info["cipher_preview"] = f"data:image/png;base64,{b64_png}"
            info["blur_preview"] = manifest.get("blur_preview", "")
            info["width"] = manifest.get("width", 0)
            info["height"] = manifest.get("height", 0)
            info["mode"] = manifest.get("mode", "RGB")

        return info
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@app.post("/api/share/{share_id}/decrypt")
async def api_share_decrypt(
    share_id: str,
    password: str = Form(...),
):
    """
    Decrypt a shared image, document, or video on the recipient unlock portal.
    Requires the exact password set by the sender.
    Enforces the 5-attempt security limit with permanent lockout when exceeded.
    """
    meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
    if not os.path.isfile(meta_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted share not found or expired.")

    with open(meta_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    max_attempts = manifest.get("max_attempts", 5)
    failed = manifest.get("failed_attempts", 0)
    if manifest.get("is_locked", False) or failed >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Lockout: Maximum 5 password attempts exceeded. This file has been locked permanently.",
        )

    clean_password = password.strip()
    if not clean_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be empty.")

    media_type = manifest.get("media_type", "image")

    try:
        if media_type == "image":
            img_path = os.path.join(STORAGE_DIR, f"{share_id}.png")
            if not os.path.isfile(img_path):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted image share not found.")

            with open(img_path, "rb") as f:
                png_bytes = f.read()

            cipher_img = crypto_engine.bytes_to_image(png_bytes)
            decrypted_img, elapsed_ms = crypto_engine.decrypt_image(cipher_img, password=clean_password)

            # Serialize to lossless PNG
            out_buf = io.BytesIO()
            decrypted_img.save(out_buf, format="PNG")
            dec_bytes = out_buf.getvalue()
            b64_dec = base64.b64encode(dec_bytes).decode("ascii")

            # Reset failed attempts on success
            manifest["failed_attempts"] = 0
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            return {
                "success": True,
                "media_type": "image",
                "filename": f"unlocked_{manifest.get('filename', 'image.png')}",
                "image_data": f"data:image/png;base64,{b64_dec}",
                "execution_time_ms": round(elapsed_ms, 2),
                "dimensions": {
                    "width": decrypted_img.width,
                    "height": decrypted_img.height,
                    "mode": decrypted_img.mode,
                },
                "lossless": True,
            }
        else:
            # Document or Video
            enc_path = os.path.join(STORAGE_DIR, f"{share_id}.enc")
            if not os.path.isfile(enc_path):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted payload file not found.")

            with open(enc_path, "rb") as f:
                enc_payload = f.read()

            dec_bytes, elapsed_ms = crypto_engine.decrypt_binary_data(enc_payload, password=clean_password)
            mime_type = manifest.get("mime_type", "application/octet-stream")
            b64_data = base64.b64encode(dec_bytes).decode("ascii")

            # Reset failed attempts on success
            manifest["failed_attempts"] = 0
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            return {
                "success": True,
                "media_type": media_type,
                "filename": f"unlocked_{manifest.get('filename', 'file')}",
                "data_url": f"data:{mime_type};base64,{b64_data}",
                "mime_type": mime_type,
                "file_size": len(dec_bytes),
                "execution_time_ms": round(elapsed_ms, 2),
            }

    except crypto_engine.KeyVerificationError as exc:
        manifest["failed_attempts"] = failed + 1
        rem = max(0, max_attempts - manifest["failed_attempts"])
        if rem == 0:
            manifest["is_locked"] = True
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        msg = f"Authentication failed: Incorrect password! {rem} attempt{'s' if rem != 1 else ''} remaining."
        if rem == 0:
            msg = "Security Lockout: Maximum 5 password attempts exceeded. Access permanently blocked."
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption error: {exc}",
        ) from exc


@app.post("/api/metrics")
async def api_metrics(
    plain_image: UploadFile = File(...),
    encrypted_image: UploadFile = File(...),
    key: Optional[str] = Form(None),
):
    """Calculate and return full metrics for arbitrary plain and encrypted image pair."""
    plain_bytes = await plain_image.read()
    cipher_bytes = await encrypted_image.read()

    p_img = validate_image_upload(plain_bytes)
    c_img = validate_image_upload(cipher_bytes)

    sec_metrics = metrics.compute_all_metrics(
        plain_image=p_img,
        encrypted_image=c_img,
        key_b64=key,
    )
    return sec_metrics


# Mount frontend static directory
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
if os.path.isdir(samples_dir):
    app.mount("/samples", StaticFiles(directory=samples_dir), name="samples")

if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file)
        return {"message": "Frontend not found"}

    @app.get("/style.css")
    async def serve_style():
        return FileResponse(os.path.join(frontend_dir, "style.css"), media_type="text/css")

    @app.get("/main.js")
    async def serve_main_js():
        return FileResponse(os.path.join(frontend_dir, "main.js"), media_type="application/javascript")

    @app.get("/s/{share_id}")
    @app.get("/share/{share_id}")
    async def serve_share_page(share_id: str):
        """Serve the dedicated recipient unlock portal."""
        meta_path = os.path.join(STORAGE_DIR, f"{share_id}.json")
        if not os.path.isfile(meta_path):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted share not found or expired.")
        share_file = os.path.join(frontend_dir, "share.html")
        if os.path.isfile(share_file):
            return FileResponse(share_file)
        return FileResponse(os.path.join(frontend_dir, "index.html"))

