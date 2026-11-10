"""
Cryptographic Engine for Image Encryption.

Implements Confusion and Diffusion image encryption:
1. Subkey expansion via HKDF-SHA256 from a 256-bit master key.
2. Deterministic pixel permutation via ChaCha20-driven Fisher-Yates (Diffusion).
3. Value substitution via ChaCha20 keystream XOR (Confusion).
4. Authenticated integrity protection via HMAC-SHA256 (Encrypt-then-MAC).
5. Lossless PNG output with embedded metadata in standard PNG chunks.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageFilter, PngImagePlugin


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class KeyVerificationError(CryptoError):
    """Raised when HMAC authentication fails (wrong key or corrupted ciphertext)."""
    pass


class InvalidImageError(CryptoError):
    """Raised when input image data is corrupted or unsupported."""
    pass


PBKDF2_ITERATIONS = 100000


@dataclass
class EncryptionResult:
    """Encrypted image package containing image data, key, and metadata."""
    encrypted_image: Image.Image
    key_b64: str
    metadata: dict
    nonce_hex: str
    tag_hex: str
    time_taken_ms: float
    password: Optional[str] = None
    is_password_protected: bool = False


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit (32-byte) key from a user password using PBKDF2-HMAC-SHA256.
    
    Args:
        password: User-provided passphrase.
        salt: 16-byte cryptographic salt.
        
    Returns:
        32-byte derived master key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_key() -> str:
    """
    Generate a cryptographically secure 256-bit (32 bytes) master key.
    
    Returns:
        Base64URL-encoded key string without padding.
    """
    raw_key = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw_key).rstrip(b'=').decode('ascii')


def decode_key(key_b64: str) -> bytes:
    """
    Decode and validate a Base64URL-encoded 256-bit master key.
    
    Args:
        key_b64: Base64URL-encoded key string.
        
    Returns:
        32-byte master key.
        
    Raises:
        KeyVerificationError: If key length or encoding is invalid.
    """
    try:
        clean_key = key_b64.strip()
        padding = 4 - (len(clean_key) % 4)
        if padding != 4:
            clean_key += '=' * padding
        raw_key = base64.urlsafe_b64decode(clean_key)
        if len(raw_key) != 32:
            raise KeyVerificationError(
                f"Invalid key length: expected 32 bytes (256-bit), got {len(raw_key)} bytes."
            )
        return raw_key
    except Exception as exc:
        if isinstance(exc, KeyVerificationError):
            raise
        raise KeyVerificationError(f"Malformed cryptographic key: {exc}") from exc


def derive_subkeys(master_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Derive cryptographically isolated subkeys using HKDF-SHA256.
    
    Args:
        master_key: 32-byte master key.
        
    Returns:
        Tuple of (k_perm, k_stream, k_mac), each 32 bytes.
    """
    salt = b"ImageCrypto-HKDF-v1-Salt"
    
    def _derive(info: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(master_key)
    
    k_perm = _derive(b"image-encryption-v1-perm")
    k_stream = _derive(b"image-encryption-v1-stream")
    k_mac = _derive(b"image-encryption-v1-mac")
    return k_perm, k_stream, k_mac


def _generate_chacha20_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate an arbitrary length keystream using ChaCha20.
    
    Args:
        key: 32-byte encryption key.
        nonce: 16-byte nonce.
        length: Desired keystream length in bytes.
        
    Returns:
        Pseudorandom byte sequence.
    """
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    # XORing zeros with keystream produces pure keystream output
    return encryptor.update(b"\x00" * length)


def _generate_permutation(n_pixels: int, k_perm: bytes, perm_nonce: bytes) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate a deterministic pixel permutation and its inverse using ChaCha20.
    
    Args:
        n_pixels: Total number of pixels (H * W).
        k_perm: 32-byte permutation subkey.
        perm_nonce: 16-byte nonce for permutation generator.
        
    Returns:
        Tuple of (forward_permutation_indices, inverse_permutation_indices).
    """
    keystream = _generate_chacha20_keystream(k_perm, perm_nonce, n_pixels * 8)
    rand_uint64 = np.frombuffer(keystream, dtype=np.uint64)
    # argsort on 64-bit random values is deterministic, uniform, and vectorized
    perm = np.argsort(rand_uint64, kind="stable")
    
    # Pre-compute inverse permutation for exact decryption
    inv_perm = np.empty_like(perm)
    inv_perm[perm] = np.arange(n_pixels, dtype=perm.dtype)
    return perm, inv_perm


def _compute_hmac(k_mac: bytes, header_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
    """Compute HMAC-SHA256 over header and ciphertext bytes."""
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header_bytes)
    h.update(ciphertext_bytes)
    return h.finalize()


def _build_canonical_header(
    version: int,
    height: int,
    width: int,
    channels: int,
    mode: str,
    stream_nonce: bytes,
    perm_nonce: bytes,
    salt_hex: str = "",
    kdf_type: str = "",
) -> bytes:
    """Construct deterministic canonical header bytes for authentication."""
    header_dict = {
        "v": version,
        "h": height,
        "w": width,
        "c": channels,
        "m": mode,
        "sn": stream_nonce.hex(),
        "pn": perm_nonce.hex(),
    }
    if salt_hex:
        header_dict["s"] = salt_hex
    if kdf_type:
        header_dict["kdf"] = kdf_type
    return json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_image(
    image: Image.Image,
    key_b64: Optional[str] = None,
    password: Optional[str] = None,
) -> EncryptionResult:
    """
    Encrypt an image using ChaCha20 permutation and diffusion.
    Supports both direct 256-bit keys and user-defined passwords (via PBKDF2-HMAC-SHA256).
    
    Args:
        image: PIL Image instance (PNG, JPG, BMP).
        key_b64: Optional existing 256-bit Base64URL key.
        password: Optional user-provided password. If provided, key is derived with PBKDF2.
        
    Returns:
        EncryptionResult with encrypted image, key, metadata, and execution time.
    """
    import time
    start_time = time.perf_counter()
    
    # 1. Normalize image format (RGB, RGBA, or L)
    if image.mode not in ("RGB", "RGBA", "L"):
        # Convert palette/CMYK to standard RGB
        image = image.convert("RGB")
    
    mode = image.mode
    width, height = image.size
    n_pixels = width * height
    
    img_array = np.array(image, dtype=np.uint8)
    if mode == "L":
        channels = 1
        flat_pixels = img_array.reshape(n_pixels, 1)
    else:
        channels = img_array.shape[2]
        flat_pixels = img_array.reshape(n_pixels, channels)
        
    total_bytes = n_pixels * channels
    
    # 2. Key management & subkey derivation
    salt_hex = ""
    kdf_type = ""
    is_pwd = False

    if password:
        is_pwd = True
        salt = os.urandom(16)
        salt_hex = salt.hex()
        kdf_type = "pbkdf2-sha256"
        master_key = derive_key_from_password(password, salt)
        key_b64 = base64.urlsafe_b64encode(master_key).rstrip(b"=").decode("ascii")
    elif key_b64:
        try:
            master_key = decode_key(key_b64)
        except KeyVerificationError:
            # key_b64 is a custom user passphrase/password (e.g., "1234")
            password = key_b64
            is_pwd = True
            salt = os.urandom(16)
            salt_hex = salt.hex()
            kdf_type = "pbkdf2-sha256"
            master_key = derive_key_from_password(password, salt)
            key_b64 = base64.urlsafe_b64encode(master_key).rstrip(b"=").decode("ascii")
    else:
        key_b64 = generate_key()
        master_key = decode_key(key_b64)

    k_perm, k_stream, k_mac = derive_subkeys(master_key)
    
    # 3. Fresh nonces for this encryption operation
    perm_nonce = os.urandom(16)
    stream_nonce = os.urandom(16)
    
    # 4. Spatial Permutation (Diffusion of position)
    perm, _ = _generate_permutation(n_pixels, k_perm, perm_nonce)
    permuted_pixels = flat_pixels[perm]
    
    # 5. Keystream Substitution (Confusion of value)
    stream_keystream = _generate_chacha20_keystream(k_stream, stream_nonce, total_bytes)
    stream_array = np.frombuffer(stream_keystream, dtype=np.uint8).reshape(permuted_pixels.shape)
    cipher_pixels = np.bitwise_xor(permuted_pixels, stream_array)
    
    # 6. Authenticated integrity tag (HMAC-SHA256)
    header_bytes = _build_canonical_header(
        version=1,
        height=height,
        width=width,
        channels=channels,
        mode=mode,
        stream_nonce=stream_nonce,
        perm_nonce=perm_nonce,
        salt_hex=salt_hex,
        kdf_type=kdf_type,
    )
    ciphertext_bytes = cipher_pixels.tobytes()
    tag = _compute_hmac(k_mac, header_bytes, ciphertext_bytes)
    
    # 7. Reshape into image array
    if mode == "L":
        cipher_img_array = cipher_pixels.reshape(height, width)
    else:
        cipher_img_array = cipher_pixels.reshape(height, width, channels)
        
    encrypted_image = Image.fromarray(cipher_img_array, mode=mode)
    
    # 8. Embed metadata in PNG tEXt chunk
    meta_dict = {
        "version": 1,
        "height": height,
        "width": width,
        "channels": channels,
        "mode": mode,
        "stream_nonce": stream_nonce.hex(),
        "perm_nonce": perm_nonce.hex(),
        "tag": tag.hex(),
        "salt": salt_hex,
        "kdf": kdf_type,
    }
    
    png_info = PngImagePlugin.PngInfo()
    png_info.add_text("ImageCryptoMeta", json.dumps(meta_dict))
    encrypted_image.info["pnginfo"] = png_info
    encrypted_image.info["ImageCryptoMeta"] = meta_dict
    
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    
    return EncryptionResult(
        encrypted_image=encrypted_image,
        key_b64=key_b64,
        metadata=meta_dict,
        nonce_hex=stream_nonce.hex(),
        tag_hex=tag.hex(),
        time_taken_ms=elapsed_ms,
        password=password,
        is_password_protected=is_pwd,
    )


def extract_metadata(image: Image.Image, fallback_meta: Optional[dict] = None) -> dict:
    """
    Extract cryptographic metadata from an encrypted PNG image.
    
    Args:
        image: Loaded PIL Image.
        fallback_meta: Optional fallback dictionary if PNG chunk was stripped.
        
    Returns:
        Parsed metadata dictionary.
        
    Raises:
        InvalidImageError: If metadata is absent or unparseable.
    """
    if "ImageCryptoMeta" in image.info:
        raw_meta = image.info["ImageCryptoMeta"]
        if isinstance(raw_meta, dict):
            return raw_meta
        try:
            return json.loads(raw_meta)
        except Exception:
            pass
            
    if fallback_meta:
        return fallback_meta
        
    raise InvalidImageError(
        "No cryptographic header found in image. "
        "Make sure this image was encrypted with this tool and saved as a lossless PNG."
    )


def decrypt_image(
    image: Image.Image,
    key_b64: Optional[str] = None,
    password: Optional[str] = None,
    fallback_meta: Optional[dict] = None,
) -> Tuple[Image.Image, float]:
    """
    Decrypt an encrypted image with the provided master key or password.
    
    Args:
        image: Encrypted PIL Image.
        key_b64: Optional master key in Base64URL format.
        password: Optional user-provided password.
        fallback_meta: Optional metadata dict if PNG header chunk was lost.
        
    Returns:
        Tuple of (decrypted_image, elapsed_ms).
        
    Raises:
        KeyVerificationError: If HMAC tag validation fails (wrong key or tampering).
        InvalidImageError: If image or metadata format is invalid.
    """
    import time
    start_time = time.perf_counter()
    
    # 1. Retrieve metadata
    meta = extract_metadata(image, fallback_meta)
    
    version = meta.get("version", 1)
    height = meta["height"]
    width = meta["width"]
    channels = meta["channels"]
    mode = meta["mode"]
    stream_nonce = bytes.fromhex(meta["stream_nonce"])
    perm_nonce = bytes.fromhex(meta["perm_nonce"])
    stored_tag = bytes.fromhex(meta["tag"])
    salt_hex = meta.get("salt", "")
    kdf_type = meta.get("kdf", "")
    
    # 2. Derive cryptographic subkeys
    if password:
        if not salt_hex:
            raise KeyVerificationError(
                "This image was encrypted with a direct cryptographic key, not a custom password."
            )
        salt = bytes.fromhex(salt_hex)
        master_key = derive_key_from_password(password, salt)
    elif key_b64:
        try:
            master_key = decode_key(key_b64)
        except KeyVerificationError:
            if salt_hex:
                # User likely entered their custom password in the key field
                master_key = derive_key_from_password(key_b64, bytes.fromhex(salt_hex))
            else:
                raise
    else:
        raise KeyVerificationError("Decryption failed: Please provide either a decryption key or password.")

    k_perm, k_stream, k_mac = derive_subkeys(master_key)
    
    # 3. Extract ciphertext bytes from image array
    cipher_array = np.array(image, dtype=np.uint8)
    n_pixels = width * height
    expected_size = n_pixels * (1 if mode == "L" else channels)
    
    if cipher_array.size != expected_size:
        raise InvalidImageError(
            f"Image dimensions in metadata ({width}x{height}, {channels} channels, expected {expected_size} bytes) "
            f"do not match actual image byte size ({cipher_array.size} bytes). Image or header has been corrupted."
        )

    if mode == "L":
        cipher_flat = cipher_array.reshape(n_pixels, 1)
    else:
        cipher_flat = cipher_array.reshape(n_pixels, channels)
        
    ciphertext_bytes = cipher_flat.tobytes()
    
    # 4. Verify HMAC-SHA256 Authenticated Tag BEFORE processing (Encrypt-then-MAC)
    header_bytes = _build_canonical_header(
        version=version,
        height=height,
        width=width,
        channels=channels,
        mode=mode,
        stream_nonce=stream_nonce,
        perm_nonce=perm_nonce,
        salt_hex=salt_hex,
        kdf_type=kdf_type,
    )
    
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header_bytes)
    h.update(ciphertext_bytes)
    try:
        h.verify(stored_tag)
    except InvalidSignature as exc:
        raise KeyVerificationError(
            "Authentication failed! The password or key is incorrect, or the encrypted image has been tampered with."
        ) from exc
        
    # 5. Keystream XOR Inverse (Substitution undo)
    total_bytes = n_pixels * channels
    stream_keystream = _generate_chacha20_keystream(k_stream, stream_nonce, total_bytes)
    stream_array = np.frombuffer(stream_keystream, dtype=np.uint8).reshape(cipher_flat.shape)
    permuted_pixels = np.bitwise_xor(cipher_flat, stream_array)
    
    # 6. Inverse Permutation (Position undo)
    _, inv_perm = _generate_permutation(n_pixels, k_perm, perm_nonce)
    original_flat = permuted_pixels[inv_perm]
    
    # 7. Reshape to original dimensions
    if mode == "L":
        orig_img_array = original_flat.reshape(height, width)
    else:
        orig_img_array = original_flat.reshape(height, width, channels)
        
    decrypted_image = Image.fromarray(orig_img_array, mode=mode)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    
    return decrypted_image, elapsed_ms


def image_to_png_bytes(image: Image.Image, metadata: Optional[dict] = None) -> bytes:
    """Serialize a PIL Image to PNG bytes, preserving cryptographic metadata chunk."""
    buffer = io.BytesIO()
    png_info = PngImagePlugin.PngInfo()
    if metadata:
        png_info.add_text("ImageCryptoMeta", json.dumps(metadata))
    image.save(buffer, format="PNG", pnginfo=png_info)
    return buffer.getvalue()


def bytes_to_image(image_bytes: bytes) -> Image.Image:
    """Load a PIL Image from byte sequence."""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()  # Ensure image data is loaded into memory
        return img
    except Exception as exc:
        raise InvalidImageError(f"Could not decode image from bytes: {exc}") from exc


def generate_blur_preview(image: Image.Image) -> str:
    """
    Generate a lightweight, privacy-preserving blurred preview (data URL)
    for recipient lock screen display before password authentication.
    """
    try:
        preview = image.copy()
        if preview.mode in ("RGBA", "LA", "P"):
            preview = preview.convert("RGB")
        # Resize down to max 320px for fast loading
        preview.thumbnail((320, 320), Image.Resampling.LANCZOS)
        # Apply heavy Gaussian blur for privacy
        blurred = preview.filter(ImageFilter.GaussianBlur(radius=22))
        buf = io.BytesIO()
        blurred.save(buf, format="JPEG", quality=60)
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/jpeg;base64,{b64}"
    except Exception:
        return ""


def encrypt_binary_data(data: bytes, password: str) -> Tuple[bytes, float]:
    """
    Encrypt document (PDF, DOCX, PPT, TXT) or video (MP4, WEBM, MKV) files
    using ChaCha20-Poly1305 authenticated encryption and PBKDF2-HMAC-SHA256.
    
    Payload layout:
        [16B Salt] + [12B Nonce] + [Ciphertext + 16B Poly1305 MAC Tag]
    """
    start_time = time.perf_counter()
    clean_password = password.strip()
    if not clean_password:
        raise CryptoError("Encryption password cannot be empty.")
        
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    master_key = derive_key_from_password(clean_password, salt)
    
    chacha = ChaCha20Poly1305(master_key)
    ciphertext = chacha.encrypt(nonce, data, None)
    
    payload = salt + nonce + ciphertext
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return payload, elapsed_ms


def decrypt_binary_data(payload: bytes, password: str) -> Tuple[bytes, float]:
    """
    Decrypt authenticated binary payload using ChaCha20-Poly1305.
    Throws KeyVerificationError on wrong password or ciphertext corruption.
    """
    start_time = time.perf_counter()
    clean_password = password.strip()
    if not clean_password:
        raise CryptoError("Decryption password cannot be empty.")
        
    if len(payload) < (16 + 12 + 16):
        raise KeyVerificationError("Encrypted payload is corrupted or truncated.")
        
    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext = payload[28:]
    
    master_key = derive_key_from_password(clean_password, salt)
    chacha = ChaCha20Poly1305(master_key)
    
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise KeyVerificationError("Authentication failed! The password is incorrect.") from exc
        
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return plaintext, elapsed_ms

