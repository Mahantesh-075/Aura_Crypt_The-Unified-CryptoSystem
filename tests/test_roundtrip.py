"""
Roundtrip Lossless Decryption Tests.

Verifies:
- Bit-exact reconstruction (MSE = 0.0, PSNR = inf)
- RGB, RGBA, Grayscale (L) formats
- Various dimensions (1x1, non-square, prime dimensions, standard 512x512)
"""

import io
import numpy as np
import pytest
from PIL import Image

from backend import crypto_engine


@pytest.mark.parametrize("mode,size", [
    ("RGB", (100, 100)),
    ("RGB", (1, 1)),
    ("RGB", (13, 17)),
    ("RGB", (256, 128)),
    ("RGBA", (80, 80)),
    ("L", (90, 90)),
    ("L", (7, 11)),
])
def test_lossless_roundtrip(mode: str, size: tuple[int, int]):
    width, height = size
    if mode == "L":
        arr = np.random.randint(0, 256, (height, width), dtype=np.uint8)
    elif mode == "RGBA":
        arr = np.random.randint(0, 256, (height, width, 4), dtype=np.uint8)
    else:
        arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)

    orig_img = Image.fromarray(arr, mode=mode)

    # Encrypt
    res = crypto_engine.encrypt_image(orig_img)
    assert res.key_b64 is not None
    assert len(res.key_b64) >= 43

    # Serialize to PNG bytes and reload
    png_bytes = crypto_engine.image_to_png_bytes(res.encrypted_image, res.metadata)
    loaded_cipher = crypto_engine.bytes_to_image(png_bytes)

    # Decrypt
    decrypted_img, elapsed = crypto_engine.decrypt_image(loaded_cipher, res.key_b64)

    assert decrypted_img.mode == orig_img.mode
    assert decrypted_img.size == orig_img.size

    dec_arr = np.array(decrypted_img, dtype=np.uint8)
    assert np.array_equal(arr, dec_arr), "Decrypted image must be bit-exact to original!"


def test_custom_key_reproducibility():
    img = Image.new("RGB", (32, 32), color=(45, 90, 180))
    key = crypto_engine.generate_key()

    res1 = crypto_engine.encrypt_image(img, key_b64=key)
    dec1, _ = crypto_engine.decrypt_image(res1.encrypted_image, key)

    assert np.array_equal(np.array(img), np.array(dec1))


def test_password_based_roundtrip():
    arr = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    pwd = "UltraSecretCustomPassword#2026!"

    res = crypto_engine.encrypt_image(img, password=pwd)
    assert res.is_password_protected is True
    assert "salt" in res.metadata and len(res.metadata["salt"]) == 32

    # Serialize to PNG bytes
    png_bytes = crypto_engine.image_to_png_bytes(res.encrypted_image, res.metadata)
    loaded = crypto_engine.bytes_to_image(png_bytes)

    # Decrypt with correct password
    decrypted, _ = crypto_engine.decrypt_image(loaded, password=pwd)
    assert np.array_equal(arr, np.array(decrypted))

