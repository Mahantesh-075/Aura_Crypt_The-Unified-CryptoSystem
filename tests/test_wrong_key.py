"""
Security Tests: Wrong Key & Tamper Resistance.

Verifies:
- 1-bit flipped key is rejected immediately by HMAC verification
- Arbitrary wrong key is rejected
- Altered ciphertext byte is rejected
- Malformed keys are rejected
"""

import base64
import numpy as np
import pytest
from PIL import Image

from backend import crypto_engine


def test_wrong_key_rejected():
    img = Image.new("RGB", (64, 64), color=(120, 200, 50))
    res = crypto_engine.encrypt_image(img)

    wrong_key = crypto_engine.generate_key()
    with pytest.raises(crypto_engine.KeyVerificationError):
        crypto_engine.decrypt_image(res.encrypted_image, wrong_key)


def test_one_bit_flipped_key_rejected():
    img = Image.new("RGB", (50, 50), color=(80, 160, 240))
    res = crypto_engine.encrypt_image(img)

    raw_key = bytearray(crypto_engine.decode_key(res.key_b64))
    # Flip exactly 1 bit in the key
    raw_key[0] ^= 0x01
    flipped_key_b64 = base64.urlsafe_b64encode(bytes(raw_key)).rstrip(b"=").decode("ascii")

    with pytest.raises(crypto_engine.KeyVerificationError):
        crypto_engine.decrypt_image(res.encrypted_image, flipped_key_b64)


def test_tampered_ciphertext_rejected():
    img = Image.new("RGB", (40, 40), color=(10, 20, 30))
    res = crypto_engine.encrypt_image(img)

    # Tamper with 1 pixel of the encrypted image
    cipher_arr = np.array(res.encrypted_image, dtype=np.uint8)
    cipher_arr[5, 5, 0] ^= 0xFF
    tampered_img = Image.fromarray(cipher_arr, mode="RGB")
    tampered_img.info["ImageCryptoMeta"] = res.metadata

    with pytest.raises(crypto_engine.KeyVerificationError):
        crypto_engine.decrypt_image(tampered_img, res.key_b64)


def test_malformed_key():
    img = Image.new("RGB", (20, 20), color=(0, 0, 0))
    res = crypto_engine.encrypt_image(img)

    with pytest.raises(crypto_engine.KeyVerificationError):
        crypto_engine.decrypt_image(res.encrypted_image, "not-a-valid-base64-key")


def test_wrong_password_rejected():
    img = Image.new("RGB", (30, 30), color=(100, 150, 200))
    res = crypto_engine.encrypt_image(img, password="CorrectPassword123!")

    # Attempt with wrong password
    with pytest.raises(crypto_engine.KeyVerificationError):
        crypto_engine.decrypt_image(res.encrypted_image, password="WrongPassword999!")

