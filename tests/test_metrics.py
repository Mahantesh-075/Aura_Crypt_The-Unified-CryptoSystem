"""
Security Evaluation Metrics Verification Tests.

Verifies:
- Shannon Entropy reaches near 8.0 for encrypted images
- Adjacent pixel correlation is broken (~0.0)
- Histogram passes chi-square uniformity test
- Differential NPCR and UACI meet academic bounds
"""

import numpy as np
import pytest
from PIL import Image

from backend import crypto_engine, metrics


def test_entropy_and_correlation_bounds():
    # Natural-like image with high adjacent correlation
    arr = np.zeros((150, 150, 3), dtype=np.uint8)
    for y in range(150):
        for x in range(150):
            arr[y, x] = [int(y * 1.5), int(x * 1.5), int((x + y) * 0.7)]
    plain_img = Image.fromarray(arr, mode="RGB")

    res = crypto_engine.encrypt_image(plain_img)

    plain_arr = np.array(plain_img)
    cipher_arr = np.array(res.encrypted_image)

    # 1. Plain image should have strong correlation
    plain_corr = metrics.compute_adjacent_correlation(plain_arr)
    assert plain_corr["horizontal"] > 0.90, "Plain image should have high adjacent correlation"

    # 2. Cipher image should have near zero correlation
    cipher_corr = metrics.compute_adjacent_correlation(cipher_arr)
    assert abs(cipher_corr["horizontal"]) < 0.08, "Encrypted image must eliminate spatial correlation"
    assert abs(cipher_corr["vertical"]) < 0.08
    assert abs(cipher_corr["diagonal"]) < 0.08

    # 3. Plain vs Cipher correlation should be near zero
    pv_corr = metrics.compute_plain_cipher_correlation(plain_arr, cipher_arr)
    assert abs(pv_corr) < 0.05

    # 4. Cipher entropy should approach 8.0
    cipher_entropy = metrics.compute_shannon_entropy(cipher_arr)
    assert cipher_entropy["average"] > 7.95, f"Expected entropy > 7.95, got {cipher_entropy['average']}"


def test_histogram_chi_square_uniformity():
    img = Image.new("RGB", (128, 128), color=(20, 150, 200))
    res = crypto_engine.encrypt_image(img)
    cipher_arr = np.array(res.encrypted_image)

    hist_data = metrics.compute_histogram_and_chisquare(cipher_arr)
    assert hist_data["is_uniform"] is True, f"Chi-square {hist_data['chi_square']} failed uniformity test"


def test_differential_attack_metrics():
    # High-texture image
    rng = np.random.default_rng(999)
    arr = rng.integers(0, 256, (64, 64, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    key = crypto_engine.generate_key()

    diff_res = metrics.compute_differential_metrics(img, key)
    # NPCR should be >= 99.0%
    assert diff_res["npcr"] >= 99.0, f"NPCR was {diff_res['npcr']}"
    # UACI should be around 30-36%
    assert 28.0 <= diff_res["uaci"] <= 38.0, f"UACI was {diff_res['uaci']}"
