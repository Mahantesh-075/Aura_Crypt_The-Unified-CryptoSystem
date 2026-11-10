# PRD: Image Encryption Using Cryptographic Techniques

**Team:** Ramanagouda, Shobhith Sundar, Sunil Jante | **Guide:** Prof. Anand HD | **Dept:** ECE, Dr. AIT | **Year:** 2026-27

## 1. Overview

A web app where a user uploads an image, the system generates a secret key, and returns an encrypted image whose pixels are randomly shuffled and value-scrambled so it looks like noise. Uploading the encrypted image with the correct key restores the original exactly. A wrong key gives an error or garbage.

## 2. Goals and Non-Goals

**Goals**

- G1: Key generated automatically on encryption.
- G2: Encrypted image is visually unrecognizable.
- G3: Correct key gives a bit-exact original (lossless).
- G4: Wrong key never reveals the image.
- G5: Fast (under 3 s for a 1080p image) and measurable (security metrics dashboard).

**Non-goals (v1):** video encryption, user accounts, cloud storage, JPEG-compression resistance, optical/quantum methods.

## 3. Users and Use Cases

Students/individuals sharing private images; medical or confidential image senders (demo); evaluators who want to see metrics.

## 4. User Flow

1. **Encrypt:** Upload image, click Encrypt, see encrypted preview, download `encrypted.png`, copy/download the key.
2. **Decrypt:** Upload `encrypted.png`, paste the key, click Decrypt, see the original and download it.
3. **Wrong key:** "Key verification failed" shown, no image output.

## 5. Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| F1 | Upload PNG/JPG/BMP (max 10 MB), validate type and size | P0 |
| F2 | Generate a 256-bit random key (`secrets`), shown as Base64URL, with copy/download buttons | P0 |
| F3 | Pixel permutation driven by the key | P0 |
| F4 | Value diffusion (XOR with key-derived keystream) | P0 |
| F5 | Output encrypted image as lossless PNG | P0 |
| F6 | Decrypt with key restoring the exact original | P0 |
| F7 | Integrity/wrong-key detection via HMAC-SHA256 tag | P0 |
| F8 | Side-by-side preview: original / encrypted / decrypted | P1 |
| F9 | Metrics panel: entropy, histogram, correlation, NPCR, UACI, MSE, PSNR | P1 |
| F10 | Encrypt and decrypt time display | P2 |
| F11 | Optional password-derived key (Argon2/PBKDF2) | P2 |
| F12 | Optional carrier-image mode (from the IIT Guwahati paper) | P3 |

## 6. Algorithm (core design)

**Why not shuffle only?** A pure pixel shuffle keeps the histogram identical (same colors, just rearranged) and is weak against statistical and known-plaintext attacks. Both papers stress confusion + diffusion. So we do both.

**Encrypt(image, key):**

1. Load image, convert to a NumPy array (H x W x C, uint8). Save H, W, C.
2. `key = secrets.token_bytes(32)`.
3. Derive subkeys with HKDF-SHA256: `k_perm`, `k_stream`, `k_mac`.
4. **Permutation (diffusion of position):** flatten to N = H\*W pixels (all channels move together). Generate a permutation of 0..N-1 using Fisher-Yates driven by a ChaCha20 keystream from `k_perm` (deterministic and portable; avoid relying on NumPy's RNG across versions).
5. **Substitution (confusion of value):** generate H*W*C bytes of ChaCha20 keystream from `k_stream` (unique nonce stored in header) and XOR with the permuted pixel bytes.
6. Compute `tag = HMAC-SHA256(k_mac, header || ciphertext_bytes)`.
7. Save PNG; store header (version, H, W, C, nonce, tag) in a PNG text chunk, or a small `.meta` file as fallback.

**Decrypt(png, key):** derive the same subkeys, verify HMAC first (reject on failure), XOR keystream, apply the inverse permutation, rebuild image.

**Rules:** always lossless output (PNG); never re-save as JPG; key is never stored on the server; each encryption uses a fresh random key and nonce.

## 7. Architecture

```
Browser (HTML/JS or React)
   | upload / key / download   (HTTPS)
FastAPI backend
   |- /api/encrypt   -> crypto_engine.encrypt()
   |- /api/decrypt   -> crypto_engine.decrypt()
   |- /api/metrics   -> metrics.compute()
   |- crypto_engine  (Pillow, NumPy, cryptography)
   '- temp storage (auto-delete after response, no persistence)
```

Option for simplicity: single Flask app with Jinja templates. Option for privacy: implement the same algorithm in browser JavaScript (Web Crypto) so images never leave the device.

## 8. API Spec

- `POST /api/encrypt` (multipart: `image`) returns `{ encrypted_image (PNG/base64), key, metrics }`
- `POST /api/decrypt` (multipart: `image`, form: `key`) returns the decrypted PNG, or `400 {error:"Key verification failed"}`
- `GET /api/health`

## 9. Tech Stack

| Layer | Choice |
| --- | --- |
| Language | Python 3.11+ |
| Backend | FastAPI + Uvicorn (or Flask) |
| Image handling | Pillow (optionally OpenCV) |
| Math | NumPy |
| Crypto | `cryptography` (ChaCha20, HKDF, HMAC); `hashlib` for SHA-256 |
| Metrics plots | Matplotlib or Chart.js |
| Frontend | HTML/CSS/JS (or React + Vite) |
| Testing | pytest |
| Version control | Git + GitHub |
| Transport | HTTPS/TLS (deployment) |

## 10. Folder Structure

```
image-encryption/
  backend/
    app.py
    crypto_engine.py
    metrics.py
    requirements.txt
  frontend/
    index.html  style.css  main.js
  tests/
    test_roundtrip.py  test_wrong_key.py  test_metrics.py
  samples/
  docs/ (PRD, report, screenshots)
  README.md
```

## 11. Non-Functional Requirements

- Performance: 1080p encrypt/decrypt under 3 s.
- Security: key never logged or stored; HMAC verified before decrypting; constant-time tag comparison; file type validation; rate limiting; no raw EXIF leakage in output.
- Reliability: decrypted image hash equals original hash for 100% of test images.
- Usability: works on desktop and mobile browsers; clear error messages.

## 12. Evaluation Metrics (from Alghamdi & Munir, 2024)

| Metric | Target for good encryption |
| --- | --- |
| Shannon entropy | close to 8 |
| Adjacent pixel correlation (H/V/D) | close to 0 |
| Plain vs cipher correlation | close to 0 |
| Histogram | near-uniform (chi-square below 293.24) |
| NPCR | at least 99.6094% |
| UACI | about 33.4635% |
| MSE / PSNR | high MSE / low PSNR vs original |
| Key space | 2^256 (above 2^100 requirement) |
| Key sensitivity | 1-bit key change gives a completely different result, decryption fails |
| Decryption | exact match (MSE = 0) |

Include a comparison table: shuffle-only vs shuffle + XOR (shows why diffusion is needed).

## 13. Test Plan

1. Round-trip on PNG, JPG, grayscale, RGBA, tiny (1x1) and large images.
2. Wrong key (1 bit flipped) rejected.
3. Tampered ciphertext rejected (HMAC).
4. Differential test: change 1 pixel in the plaintext, compute NPCR/UACI.
5. Metrics thresholds above.
6. Performance benchmarks at 256/512/1080p/4K.
7. Upload abuse: non-image file, oversize file.

## 14. Milestones (suggested 6 weeks)

| Week | Deliverable |
| --- | --- |
| 1 | Setup, repo, literature review, finalize algorithm |
| 2 | `crypto_engine.py` with unit tests (round-trip working) |
| 3 | Backend APIs + HMAC + validation |
| 4 | Frontend: upload/encrypt/decrypt/preview/download |
| 5 | Metrics module and dashboard, comparison table |
| 6 | Testing, documentation, report, PPT, demo video |

## 15. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Shuffle-only is statistically weak | Add XOR diffusion (F4) |
| JPEG recompression destroys data | Force PNG output; warn user |
| User loses key | Image is unrecoverable by design; warn clearly, offer key download |
| RNG differences across library versions | Use ChaCha20-based permutation |
| Large image memory use | Size limit, vectorized NumPy |
| Key shown over insecure HTTP | Enforce HTTPS in deployment |

## 16. Future Scope

Password-based keys, RSA/ECC key exchange for sharing keys, chaotic-map (logistic/Arnold) key sources, carrier-image frequency-domain mode (Prasanna et al.), DNA coding, batch/video encryption, mobile app.

## 17. Antigravity IDE Build Prompts

Paste this PRD into the project root as `PRD.md`, then give the agent tasks in order:

1. "Read PRD.md. Scaffold the folder structure in section 10 and `requirements.txt`."
2. "Implement `crypto_engine.py` per section 6 with encrypt/decrypt functions and docstrings."
3. "Write pytest tests per section 13 items 1-3 and run them until they pass."
4. "Build FastAPI endpoints from section 8 with validation and temp-file cleanup."
5. "Build the frontend for the flow in section 4."
6. "Implement `metrics.py` for section 12 and show results in the UI."
7. "Write README with setup and demo steps." Review each step's output and run the tests yourself before moving on.