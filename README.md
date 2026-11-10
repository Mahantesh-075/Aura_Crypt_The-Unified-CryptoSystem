# AURA-CRYPT: Digital Image Encryption Using Cryptographic Techniques

Author: MAHANTESH BASAVARAJ HAVELI

---
<img width="1917" height="1018" alt="Screenshot 2026-11-10 150137" src="https://github.com/user-attachments/assets/4faff14b-e746-423a-99ad-f5249beb5b5c" />


## 1. Overview & Problem Statement

In multimedia security, digital images exhibit high spatial correlation ($\rho \approx 0.99$) and pixel redundancy. Standard block ciphers applied naively in Electronic Codebook (ECB) mode fail because identical plaintext blocks produce identical ciphertext blocks, leaving visual silhouettes completely exposed.

Conversely, naive pixel-shuffling (permutation-only) schemes merely rearrange pixel positions. Because pixel values remain unmodified, the color frequency histogram of the shuffled image is identical to that of the plain image, rendering it vulnerable to histogram analysis and known-plaintext attacks.

**AURA-CRYPT** implements Claude Shannon's dual principles of **Confusion and Diffusion**:
1. **Diffusion of Position (Spatial Shuffling):** A deterministic, portable Fisher-Yates permutation driven by a 64-bit integer keystream derived from ChaCha20 with subkey $K_{\text{perm}}$.
2. **Confusion of Value (Keystream Substitution):** Pixel value scrambling via a vectorized bitwise XOR with a fresh ChaCha20 keystream using subkey $K_{\text{stream}}$ and a 16-byte cryptographically random nonce.
3. **Authenticated Integrity (Encrypt-then-MAC):** An HMAC-SHA256 signature generated over canonical header bytes and ciphertext bytes using $K_{\text{mac}}$. The tag is validated before decryption; any wrong key or corrupted byte triggers immediate rejection without decrypting garbage.
4. **Format-Preserving Lossless PNG Storage:** Cryptographic metadata is stored in standard PNG auxiliary text chunks (`tEXt` chunk with key `ImageCryptoMeta`). The encrypted image remains a viewable, shareable `.png` file looking like pure static white noise.

---

## 2. Cryptographic Architecture

```
                         +--------------------------+
                         |  Original Image (Plain)  |
                         +------------+-------------+
                                      |
                     [ 256-bit Random Master Key ]
                                      |
                           +----------v----------+
                           |     HKDF-SHA256     |
                           +----------+----------+
                                      |
            +-------------------------+-------------------------+
            |                         |                         |
       (k_perm)                   (k_stream)                 (k_mac)
            |                         |                         |
            v                         v                         |
  +--------------------+    +--------------------+              |
  |  ChaCha20-driven   |    | ChaCha20 Keystream |              |
  | Fisher-Yates Perm  |--->|    XOR Diffusion   |              |
  | (Spatial Shuffling)|    | (Value Confusion)  |              |
  +--------------------+    +---------+----------+              |
                                      |                         |
                                      +------------+------------+
                                                   |
                                                   v
                                        +---------------------+
                                        | HMAC-SHA256 Tag Gen |
                                        +----------+----------+
                                                   |
                                                   v
                                        +---------------------+
                                        | Lossless PNG Output |
                                        | (tEXt Chunk Header) |
                                        +---------------------+
```

---

## 3. Project File Structure

```
Image_Encryption/
├── backend/
│   ├── __init__.py           # Package marker
│   ├── app.py                # FastAPI REST endpoints & static file server
│   ├── crypto_engine.py      # HKDF, ChaCha20 Permutation, Keystream XOR, HMAC-SHA256
│   └── metrics.py            # Shannon Entropy, Correlation, NPCR/UACI, Chi-Square
├── frontend/
│   ├── index.html            # Semantic HTML5 dark glassmorphic dashboard
│   ├── style.css             # Vanilla CSS design system with micro-animations
│   └── main.js               # Reactive client controller & live canvas histograms
├── tests/
│   ├── test_roundtrip.py     # Bit-exact lossless roundtrip across RGB/RGBA/Grayscale
│   ├── test_wrong_key.py     # 1-bit key sensitivity & HMAC tamper rejection tests
│   ├── test_metrics.py       # Entropy & correlation mathematical bounds tests
│   └── test_api.py           # FastAPI integration test suite
├── samples/                  # Built-in benchmark presets (Gradient, Medical Scan, Geometric)
├── pytest.ini                # Pytest pythonpath configuration
├── requirements.txt          # Pinned Python package dependencies
└── README.md                 # System manual & evaluation documentation
```

---

## 4. Security Evaluation Metrics (Alghamdi & Munir, 2024 Standards)

| Metric | Target Standard | Plaintext Image | Proposed AURA-CRYPT | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Shannon Entropy** | $\approx 8.000$ bits/byte | $6.88 - 7.15$ | **$7.999$** | **Optimal Randomness** |
| **Adjacent Correlation ($H$)** | $\approx 0.000$ | $0.95 - 0.99$ | **$-0.003$** | **Spatial Redundancy Broken** |
| **Adjacent Correlation ($V$)** | $\approx 0.000$ | $0.94 - 0.98$ | **$+0.001$** | **Spatial Redundancy Broken** |
| **Adjacent Correlation ($D$)** | $\approx 0.000$ | $0.93 - 0.97$ | **$+0.002$** | **Spatial Redundancy Broken** |
| **Plain vs. Cipher Correlation** | $\approx 0.000$ | $1.000$ | **$0.0006$** | **Orthogonal Independence** |
| **Histogram $\chi^2$ Test** | $< 293.25$ ($\alpha=0.05$) | $> 50,000$ (Non-uniform) | **$241.6$** | **Passed (Flat Uniform Distribution)** |
| **NPCR (Differential)** | $\ge 99.6094\%$ | N/A | **$99.6105\%$** | **Passed** |
| **UACI (Differential)** | $\approx 33.4635\%$ | N/A | **$33.4680\%$** | **Passed** |
| **Decrypted Fidelity (MSE)** | $0.0000$ | N/A | **$0.0000$** | **Bit-Exact Lossless** |
| **Decrypted Fidelity (PSNR)**| $\infty\text{ dB}$ | N/A | **$\infty\text{ dB}$** | **Bit-Exact Lossless** |
| **Key Space** | $> 2^{100}$ | N/A | **$2^{256}$** | **Immune to Brute-Force** |

---

## 5. Ablation Study: Why Shuffling Alone Fails

| Parameter | Plain Image | Shuffle-Only (Permutation) | Proposed (Shuffle + ChaCha20 Diffusion) |
| :--- | :--- | :--- | :--- |
| **Shannon Entropy** | $6.88$ | $6.88$ *(Unchanged)* | **$7.999$** |
| **Adjacent Correlation** | $0.98$ | $0.08$ | **$0.001$** |
| **Histogram $\chi^2$** | $>50,000$ | $>50,000$ *(Identical to Plain)* | **$< 250.0$** *(Uniform)* |
| **Visual Appearance** | Identical | Scrambled silhouettes | Pure RGB static noise |

---

---

## 6. How to Run the Application

You can interact with AURA-CRYPT through three flexible interfaces:

### Option A: Web Application with Mobile-Ready Share Links (Cross-Device Access)

Start the local web server bound to all network interfaces (`0.0.0.0`):
```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```
Open **http://127.0.0.1:8000/** (or your local IP `http://10.226.97.149:8000/`) in your browser:
1. **Upload any photo** (PNG, JPG, BMP, WEBP).
2. Choose **"🔗 Shareable Password Link"** and set your custom password.
3. Click **"⚡ Encrypt & Generate Share Link"**.
4. The system encrypts the image using PBKDF2-HMAC-SHA256 (100k rounds) + ChaCha20 + HMAC-SHA256 and creates a unique recipient link.
5. **Mobile Phone & Cross-Device Sharing**:
   - **📱 Local Wi-Fi / Hotspot**: `http://10.226.97.149:8000/share/<id>`  
     *(Works on any mobile phone or tablet connected to the same Wi-Fi or laptop mobile hotspot)*
   - **🌐 Public Worldwide Link**: `https://6e1a9e5eceeb25.lhr.life/share/<id>`  
     *(Works from anywhere in the world on mobile cellular data 4G/5G or remote Wi-Fi)*
   - **📷 Instant QR Code Scan**: Point your mobile phone camera at the screen to open the recipient portal instantly without typing long URLs.
   - **💬 Direct WhatsApp Share**: Click the WhatsApp button to share the link directly to your contact.
6. **Recipient Experience on Mobile**:
   - When opened on a mobile phone (Chrome/Safari), the recipient sees the encrypted ciphertext noise preview.
   - If they enter the **wrong password**: access is denied, the phone shakes, and the ciphertext remains locked.
   - If they enter the **correct password**: the photo unlocks cleanly with lossless bit-exact recovery (MSE = 0.0000, PSNR = $\infty$ dB), along with an instant download button.

---

### Option B: Interactive Desktop GUI (Tkinter)

Launch the desktop graphical application:
```powershell
& ".\.venv\Scripts\python.exe" gui_app.py
```
- **Encrypt Studio**: Encrypt images with direct 256-bit keys or custom passphrases.
- **Security Fix**: Decryption key is **not** auto-populated when moving to Decrypt Studio.
- **Testing Helpers**: Click **"🎲 Generate Random Key"** in Decrypt Studio to test and verify HMAC rejection of incorrect keys, or click **"📋 Paste Key"** to paste your clipboard key.

---

### Option C: Automated Command-Line Runner (CLI)

Run full encryption, decryption, and academic security ablation audits directly from the terminal:
```powershell
# Run the automated benchmark demonstration:
& ".\.venv\Scripts\python.exe" run_demo.py

# Or encrypt your own image:
& ".\.venv\Scripts\python.exe" run_demo.py encrypt path/to/image.png

# Decrypt an image with a key:
& ".\.venv\Scripts\python.exe" run_demo.py decrypt path/to/image_encrypted.png <YOUR_KEY>

# Generate an academic ablation audit table:
& ".\.venv\Scripts\python.exe" run_demo.py audit path/to/image.png
```

---

## 7. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health status and cryptographic engine information |
| `GET` | `/api/network/info` | Returns local LAN IP and public tunnel URLs for mobile device sharing |
| `POST` | `/api/encrypt` | Encrypts uploaded image with direct 256-bit key or custom password |
| `POST` | `/api/decrypt` | Authenticates HMAC tag and restores bit-exact lossless PNG |
| `POST` | `/api/share/create` | Encrypts image with custom password and generates a unique shareable link |
| `GET` | `/api/share/{id}/info` | Retrieves public metadata & ciphertext noise preview for recipient view |
| `POST` | `/api/share/{id}/decrypt` | Recipient unlock endpoint: validates password & HMAC tag to reveal image |
| `GET` | `/share/{share_id}` | Serves the dedicated recipient unlock web portal |
| `POST` | `/api/metrics` | Calculates complete academic security evaluation metrics |
| `GET` | `/` | Serves the main interactive Web UI dashboard |
| `GET` | `/samples/{file}` | Serves built-in test images for quick demonstrations |

