# HARDENED-CLOUD-INFRASTRUCTURE-FOR-AGRICULTURAL-DATA# 🌿 AgriVault
### Hardened Cloud Infrastructure for Agriculture Data
**Final Year Project — Cloud Computing, Cyber Security & Ethical Hacking**

---

## Project Overview

AgriVault is a secure file storage system built for protecting sensitive agriculture data. It mirrors the concept of a private Google Drive where **every file is AES-256 encrypted before storage** — making a cloud storage breach useless without the encryption key.

---

## Security Architecture

```
Your File
    │
    ▼
[PBKDF2-HMAC-SHA256]  ← Password + Random 256-bit Salt
    │  310,000 iterations
    ▼
[256-bit AES Key]
    │
    ▼
[AES-256-CBC Encrypt]  ← Random 128-bit IV per file
    │
    ▼
[HMAC-SHA256]  ← Encrypt-then-MAC (tamper detection)
    │
    ▼
[.agv File] → Vault Storage
```

### .agv File Format

| Field            | Size     | Description                        |
|-----------------|----------|------------------------------------|
| MAGIC_HEADER    | 12 bytes | `AGRIVAULT_V1` identifier          |
| SALT            | 32 bytes | Random salt for PBKDF2             |
| IV              | 16 bytes | Random AES initialization vector   |
| HMAC            | 32 bytes | SHA-256 MAC over IV + ciphertext   |
| TIMESTAMP       | 8 bytes  | Unix timestamp of encryption       |
| FILENAME_LEN    | 2 bytes  | Length of original filename        |
| FILENAME        | variable | Original filename (UTF-8)          |
| CIPHERTEXT      | variable | AES-256-CBC encrypted content      |

---

## Project Structure

```
agri_vault/
├── crypto_engine.py      # Core AES-256-CBC encryption/decryption
├── app.py                # Flask REST API server
├── agrivault_cli.py      # Command-line interface
├── test_crypto.py        # Unit tests (17 tests)
├── requirements.txt      # Python dependencies
└── portal/
    └── index.html        # Web portal (Google Drive-style UI)
```

---

## Setup & Installation

### 1. Prerequisites
- Python 3.10+
- VS Code
- pip

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Flask Server
```bash
python app.py
```
Server starts at: `http://localhost:5000`

### 4. Open the Web Portal
Open `portal/index.html` in your browser.

> ⚠️ For the web portal to connect to Flask, ensure the server is running on port 5000.

---

## Usage

### Web Portal (Recommended)
1. Open `portal/index.html` in your browser
2. Drag & drop any agriculture data file (CSV, PDF, images, etc.)
3. Enter a strong password
4. Click **Encrypt & Upload**
5. Files appear in the encrypted vault below
6. To download: click **Download**, enter your password → original file is restored

### Command Line Interface

**Encrypt a file:**
```bash
python agrivault_cli.py encrypt soil_data.csv
# You'll be prompted for a password

# Or pass directly (less secure — visible in shell history):
python agrivault_cli.py encrypt soil_data.csv --password MySecret123!
```

**Decrypt a file:**
```bash
python agrivault_cli.py decrypt soil_data.csv.agv
python agrivault_cli.py decrypt soil_data.csv.agv --output ./restored/
```

**View metadata (no password needed):**
```bash
python agrivault_cli.py info soil_data.csv.agv
```

### Python API
```python
from crypto_engine import encrypt_file, decrypt_file

# Encrypt
result = encrypt_file("crop_report.xlsx", "StrongPassword!")
print(result["encrypted_path"])  # → crop_report.xlsx.agv

# Decrypt
result = decrypt_file("crop_report.xlsx.agv", "StrongPassword!")
print(result["decrypted_path"])  # → original file restored
```

---

## REST API Endpoints

| Method | Endpoint                | Description                      |
|--------|------------------------|----------------------------------|
| POST   | `/api/upload`          | Upload & encrypt file            |
| GET    | `/api/files`           | List vault contents              |
| POST   | `/api/download/:id`    | Decrypt & download file          |
| DELETE | `/api/delete/:id`      | Securely wipe file               |
| GET    | `/api/stats`           | Vault statistics                 |
| GET    | `/api/health`          | Server health check              |

---

## Running Tests
```bash
python test_crypto.py
```

**Test coverage (17 tests):**
- ✅ Key derivation (PBKDF2)
- ✅ HMAC integrity
- ✅ Small/large/binary/empty file roundtrip
- ✅ Wrong password rejection
- ✅ Tampered ciphertext detection
- ✅ IV/salt uniqueness (ciphertext non-determinism)
- ✅ Metadata reading without decryption
- ✅ Magic header validation
- ✅ Constant-time HMAC comparison

---

## Key Security Concepts Demonstrated

| Concept                  | Implementation                            |
|--------------------------|-------------------------------------------|
| Data at Rest Encryption  | AES-256-CBC on every stored file          |
| Password-Based KDF       | PBKDF2-HMAC-SHA256, 310k iterations       |
| Semantic Security        | Random IV per encryption (CBC mode)       |
| Integrity Protection     | HMAC-SHA256 (Encrypt-then-MAC)            |
| Tamper Detection         | HMAC verified before decryption           |
| Timing Attack Prevention | Constant-time HMAC comparison             |
| Secure Deletion          | Random overwrite before file removal      |
| Filename Privacy         | Original name stored inside ciphertext    |

---

## Technologies Used

- **Python 3.10+** — Core language
- **cryptography** — AES, PBKDF2, HMAC (PyCA library)
- **Flask** — REST API web server
- **HTML/CSS/JS** — Web portal frontend
- **VS Code** — Development environment

---

## Learning Objectives Achieved

1. **AES-256 Encryption** — Understand block ciphers and CBC mode
2. **Key Derivation** — Why raw passwords can't be used as keys; PBKDF2
3. **Data at Rest Protection** — Why cloud storage needs client-side encryption
4. **Integrity vs Confidentiality** — HMAC adds integrity on top of encryption
5. **Secure API Design** — RESTful patterns for file management
6. **Agriculture Context** — Soil data, yield reports, irrigation schedules

---

*Specialization: Cloud Computing, Cyber Security & Ethical Hacking*
*Technology: Python, cryptography library (PyCA)*
