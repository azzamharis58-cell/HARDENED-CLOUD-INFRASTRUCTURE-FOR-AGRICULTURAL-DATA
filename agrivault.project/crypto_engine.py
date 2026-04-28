"""
AgriVault - Secure File Encryption Engine
Hardened Cloud Infrastructure for Agriculture Data
Uses AES-256 in CBC mode via the cryptography library
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json
import struct
import time


MAGIC_HEADER = b"AGRIVAULT_V1"
SALT_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 32
PBKDF2_ITERATIONS = 310_000  # OWASP 2023 recommended minimum


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 for integrity verification."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def encrypt_file(input_path: str, password: str) -> dict:
    """
    Encrypt a file using AES-256-CBC with PBKDF2 key derivation.
    
    Format: MAGIC | SALT(32) | IV(16) | HMAC(32) | TIMESTAMP(8) |
            ORIG_FILENAME_LEN(2) | ORIG_FILENAME | CIPHERTEXT
    
    Returns metadata dict suitable for JSON storage.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")

    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Pad to AES block size
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # HMAC over ciphertext (Encrypt-then-MAC)
    mac = compute_hmac(key, iv + ciphertext)

    # Build binary blob
    filename_bytes = os.path.basename(input_path).encode("utf-8")
    fname_len = struct.pack(">H", len(filename_bytes))
    timestamp = struct.pack(">Q", int(time.time()))

    blob = (
        MAGIC_HEADER
        + salt
        + iv
        + mac
        + timestamp
        + fname_len
        + filename_bytes
        + ciphertext
    )

    # Output path: same dir, .agv extension
    out_path = input_path + ".agv"
    with open(out_path, "wb") as f:
        f.write(blob)

    file_size = len(plaintext)
    enc_size = len(ciphertext)

    return {
        "encrypted_path": out_path,
        "original_filename": os.path.basename(input_path),
        "original_size": file_size,
        "encrypted_size": enc_size,
        "timestamp": int(time.time()),
        "algorithm": "AES-256-CBC",
        "kdf": f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS} iterations)",
        "integrity": "HMAC-SHA256 (Encrypt-then-MAC)"
    }


def decrypt_file(encrypted_path: str, password: str, output_dir: str = None) -> dict:
    """
    Decrypt an .agv file and restore the original.
    
    Verifies HMAC before decryption (prevents padding oracle attacks).
    Returns metadata dict.
    """
    if not os.path.exists(encrypted_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")

    with open(encrypted_path, "rb") as f:
        blob = f.read()

    # Validate magic header
    magic_len = len(MAGIC_HEADER)
    if blob[:magic_len] != MAGIC_HEADER:
        raise ValueError("Invalid file: not an AgriVault encrypted file.")

    offset = magic_len
    salt = blob[offset:offset + SALT_SIZE]; offset += SALT_SIZE
    iv = blob[offset:offset + IV_SIZE]; offset += IV_SIZE
    stored_mac = blob[offset:offset + HMAC_SIZE]; offset += HMAC_SIZE
    timestamp = struct.unpack(">Q", blob[offset:offset + 8])[0]; offset += 8
    fname_len = struct.unpack(">H", blob[offset:offset + 2])[0]; offset += 2
    orig_filename = blob[offset:offset + fname_len].decode("utf-8"); offset += fname_len
    ciphertext = blob[offset:]

    key = derive_key(password, salt)

    # Verify HMAC BEFORE decrypting
    expected_mac = compute_hmac(key, iv + ciphertext)
    if not _constant_time_compare(stored_mac, expected_mac):
        raise ValueError("HMAC verification failed: wrong password or file tampered.")

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plain) + unpadder.finalize()

    # Save restored file
    out_dir = output_dir or os.path.dirname(encrypted_path)
    out_path = os.path.join(out_dir, orig_filename)
    with open(out_path, "wb") as f:
        f.write(plaintext)

    return {
        "decrypted_path": out_path,
        "original_filename": orig_filename,
        "size": len(plaintext),
        "encrypted_timestamp": timestamp
    }


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def get_file_metadata(encrypted_path: str) -> dict:
    """Read metadata from an encrypted file without decrypting."""
    with open(encrypted_path, "rb") as f:
        blob = f.read()

    magic_len = len(MAGIC_HEADER)
    if blob[:magic_len] != MAGIC_HEADER:
        raise ValueError("Not a valid AgriVault file.")

    offset = magic_len + SALT_SIZE + IV_SIZE + HMAC_SIZE
    timestamp = struct.unpack(">Q", blob[offset:offset + 8])[0]; offset += 8
    fname_len = struct.unpack(">H", blob[offset:offset + 2])[0]; offset += 2
    orig_filename = blob[offset:offset + fname_len].decode("utf-8"); offset += fname_len

    return {
        "original_filename": orig_filename,
        "timestamp": timestamp,
        "encrypted_size": len(blob[offset:]),
        "format": "AgriVault V1 (AES-256-CBC)"
    }
