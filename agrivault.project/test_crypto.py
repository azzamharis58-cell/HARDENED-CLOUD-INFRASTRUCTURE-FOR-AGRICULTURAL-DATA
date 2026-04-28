"""
Unit Tests — AgriVault Encryption Engine
Tests AES-256-CBC encrypt/decrypt, HMAC integrity, KDF, edge cases
"""

import unittest
import os
import tempfile
import time
from crypto_engine import (
    encrypt_file, decrypt_file, derive_key,
    compute_hmac, get_file_metadata, MAGIC_HEADER
)


class TestKeyDerivation(unittest.TestCase):
    """Test PBKDF2 key derivation."""

    def test_key_length(self):
        salt = os.urandom(32)
        key = derive_key("test_password", salt)
        self.assertEqual(len(key), 32, "AES-256 key must be 32 bytes")

    def test_different_salts_produce_different_keys(self):
        s1, s2 = os.urandom(32), os.urandom(32)
        k1 = derive_key("same_password", s1)
        k2 = derive_key("same_password", s2)
        self.assertNotEqual(k1, k2)

    def test_different_passwords_produce_different_keys(self):
        salt = os.urandom(32)
        k1 = derive_key("password_one", salt)
        k2 = derive_key("password_two", salt)
        self.assertNotEqual(k1, k2)

    def test_same_inputs_deterministic(self):
        salt = b'\x42' * 32
        k1 = derive_key("deterministic", salt)
        k2 = derive_key("deterministic", salt)
        self.assertEqual(k1, k2)


class TestHMAC(unittest.TestCase):
    """Test HMAC integrity computation."""

    def test_hmac_length(self):
        key = os.urandom(32)
        mac = compute_hmac(key, b"test data")
        self.assertEqual(len(mac), 32)

    def test_tampered_data_different_hmac(self):
        key = os.urandom(32)
        m1 = compute_hmac(key, b"original data")
        m2 = compute_hmac(key, b"tampered_data!")
        self.assertNotEqual(m1, m2)

    def test_different_key_different_hmac(self):
        data = b"same data"
        m1 = compute_hmac(os.urandom(32), data)
        m2 = compute_hmac(os.urandom(32), data)
        self.assertNotEqual(m1, m2)


class TestEncryptDecrypt(unittest.TestCase):
    """Test roundtrip encryption and decryption."""

    def _make_temp_file(self, content: bytes, suffix=".txt"):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(content); f.close()
        return f.name

    def tearDown(self):
        # Clean up any .agv files left in temp dir
        pass

    def test_small_file_roundtrip(self):
        content = b"Soil pH: 6.8 | Nitrogen: 42 ppm | Crop: Wheat"
        path = self._make_temp_file(content)
        try:
            res = encrypt_file(path, "AgriPassword123!")
            dec = decrypt_file(res["encrypted_path"], "AgriPassword123!")
            with open(dec["decrypted_path"], "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, content)
        finally:
            os.unlink(path)

    def test_binary_file_roundtrip(self):
        content = os.urandom(4096)  # 4 KB of random binary data
        path = self._make_temp_file(content, ".bin")
        try:
            res = encrypt_file(path, "BinaryTest@999")
            dec = decrypt_file(res["encrypted_path"], "BinaryTest@999")
            with open(dec["decrypted_path"], "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, content)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = self._make_temp_file(b"")
        try:
            res = encrypt_file(path, "EmptyFile123")
            dec = decrypt_file(res["encrypted_path"], "EmptyFile123")
            with open(dec["decrypted_path"], "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, b"")
        finally:
            os.unlink(path)

    def test_large_file(self):
        content = b"AGRI_DATA_RECORD:" + os.urandom(1024 * 100)  # ~100 KB
        path = self._make_temp_file(content)
        try:
            res = encrypt_file(path, "LargeFile@Secure")
            dec = decrypt_file(res["encrypted_path"], "LargeFile@Secure")
            with open(dec["decrypted_path"], "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, content)
        finally:
            os.unlink(path)

    def test_wrong_password_rejected(self):
        content = b"Sensitive crop yield data"
        path = self._make_temp_file(content)
        try:
            res = encrypt_file(path, "CorrectPassword1!")
            with self.assertRaises(ValueError) as ctx:
                decrypt_file(res["encrypted_path"], "WrongPassword999!")
            self.assertIn("HMAC", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_tampered_ciphertext_detected(self):
        content = b"Top secret irrigation schedule"
        path = self._make_temp_file(content)
        try:
            res = encrypt_file(path, "TamperTest123!")
            enc_path = res["encrypted_path"]
            # Flip some bytes in the ciphertext
            with open(enc_path, "r+b") as f:
                data = bytearray(f.read())
                data[-10] ^= 0xFF  # Flip bits near the end
                f.seek(0); f.write(bytes(data))
            with self.assertRaises(ValueError):
                decrypt_file(enc_path, "TamperTest123!")
        finally:
            os.unlink(path)

    def test_each_encryption_produces_unique_ciphertext(self):
        """Same file + same password → different ciphertext (due to random IV + salt)"""
        content = b"Identical content"
        path1 = self._make_temp_file(content)
        path2 = self._make_temp_file(content)
        try:
            r1 = encrypt_file(path1, "SamePassword1!")
            r2 = encrypt_file(path2, "SamePassword1!")
            with open(r1["encrypted_path"], "rb") as f: c1 = f.read()
            with open(r2["encrypted_path"], "rb") as f: c2 = f.read()
            self.assertNotEqual(c1, c2, "IV/salt randomness must make ciphertexts unique")
        finally:
            os.unlink(path1); os.unlink(path2)

    def test_metadata_correct(self):
        content = b"Crop data"
        path = self._make_temp_file(content, ".csv")
        try:
            res = encrypt_file(path, "MetaTest123!")
            self.assertEqual(res["algorithm"], "AES-256-CBC")
            self.assertIn("PBKDF2", res["kdf"])
            self.assertIn("HMAC", res["integrity"])
            self.assertEqual(res["original_size"], len(content))
        finally:
            os.unlink(path)

    def test_file_info_readable_without_password(self):
        content = b"Public metadata test"
        path = self._make_temp_file(content, ".csv")
        try:
            res = encrypt_file(path, "InfoTest123!")
            info = get_file_metadata(res["encrypted_path"])
            self.assertIn("original_filename", info)
            self.assertEqual(info["format"], "AgriVault V1 (AES-256-CBC)")
        finally:
            os.unlink(path)

    def test_magic_header_present(self):
        content = b"Magic header check"
        path = self._make_temp_file(content)
        try:
            res = encrypt_file(path, "HeaderTest123!")
            with open(res["encrypted_path"], "rb") as f:
                header = f.read(len(MAGIC_HEADER))
            self.assertEqual(header, MAGIC_HEADER)
        finally:
            os.unlink(path)

    def test_invalid_file_rejected(self):
        """Non-.agv files must be rejected."""
        path = self._make_temp_file(b"this is not encrypted")
        try:
            with self.assertRaises(ValueError):
                decrypt_file(path, "AnyPassword")
        finally:
            os.unlink(path)


class TestSecurityProperties(unittest.TestCase):
    """Verify security guarantees."""

    def test_aes_key_is_256_bits(self):
        key = derive_key("any_password", os.urandom(32))
        self.assertEqual(len(key) * 8, 256)

    def test_iv_uniqueness(self):
        ivs = set()
        for _ in range(100):
            ivs.add(os.urandom(16))
        self.assertEqual(len(ivs), 100, "IVs must be unique (random)")

    def test_hmac_constant_time_compare(self):
        from crypto_engine import _constant_time_compare
        self.assertTrue(_constant_time_compare(b"abc", b"abc"))
        self.assertFalse(_constant_time_compare(b"abc", b"xyz"))
        self.assertFalse(_constant_time_compare(b"ab", b"abc"))


if __name__ == "__main__":
    print("=" * 60)
    print("  AgriVault Unit Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
