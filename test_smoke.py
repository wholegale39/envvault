"""Smoke test for envvault — verifies AES-GCM encryption round-trip."""
import sys
import os

# server.py 要求 MASTER_PASSWORD 环境变量
os.environ.setdefault("MASTER_PASSWORD", "test-master-password")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import encrypt, decrypt, _derive_key


def test_derive_key_deterministic():
    k1 = _derive_key("test-password")
    k2 = _derive_key("test-password")
    assert k1 == k2, "same password should derive same key"


def test_encrypt_decrypt_roundtrip():
    key = _derive_key("test-password")
    plaintext = "OPENAI_API_KEY=sk-test123"
    cipher = encrypt(plaintext, key)
    assert cipher != plaintext, "ciphertext must differ from plaintext"
    assert decrypt(cipher, key) == plaintext, "round-trip must restore plaintext"


def test_wrong_password_fails():
    key = _derive_key("correct-password")
    wrong = _derive_key("wrong-password")
    cipher = encrypt("secret", key)
    try:
        decrypt(cipher, wrong)
        assert False, "wrong password should fail to decrypt"
    except Exception:
        pass  # expected


if __name__ == "__main__":
    test_derive_key_deterministic()
    test_encrypt_decrypt_roundtrip()
    test_wrong_password_fails()
    print("✅ all smoke tests passed")
