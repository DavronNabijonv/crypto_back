import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from core.get_device_id import get_device_id
from core.crypto import encrypt_file, decrypt_file
from core.sharekey import encrypt_for_sharing, decrypt_with_sharekey

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def run(label, fn):
    try:
        fn()
        print(f"  [{GREEN}PASS{RESET}] {label}")
        return True
    except Exception as e:
        print(f"  [{RED}FAIL{RESET}] {label}: {e}")
        return False


# --- Phase 1 tests ---

def test_device_round_trip(tmp):
    device_id = get_device_id()
    src = os.path.join(tmp, "hello.txt")
    enc = os.path.join(tmp, "hello.vaultx")
    dec = os.path.join(tmp, "hello_out.txt")
    with open(src, "w") as f:
        f.write("Hello, Vault!")
    encrypt_file(src, enc, device_id)
    meta = decrypt_file(enc, dec, device_id)
    assert open(dec).read() == "Hello, Vault!"
    assert meta["filename"] == "hello.txt"


def test_sharekey_round_trip(tmp):
    src = os.path.join(tmp, "report.txt")
    enc = os.path.join(tmp, "report.vaultx")
    dec = os.path.join(tmp, "report_out.txt")
    with open(src, "w") as f:
        f.write("Shared report content")
    key_hex = encrypt_for_sharing(src, enc)
    meta = decrypt_with_sharekey(enc, dec, key_hex)
    assert open(dec).read() == "Shared report content"
    assert meta["filename"] == "report.txt"


# --- Phase 2 tests ---

def test_metadata_block(tmp):
    device_id = get_device_id()
    src = os.path.join(tmp, "image.png")
    enc = os.path.join(tmp, "image.vaultx")
    dec = os.path.join(tmp, "image_out.png")
    with open(src, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    encrypt_file(src, enc, device_id)
    meta = decrypt_file(enc, dec, device_id)
    assert meta["filename"] == "image.png"
    assert meta["filetype"] == "image/png"
    assert "timestamp" in meta
    assert meta["version"] == 2


def test_tamper_ciphertext(tmp):
    device_id = get_device_id()
    src = os.path.join(tmp, "data.txt")
    enc = os.path.join(tmp, "data.vaultx")
    with open(src, "w") as f:
        f.write("sensitive data")
    encrypt_file(src, enc, device_id)
    # flip a byte near the end of the blob (inside ciphertext)
    with open(enc, "r+b") as f:
        f.seek(-10, 2)
        b = f.read(1)[0]
        f.seek(-1, 1)
        f.write(bytes([b ^ 0xFF]))
    raised = False
    try:
        decrypt_file(enc, os.path.join(tmp, "out.txt"), device_id)
    except ValueError:
        raised = True
    assert raised, "Tampered file should have raised ValueError"


def test_tamper_magic(tmp):
    device_id = get_device_id()
    src = os.path.join(tmp, "doc.txt")
    enc = os.path.join(tmp, "doc.vaultx")
    with open(src, "w") as f:
        f.write("content")
    encrypt_file(src, enc, device_id)
    with open(enc, "r+b") as f:
        f.write(b"BADMAGIC")
    raised = False
    try:
        decrypt_file(enc, os.path.join(tmp, "out.txt"), device_id)
    except ValueError:
        raised = True
    assert raised, "Bad magic should have raised ValueError"


def test_wrong_device_fails(tmp):
    device_id = get_device_id()
    src = os.path.join(tmp, "secret.txt")
    enc = os.path.join(tmp, "secret.vaultx")
    with open(src, "w") as f:
        f.write("top secret")
    encrypt_file(src, enc, device_id)
    raised = False
    try:
        decrypt_file(enc, os.path.join(tmp, "out.txt"), "wrong-device-id-xxxxxxxxxxx")
    except ValueError:
        raised = True
    assert raised, "Wrong device ID should have raised ValueError"


def test_wrong_sharekey_fails(tmp):
    src = os.path.join(tmp, "shared.txt")
    enc = os.path.join(tmp, "shared.vaultx")
    with open(src, "w") as f:
        f.write("confidential")
    encrypt_for_sharing(src, enc)
    bad_key = os.urandom(32).hex()
    raised = False
    try:
        decrypt_with_sharekey(enc, os.path.join(tmp, "out.txt"), bad_key)
    except ValueError:
        raised = True
    assert raised, "Wrong share key should have raised ValueError"


def main():
    print("\n=== VaultX Test Suite ===\n")
    passed = 0
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        cases = [
            # Phase 1
            ("Device encrypt → decrypt round-trip",          lambda: test_device_round_trip(tmp)),
            ("Share key encrypt → decrypt round-trip",       lambda: test_sharekey_round_trip(tmp)),
            # Phase 2
            ("Metadata block (filename, filetype, ts, ver)", lambda: test_metadata_block(tmp)),
            ("Tamper ciphertext → decryption fails",         lambda: test_tamper_ciphertext(tmp)),
            ("Tamper magic header → decryption fails",       lambda: test_tamper_magic(tmp)),
            ("Wrong device ID → decryption fails",           lambda: test_wrong_device_fails(tmp)),
            ("Wrong share key → decryption fails",           lambda: test_wrong_sharekey_fails(tmp)),
        ]
        for label, fn in cases:
            if run(label, fn):
                passed += 1
            else:
                failed += 1

    print(f"\n{passed} passed, {failed} failed.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
