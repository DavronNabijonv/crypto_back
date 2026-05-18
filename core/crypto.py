import os
import json
import struct
import mimetypes
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# .vaultx v2 layout (device-locked):
#   [8B magic] [1B version] [16B salt] [12B nonce] [4B blob_len] [blob]
# blob = AES-GCM ciphertext+tag of:
#   [4B meta_len] [meta JSON bytes] [file content]
MAGIC = b"VAULTXV2"
VERSION = 0x02
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERATIONS = 480_000


def derive_key(device_id: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(device_id.encode())


def _make_meta(input_path: str) -> bytes:
    filename = os.path.basename(input_path)
    mime, _ = mimetypes.guess_type(filename)
    meta = {
        "filename": filename,
        "filetype": mime or "application/octet-stream",
        "timestamp": time.time(),
        "version": VERSION,
    }
    return json.dumps(meta, separators=(",", ":")).encode()


def encrypt_file(input_path: str, output_path: str, device_id: str) -> None:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(device_id, salt)

    meta_bytes = _make_meta(input_path)
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    plaintext = struct.pack(">I", len(meta_bytes)) + meta_bytes + file_bytes
    blob = AESGCM(key).encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(salt)
        f.write(nonce)
        f.write(struct.pack(">I", len(blob)))
        f.write(blob)


def decrypt_file(input_path: str, output_path: str, device_id: str) -> dict:
    with open(input_path, "rb") as f:
        magic = f.read(8)
        if magic != MAGIC:
            raise ValueError(f"Not a device-locked .vaultx file (magic={magic!r})")
        f.read(1)  # version byte
        salt = f.read(SALT_LEN)
        nonce = f.read(NONCE_LEN)
        blob_len = struct.unpack(">I", f.read(4))[0]
        blob = f.read(blob_len)

    key = derive_key(device_id, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, blob, None)
    except Exception as e:
        raise ValueError("Decryption failed — wrong device or file corrupted/tampered.") from e

    meta_len = struct.unpack(">I", plaintext[:4])[0]
    meta = json.loads(plaintext[4 : 4 + meta_len])
    content = plaintext[4 + meta_len :]

    with open(output_path, "wb") as f:
        f.write(content)
    return meta
