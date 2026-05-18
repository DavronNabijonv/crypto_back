import os
import json
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.utils import _make_meta

# .vaultx share-mode layout:
#   [8B magic] [1B version] [12B nonce] [4B blob_len] [blob]
# blob = AES-GCM ciphertext+tag of:
#   [4B meta_len] [meta JSON bytes] [file content]
# Key is a random 256-bit value returned as hex — no KDF needed.
MAGIC = b"VAULTXSH"
VERSION = 0x02
NONCE_LEN = 12


def encrypt_for_sharing(input_path: str, output_path: str) -> str:
    share_key = os.urandom(32)
    nonce = os.urandom(NONCE_LEN)

    meta_bytes = _make_meta(input_path)
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    plaintext = struct.pack(">I", len(meta_bytes)) + meta_bytes + file_bytes
    blob = AESGCM(share_key).encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(nonce)
        f.write(struct.pack(">I", len(blob)))
        f.write(blob)

    return share_key.hex()


def decrypt_with_sharekey(
    input_path: str, output_path: str, share_key_hex: str
) -> dict:
    share_key = bytes.fromhex(share_key_hex)

    with open(input_path, "rb") as f:
        magic = f.read(8)
        if magic != MAGIC:
            raise ValueError(
                f"Not a share-mode .vaultx file (magic={magic!r})"
            )
        f.read(1)  # version byte
        nonce = f.read(NONCE_LEN)
        blob_len = struct.unpack(">I", f.read(4))[0]
        blob = f.read(blob_len)

    try:
        plaintext = AESGCM(share_key).decrypt(nonce, blob, None)
    except Exception as e:
        raise ValueError(
            "Decryption failed — wrong share key or file corrupted/tampered."
        ) from e

    meta_len = struct.unpack(">I", plaintext[:4])[0]
    meta = json.loads(plaintext[4:4 + meta_len])
    content = plaintext[4 + meta_len:]

    with open(output_path, "wb") as f:
        f.write(content)
    return meta
