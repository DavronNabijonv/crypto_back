import io
import os
import tempfile

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from core.crypto import MAGIC as DEVICE_MAGIC
from core.crypto import decrypt_file, encrypt_file
from core.sharekey import MAGIC as SHARE_MAGIC
from core.sharekey import decrypt_with_sharekey, encrypt_for_sharing

router = APIRouter()


def _stream(data: bytes, filename: str, content_type: str, extra_headers: dict = {}) -> StreamingResponse:
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    headers.update(extra_headers)
    return StreamingResponse(io.BytesIO(data), media_type=content_type, headers=headers)


# ---------------------------------------------------------------------------
# POST /encrypt
#   Client sends: the original file + their device_id (the secret)
#   Server:       derives key from device_id, encrypts, returns .vaultx
#   Server keeps: nothing — device_id is used in memory then discarded
# ---------------------------------------------------------------------------
@router.post("/encrypt")
async def encrypt(
    file: UploadFile = File(...),
    device_id: str = Form(...),
):
    raw = await file.read()

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, file.filename)
        enc = os.path.join(tmp, file.filename + ".vaultx")

        with open(src, "wb") as f:
            f.write(raw)

        encrypt_file(src, enc, device_id)  # device_id used here, never stored

        with open(enc, "rb") as f:
            encrypted = f.read()

    return _stream(encrypted, file.filename + ".vaultx", "application/octet-stream")


# ---------------------------------------------------------------------------
# POST /decrypt
#   Client sends: a .vaultx file + the key (device_id OR share_key_hex)
#   Server:       reads magic bytes to detect file type, decrypts, returns file
#   Server keeps: nothing — key is used in memory then discarded
# ---------------------------------------------------------------------------
@router.post("/decrypt")
async def decrypt(
    file: UploadFile = File(...),
    key: str = Form(...),
):
    raw = await file.read()
    magic = raw[:8]

    with tempfile.TemporaryDirectory() as tmp:
        enc = os.path.join(tmp, "input.vaultx")
        with open(enc, "wb") as f:
            f.write(raw)

        base_name = file.filename.removesuffix(".vaultx") if file.filename.endswith(".vaultx") else file.filename
        dec = os.path.join(tmp, base_name)

        try:
            if magic == DEVICE_MAGIC:
                meta = decrypt_file(enc, dec, key)        # key = device_id
            elif magic == SHARE_MAGIC:
                meta = decrypt_with_sharekey(enc, dec, key)  # key = share_key_hex
            else:
                raise HTTPException(status_code=400, detail="Unrecognized .vaultx format")
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        with open(dec, "rb") as f:
            decrypted = f.read()

    filename = meta.get("filename", base_name)
    content_type = meta.get("filetype", "application/octet-stream")
    return _stream(decrypted, filename, content_type)


# ---------------------------------------------------------------------------
# POST /share
#   Client sends: the original file
#   Server:       generates a random 256-bit key, encrypts, returns:
#                   - the .vaultx file as the response body
#                   - the share key in the X-Share-Key header
#   Server keeps: nothing — the key is generated, used, returned, then gone
# ---------------------------------------------------------------------------
@router.post("/share")
async def share(file: UploadFile = File(...)):
    raw = await file.read()

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, file.filename)
        enc = os.path.join(tmp, file.filename + ".vaultx")

        with open(src, "wb") as f:
            f.write(raw)

        share_key = encrypt_for_sharing(src, enc)  # returns key as hex, never stored

        with open(enc, "rb") as f:
            encrypted = f.read()

    return _stream(
        encrypted,
        file.filename + ".vaultx",
        "application/octet-stream",
        extra_headers={"X-Share-Key": share_key},
    )
