import os
import json
import mimetypes
import time

FORMAT_VERSION = 0x02


def _make_meta(input_path: str) -> bytes:
    filename = os.path.basename(input_path)
    mime, _ = mimetypes.guess_type(filename)
    meta = {
        "filename": filename,
        "filetype": mime or "application/octet-stream",
        "timestamp": time.time(),
        "version": FORMAT_VERSION,
    }
    return json.dumps(meta, separators=(",", ":")).encode()
