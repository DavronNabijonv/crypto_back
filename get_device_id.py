import hashlib
import platform


def get_device_id() -> str:
    # /etc/machine-id is a stable UUID written once at OS install.
    # uuid.getnode() is NOT used — on modern Linux, NetworkManager randomizes
    # MAC addresses per connection, making it non-deterministic across reboots.
    try:
        with open("/etc/machine-id") as f:
            machine_id = f.read().strip()
    except OSError:
        # Fallback for non-Linux (macOS, Windows) or missing file
        machine_id = platform.node()

    raw = f"{machine_id}-{platform.system()}"
    return hashlib.sha256(raw.encode()).hexdigest()
