"""
Filesystem-based volume blob storage.
Volumes are stored as opaque binary blobs — the server cannot read them.
"""
import os
import shutil
from . import config


class VolumeStore:
    """Stores encrypted volume payloads on the filesystem."""

    def __init__(self, base_path: str | None = None):
        self._base = base_path or config.VOLUME_STORAGE_PATH
        os.makedirs(self._base, exist_ok=True)

    def _user_dir(self, user_id: str) -> str:
        # Sanitize: user_id is a UUID, but be safe
        safe_id = user_id.replace("/", "").replace("..", "")
        return os.path.join(self._base, safe_id)

    def _volume_path(self, user_id: str, volume_name: str) -> str:
        safe_name = volume_name.replace("/", "").replace("..", "")
        return os.path.join(self._user_dir(user_id), f"{safe_name}.bin")

    def store(self, user_id: str, volume_name: str, data: bytes) -> str:
        """Store an encrypted volume blob. Returns the storage path."""
        user_dir = self._user_dir(user_id)
        os.makedirs(user_dir, exist_ok=True)
        path = self._volume_path(user_id, volume_name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def load(self, user_id: str, volume_name: str) -> bytes | None:
        """Load an encrypted volume blob. Returns None if not found."""
        path = self._volume_path(user_id, volume_name)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def delete_volume(self, user_id: str, volume_name: str) -> None:
        path = self._volume_path(user_id, volume_name)
        if os.path.exists(path):
            os.remove(path)

    def delete_user(self, user_id: str) -> None:
        """Remove all volumes for a user."""
        user_dir = self._user_dir(user_id)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)

    def get_size(self, user_id: str, volume_name: str) -> int:
        path = self._volume_path(user_id, volume_name)
        if os.path.exists(path):
            return os.path.getsize(path)
        return 0
