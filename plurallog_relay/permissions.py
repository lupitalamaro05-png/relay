"""
Maps sharing permission flags to volume names.
Must match the Flutter client's SharingPermissions.enabledVolumes logic.
"""
import json

PERMISSION_VOLUME_MAP = {
    "share_front_status": ["fronts"],
    "share_members": ["members"],
    "share_front_history": ["fronts"],
    "share_journal": ["journal"],
    "share_mood_trends": ["analytics"],
    "share_polls": ["polls"],
    "share_vault": ["vault"],
}

ALWAYS_SHARED_VOLUMES = ["meta"]

VALID_VOLUME_NAMES = {"meta", "members", "fronts", "journal", "chat", "polls", "analytics", "vault"}


def permissions_to_volumes(permissions: dict) -> set[str]:
    volumes = set(ALWAYS_SHARED_VOLUMES)
    for perm_key, is_enabled in permissions.items():
        if is_enabled and perm_key in PERMISSION_VOLUME_MAP:
            volumes.update(PERMISSION_VOLUME_MAP[perm_key])
    return volumes


def is_volume_allowed(permissions_json: str, volume_name: str) -> bool:
    try:
        perms = json.loads(permissions_json)
    except (json.JSONDecodeError, TypeError):
        perms = {}
    allowed = permissions_to_volumes(perms)
    return volume_name in allowed
