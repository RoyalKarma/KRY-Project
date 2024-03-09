import secrets
from file_share.definitions import api_key_length_bytes


def generate_api_key() -> str:
    """Generates 256 bit long API key for one use."""
    return secrets.token_urlsafe(api_key_length_bytes)
