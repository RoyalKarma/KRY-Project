from typing import Any

from file_share.database import Database
from file_share.app.app import FileShareApp
from file_share.definitions.procedures import create_cert
from file_share.definitions import certs_dir

db_instance = Database()


def is_first_init():
    """
    Fuction to check if this is the first time the app is run.
    Args:
        None
    Returns:
        bool: True if this is the first time the app is run, False otherwise
    """
    return db_instance.get_me() is None


#
def first_init_app(name: str, password: str, config: dict[str, Any]) -> FileShareApp:
    """
    If this is the first time the app is run, this function will create a new user and generate a cert for it.
    Args:
        name (str): Name of the user
        password (str): Password of the user
        config (dict[str, Any]): Configuration dictionary
    Returns:
        FileShareApp: FileShareApp instance
    """
    if not db_instance.add_me(name, password):
        raise ValueError("This is not first app run.")
    token = db_instance.get_token(password)
    create_cert(name, certs_dir, token)
    return FileShareApp(token, config)


def init_app(password: str, config: dict[str, Any]) -> FileShareApp:
    """
    Function to initialize the app if the user already exists.
    Args:
        password (str): Password of the user
        config (dict[str, Any]): Configuration dictionary
    returns:
        FileShareApp: FileShareApp instance
    """
    return FileShareApp(db_instance.get_token(password), config)
