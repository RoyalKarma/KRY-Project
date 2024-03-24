from file_share.definitions import (
    my_username,
)
from file_share.app.init_app import is_first_init, first_init_app, init_app

if __name__ == "__main__":
    config = {"visible": True, "audible": True}
    if is_first_init():
        fs_app = first_init_app(my_username, "piesek", config)
    else:
        fs_app = init_app("piesek", config)
    fs_app.start()
    for thread in fs_app.threads:
        thread.join()
