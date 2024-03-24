import subprocess
from pathlib import Path

from file_share.definitions import (
    certs_dir,
    my_username,
)
from file_share.app.app import FileShareApp

if __name__ == "__main__":
    # Checking if certs exist if not they are generated
    Path(certs_dir).mkdir(exist_ok=True)
    if not (Path(certs_dir) / "rsa.crt").exists():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-keyout",
                f"{certs_dir}/rsa.key",
                "-out",
                f"{certs_dir}/rsa.crt",
                "-days",
                "3650",
                "-nodes",
                "-subj",
                f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={my_username}",
            ]
        )
    fs_app = FileShareApp(b"pies", {"visible": True, "audible": True})
    fs_app.start()
    for thread in fs_app.threads:
        thread.join()
