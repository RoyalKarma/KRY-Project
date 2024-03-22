import os
import subprocess
from pathlib import Path

from file_share.definitions.dataclasses import Certificate
from file_share.receiver import StoppableUvicorn
from file_share.database import Database
from file_share.definitions import (
    db,
    certs_dir,
    username,
)
from file_share.app.app import FileShareApp

if __name__ == "__main__":
    # Checking if certs exist if not they are generated
    Path(certs_dir).mkdir(exist_ok=True)
    # if not (Path(sender_certs) / "rsa.crt").exists():
    #     subprocess.run(
    #         [
    #             "openssl",
    #             "req",
    #             "-x509",
    #             "-newkey",
    #             "rsa:4096",
    #             "-keyout",
    #             f"{sender_certs}/rsa.key",
    #             "-out",
    #             f"{sender_certs}/rsa.crt",
    #             "-days",
    #             "3650",
    #             "-nodes",
    #             "-subj",
    #             f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={sender_name}",
    #         ]
    #     )
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
                f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={username}",
            ]
        )

    # Creating dbs for sender and reciever and adding certs of the other part
    # sender_database = Database(sender_db)
    # sender_database.add_user(Certificate(receiver_certs + "/rsa.crt"))
    # receiver_database = Database(receiver_db)
    # receiver_database.add_user(Certificate(sender_certs + "/rsa.crt"))
    fs_app = FileShareApp(b"pies", {"visible": True, "audible": True})
    fs_app.start()
    for thread in fs_app.threads:
        thread.join()
