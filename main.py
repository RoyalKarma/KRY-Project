import os
import subprocess
from pathlib import Path

from file_share.receiver import run_server
from file_share.database import Database
from file_share.definitions import receiver_db, sender_db, receiver_certs, sender_certs, sender_name, receiver_name

if __name__ == "__main__":
    Path(sender_certs).mkdir(exist_ok=True)
    Path(receiver_certs).mkdir(exist_ok=True)
    if not (Path(sender_certs) / "rsa.crt").exists():
        print("running")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", f"{sender_certs}/rsa.key", "-out", f"{sender_certs}/rsa.crt", "-days", "3650", "-nodes",
                    "-subj", f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={sender_name}"])
    if not (Path(receiver_certs) / "rsa.crt").exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-keyout", f"{receiver_certs}/rsa.key", "-out",
                    f"{receiver_certs}/rsa.crt", "-days", "3650", "-nodes",
                    "-subj", f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={receiver_name}"])

    sender_database = Database(sender_db)
    sender_database.add_user(receiver_certs + "/rsa.crt")
    receiver_database = Database(receiver_db)
    receiver_database.add_user(sender_certs + "/rsa.crt")
    run_server()
