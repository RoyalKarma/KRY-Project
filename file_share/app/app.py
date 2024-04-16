import asyncio
import base64
import ssl
from cryptography.hazmat.primitives import hashes
import tkinter.messagebox
from pathlib import Path
from typing import Any, Union, Optional
from tkinter import *
from tkinter import filedialog as fd

from file_share.definitions.enums import SendStatus
from file_share.definitions.procedures import load_file

import re

from file_share.database import Database, Files
from file_share.definitions import PORT, certs_dir
from file_share.friend_finder.ping_em import StoppablePingClient, StoppableUDPServer
from file_share.definitions.dataclasses import (
    StoppableThread,
    DecryptedFile,
    Certificate,
)
from file_share.receiver import StoppableUvicorn
from file_share.sender.sender import StoppableQueueSender, send_or_store_file, send_cert


class FileShareApp:
    def __init__(self, token: bytes, config: dict[str, Any]):
        """
        Initialize the application.
        Config currently supports these keys:
            'visible': if True, app will respond to pings
            'audible': if True, app will send pings
        """
        self.token: bytes = token
        self.config: dict[str, Any] = config
        self.threads: list[StoppableThread] = []
        self.database = Database()
        self.file_path = ""

    # Helper methods for Tkinter interactions
    def get_file(self, app_window):
        """
        Select a file to be sent.
        Args:
            app_window: Tkinter window
        """
        self.file_path = fd.askopenfilename()
        file_label = Entry(app_window)
        file_label.delete(0, END)
        file_label.insert(0, self.file_path)
        file_label.grid(row=4, column=1, sticky=EW)

    def set_target(self, friend):
        """
        Set target user for file transfer.
        Args:
            friend: username of the target user
        """
        self.target_field.delete(0, END)
        self.target_field.insert(0, friend)

    def prepare_file(self, file_path, target):
        """
        Prepare a file to be sent via the app.
        Args:
            file_path: path to the file
            target: username of the target user
        """
        return load_file(file_path, target)

    def show_friends(self):
        """
        Show a list of friends in a new window.
        Args:
            None
        """
        top = Tk()
        friends_listbox = Listbox(top, width=50)
        friends = self.list_friends()
        i = 0
        for friend in friends:
            friends_listbox.insert(i, friend)
            i += 1
        friends_listbox.pack()
        top.mainloop()

    def get_selected_file_from_listbox(self, ListBox):
        """
        Retrieves the currently selected file from a listbox.
        Args:
            ListBox: Tkinter listbox
        """
        get_selected_file = ListBox.get(ACTIVE)
        # Make sure to always just use the database file index, since file might have a different index in the files list, listbox and db
        selected_file_index = re.search("\d+", get_selected_file).group(0)
        print("Index selected:", selected_file_index)
        # Passing files as arg doesnt work, so it has to be listed again
        files = self.list_incoming_queue()
        for file in files:
            if int(file.idx) == int(selected_file_index):
                return file

    # Pulls the outgoing queue from the db and inserts it into a listbox, currently also testing file saving from queue here
    def show_outgoing_queue(self):
        """
        Takes the outgoing queue from the database and inserts it into a listbox.
        Args:
            None
        """
        top = Tk()
        outgoing_listbox = Listbox(top, width=50)
        files = self.list_outgoing_queue()
        print(files)
        for file in files:
            parsedfile = f"{file.idx}-{file.filename}-{file.username}-{file.timestamp}"
            outgoing_listbox.insert(file.idx, parsedfile)
        outgoing_listbox.pack()
        top.mainloop()

    def show_incoming_queue(self):
        """
        Show the incoming queue in a new window where the user can save files, ignore them or save all.
        Args:
            None
        """
        top = Tk()
        incoming_listbox = Listbox(top, selectmode=SINGLE, width=50)
        incoming_listbox.pack()

        def update_list():
            """
            Updates the list of incoming files.
            """
            files = self.list_incoming_queue()
            incoming_listbox.delete(0, END)
            for file in files:
                parsed_file = (
                    f"{file.idx}-{file.filename}-{file.username}-{file.timestamp}"
                )
                incoming_listbox.insert(file.idx, parsed_file)

        update_list()

        save_incoming_button = Button(
            top,
            text="SAVE",
            command=lambda: [
                self.save_file_from_queue(
                    self.get_selected_file_from_listbox(incoming_listbox),
                    fd.askdirectory(),
                ),
                update_list(),
            ],
        )
        ignore_incoming_button = Button(
            top,
            text="Ignore file",
            command=lambda: [
                self.ignore_incoming_file(
                    self.get_selected_file_from_listbox(incoming_listbox)
                ),
                update_list(),
            ],
        )
        save_all = Button(
            top,
            text="SAVE ALL",
            command=lambda: [
                self.save_all_files_from_queue(fd.askdirectory()),
                update_list(),
            ],
        )

        ignore_incoming_button.pack()
        save_incoming_button.pack()
        save_all.pack()
        incoming_listbox.pack()
        top.mainloop()

    def show_non_friends(self):
        """
        Shows a list of non-friends who are reacheable by the app and allows user to to add them asi friends.
        Args:
            None
        """
        top = Tk()
        befriend_button = Button(
            top,
            text="Befriend this MF",
            command=lambda: [self.befriend(username=non_friends_listbox.get(ACTIVE))],
        )
        non_friends_listbox = Listbox(top, selectmode=SINGLE)
        non_friends = self.list_non_friends()
        i = 0
        for non_friend in non_friends:
            non_friends_listbox.insert(i, non_friend)
            i += 1
        non_friends_listbox.pack()
        befriend_button.pack()
        top.mainloop()

    def get_own_fingerprint(self):
        """
        Show logged in user's fingerprint.
        """
        top = Tk()
        fingerprint = self.get_my_fingerprint()
        finger_label = Label(top, text=fingerprint)
        finger_label.pack()

    def get_friends_fingerprint(self, name):
        """
        Show a friend's fingerprint.
        Args:
            name: username of the friend
        """
        top = Tk()
        fingerprint = self.get_user_fingerprint(username=name)
        print(fingerprint)
        fingerprint_label = Label(top, text=fingerprint)
        fingerprint_label.pack()

    def get_all_users(self):
        """
        Return all users who are reachable whetever they are in friends or not
        Args:
            None
        """
        friends = self.list_friends()
        non_friends = self.list_non_friends()
        return friends + non_friends

    def start(self):
        """Start the application."""
        print("APP HAS STARTED")
        thread = StoppableUvicorn(self.token, daemon=True)
        self.threads.append(thread)
        thread.start()
        thread = StoppableQueueSender(self.token, daemon=True)
        self.threads.append(thread)
        thread.start()
        if self.config.get("visible", False):
            thread = StoppableUDPServer(self.database, daemon=True)
            self.threads.append(thread)
            thread.start()
        if self.config.get("audible", False):
            thread = StoppablePingClient(daemon=True)
            self.threads.append(thread)
            thread.start()

        # init main window
        app_window = Tk()

        # Choose a file
        open_file_button = Button(
            app_window,
            text="Choose a file to be sent",
            command=lambda: self.get_file(app_window),
        )
        open_file_button.grid(column=0, row=1, sticky=EW, padx=10, pady=5)
        # List friends usernames
        list_friends_button = Button(
            app_window, text="List friends", command=lambda: self.show_friends()
        )
        list_friends_button.grid(column=0, row=2, sticky=EW, padx=10, pady=5)

        # Choose target for file sending

        transfer_targets = self.list_friends()
        transfer_target_var = StringVar(app_window)
        transefer_target_options = OptionMenu(
            app_window, transfer_target_var, "", *transfer_targets
        )
        transefer_target_options.grid(column=1, row=2, sticky=EW, padx=10, pady=5)

        def send_file():
            if not self.file_path:
                message = tkinter.messagebox.Message(
                    message="Please choose a file first.",
                    icon=tkinter.messagebox.WARNING,
                )
                message.show()
                return
            status = self.send_sync(
                self.prepare_file(self.file_path, transfer_target_var.get())
            )
            if status == SendStatus.SUCCESS:
                message = tkinter.messagebox.Message(message="File sent successfully.")
                message.show()
            elif status == SendStatus.QUEUED:
                message = tkinter.messagebox.Message(
                    message="User inactive, will attempt to resend later."
                )
                message.show()
            elif status == SendStatus.NOT_FRIEND:
                message = tkinter.messagebox.Message(
                    message="User is known to us, bot is not a trusted friend!",
                    icon=tkinter.messagebox.ERROR,
                )
                message.show()
            elif status == SendStatus.UNKNOWN_USER:
                message = tkinter.messagebox.Message(
                    message="Unknown user!", icon=tkinter.messagebox.ERROR
                )
                message.show()
            elif status == SendStatus.REFUSED_QUEUED:
                message = tkinter.messagebox.Message(
                    message="User did not accept the file. An attempt to resend the file has been scheduled.",
                    icon=tkinter.messagebox.WARNING,
                )
                message.show()

        # Send file
        send_file_button = Button(
            app_window,
            text="SEND FILE",
            command=lambda: send_file(),
        )
        send_file_button.grid(row=4, sticky=EW, padx=10, pady=5)

        # Show outbound queue
        show_outbound_button = Button(
            app_window,
            text="List outgoing queue",
            command=lambda: self.show_outgoing_queue(),
        )
        show_outbound_button.grid(column=0, row=3, sticky=EW, padx=10, pady=5)

        # Show inbound queue
        show_inbound_button = Button(
            app_window,
            text="List incoming queue",
            command=lambda: self.show_incoming_queue(),
        )
        show_inbound_button.grid(column=1, row=3, sticky=EW, padx=10, pady=5)

        show_non_friends_button = Button(
            app_window,
            text="List Non friends in DB",
            command=lambda: self.show_non_friends(),
        )
        show_non_friends_button.grid(column=1, row=1, sticky=EW, padx=10, pady=5)

        show_own_fingerprint_button = Button(
            app_window,
            text="Show  my own fingerprint",
            command=lambda: self.get_own_fingerprint(),
        )
        show_own_fingerprint_button.grid(column=0, row=5, sticky=EW, padx=10, pady=5)

        users = self.get_all_users()
        fingerprint_user = StringVar(app_window)
        show_friends_fingerprint_options = OptionMenu(
            app_window, fingerprint_user, "", *users
        )

        show_friends_fingerprint_button = Button(
            app_window,
            text="Show users fingerprint",
            command=lambda: self.get_friends_fingerprint(fingerprint_user.get()),
        )

        show_friends_fingerprint_options.grid(
            column=1, row=6, sticky=EW, padx=10, pady=5
        )
        show_friends_fingerprint_button.grid(
            column=0, row=6, sticky=EW, padx=10, pady=5
        )

        scan_ip_entry = Entry(app_window)
        scan_ip_entry.grid(column=1, row=7, sticky=EW, padx=10, pady=5)

        scan_ip_button = Button(
            app_window,
            text="Scan IP",
            command=lambda: self.check_ip(scan_ip_entry.get()),
        )
        scan_ip_button.grid(column=0, row=7, sticky=EW, padx=10, pady=5)

        app_window.mainloop()

    def stop(self):
        for thread in self.threads:
            thread.stop()

    async def send(self, file: DecryptedFile) -> SendStatus:  # Implemented
        """Asynchronous send method."""
        return await send_or_store_file(self.token, file, self.database)

    def send_sync(self, file: DecryptedFile) -> SendStatus:
        """Same as method send, but is synchronous."""
        return asyncio.run(self.send(file))

    def list_incoming_queue(self) -> list[Files]:  # Implemented
        """List all files that are waiting in the incoming queue."""
        return self.database.get_all_files(True)

    def list_outgoing_queue(self) -> list[Files]:  # Implemented
        """List all files that are waiting in the outgoing queue."""
        return self.database.get_all_files(False)

    def save_file_from_queue(self, file: Files, path: Union[str, Path]):  # Implemented
        """
        Save an incoming file.
        Args:
            file: File to be saved
            path: Path where the file will be saved
        """
        try:
            decrypted_file = self.database.decrypt_file(file.idx, self.token)
            decrypted_file.save(path)
            self.database.remove_file_from_queue(file.idx)
        except OSError as e:
            print(f"File {file.filenaKRYTex/main.texme} could not be saved.", e)

    def save_all_files_from_queue(self, path: Union[str, Path]):  # Implemented
        """
        Save all files in the queue to the specified location.
        Args:
            path: Path where the files will be saved
        """
        if isinstance(path, str):
            path = Path(path)
        if not path.is_dir():
            path = path.parent
        for file in self.database.get_all_files(True):
            self.save_file_from_queue(file, path)

    def ignore_incoming_file(self, file: Files) -> bool:  # Implemented
        """
        Ignore a file that is incoming and remove it from the database.
        Args:
            file: File to be ignored
        """
        if not file.incoming:
            return False
        self.database.remove_file_from_queue(idx=file.idx)
        return True

    def list_friends(self) -> list[str]:  # Implemented, probably
        """Returns a list of all known friends' usernames."""
        return self.database.get_all_users()

    def list_non_friends(self) -> list[str]:  #  Implemented
        """Returns all users that are known but are not our friends."""
        return self.database.get_all_users(False)

    def befriend(self, username: str) -> bool:  #  Implemented
        """Make a friend out of the user. Returns False if the user was already our friend."""
        return self.database.befriend(username)

    def check_ip(self, ip_address: str) -> Optional[str]:  # NOT implemented
        """
        Check if the user with this IP uses this protocol.
        This person will be added to the known users (not friends yet).
        Args:
            ip_address: IP address to check
        returns: username on success, None otherwise
        """
        try:
            asyncio.run(send_cert(ip_address, self.database))
            cert = Certificate(ssl.get_server_certificate((ip_address, PORT)).encode())
            self.database.add_user(cert, ip_address)
            return cert.name
        except Exception as e:
            print(e)

    @staticmethod
    def get_my_fingerprint() -> str:
        """Return a fingerprint of my certificate to convince friends."""
        cert = Certificate(Path(certs_dir) / "rsa.crt")
        return base64.b64encode(cert.cert.fingerprint(hashes.SHA256())).decode()

    def get_user_fingerprint(self, username: str) -> str:
        """Return a fingerprint of a friend certificate to check with them."""
        cert = Certificate(self.database.get_user(username, False).cert_file)
        return base64.b64encode(cert.cert.fingerprint(hashes.SHA256())).decode()
