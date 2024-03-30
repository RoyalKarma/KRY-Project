import asyncio
import ssl
from pathlib import Path
from typing import Any, Union, Optional
from tkinter import *
from tkinter import filedialog as fd

from file_share.definitions.procedures import load_file

import re

from file_share.database import Database, Files
from file_share.definitions import PORT
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
        self.file_path = ''


    #Helper methods for Tkinter
    def getfile(self, app_window):
        self.file_path = fd.askopenfilename()
        file_label = Label(app_window,text = self.file_path)
        file_label.pack()

    def listfriends(self):
        top = Tk()
        Lb1 = Listbox(top)
        friends = self.list_friends()
        print(friends)
        i=0
        for friend in friends:
            Lb1.insert(i,friend)
            i+=1
        Lb1.pack()
        top.mainloop()

    def prepfile(self, file_path,target):
        return load_file(file_path,target)
    
    def getselectedfile(self,Lb2):
        get_selected_file = Lb2.get(ACTIVE)
        selected_file_index = re.search("\d+", get_selected_file).group(0)
        print("Index selected:", selected_file_index)
        files = self.list_outgoing_queue()
        for file in files:
            if int(file.idx) == int(selected_file_index):
                return file
    
    def listoutgoing(self):
        top = Tk()
        Lb2 = Listbox(top)
        files = self.list_outgoing_queue()
        for file in files:
            Lb2.insert(file.idx,file)

        path_to_save = fd.askdirectory()

        save_incoming= Button(top, text='save selected file', command=lambda:[self.save_file_from_queue(self.getselectedfile(Lb2), path_to_save)])
        save_incoming.pack()
        Lb2.pack()

        top.mainloop()
    
    # def listincoming(self):
    #    top = Tk()
    #    Lb3 = Listbox(top, selectmode=SINGLE)
    #    Lb3.pack()
    #
    #    files = self.list_incoming_queue()
    #    
    #    print(files)
    #    i=0
    #    for file in files:
    #        Lb3.insert(file.idx,file)
    #    
    #    selected_file = Lb3.get(ACTIVE)
    #    print(selected_file)
    #    save_incoming= Button(top, text='save selected file', command=lambda:self.save_file_from_queue(selected_file))
    #    save_incoming.pack()
    #    top.mainloop()###


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

        #Choose a file 
        open_file = Button(app_window, text="pick file", command=lambda:self.getfile(app_window))
        open_file.pack()
        #List friends usernames
        list_friends = Button(app_window, text='List friends', command=lambda:self.listfriends())
        list_friends.pack()

        #Choose target for file sending
        target_entry = Entry(app_window)
        target= target_entry.get()
        target_entry.pack()

        #Send file  
        send_file = Button(app_window, text='send file', command=lambda:self.send_sync(self.prepfile(self.file_path,target)))
        send_file.pack()

        #Show outbound queue
        show_outbound = Button(app_window, text='List outgoing queue', command=lambda:self.listoutgoing())
        show_outbound.pack()

        #SHow inbound quue
        show_inbound = Button(app_window, text='List incoming queue', command=lambda:self.listincoming())
        show_inbound.pack()

        #Save file from queuq


        
        
        app_window.mainloop()

    def stop(self):
        for thread in self.threads:
            thread.stop()

    async def send(self, file: DecryptedFile) -> bool:
        """Asynchronous send method."""
        return await send_or_store_file(self.token, file, self.database)

    def send_sync(self, file: DecryptedFile) -> bool:
        """Same as method send, but is synchronous."""
        return asyncio.run(self.send(file))

    def list_incoming_queue(self) -> list[Files]:
        """List all files that are waiting in the incoming queue."""
        return self.database.get_all_files(True)

    def list_outgoing_queue(self) -> list[Files]:
        """List all files that are waiting in the outgoing queue."""
        return self.database.get_all_files(False)

    def save_file_from_queue(self, file: Files, path: Union[str, Path]):
        """Save an incoming file."""
        try:
            decrypted_file = self.database.decrypt_file(file.idx, self.token)
            decrypted_file.save(path)
            self.database.remove_file_from_queue(file.idx)
        except OSError as e:
            print(f"File {file.filename} could not be saved.", e)

    def save_all_files_from_queue(self, path: Union[str, Path]):
        """Save all files in the queue to the specified location."""
        if isinstance(path, str):
            path = Path(path)
        if not path.is_dir():
            path = path.parent
        for file in self.database.get_all_files(True):
            self.save_file_from_queue(file, path)

    def ignore_incoming_file(self, file: Files) -> bool:
        """Ignore a file that is incoming and remove it from the database."""
        if not file.incoming:
            return False
        self.database.remove_file_from_queue(idx=file.idx)
        return True

    def list_friends(self) -> list[str]:
        """Returns a list of all known friends' usernames."""
        return self.database.get_all_users()

    def list_non_friends(self) -> list[str]:
        """Returns all users that are known but are not our friends."""
        return self.database.get_all_users(False)

    def befriend(self, username: str) -> bool:
        """Make a friend out of the user. Returns False if the user was already our friend."""
        return self.database.befriend(username)

    def check_ip(self, ip_address: str) -> Optional[str]:
        """
        Check if the user with this IP uses this protocol.
        This person will be added to the known users (not friends yet).

        returns username on success, None otherwise
        """
        try:
            asyncio.run(send_cert(ip_address))
            cert = Certificate(ssl.get_server_certificate((ip_address, PORT)).encode())
            self.database.add_user(cert)
            return cert.name
        except:
            return None
    