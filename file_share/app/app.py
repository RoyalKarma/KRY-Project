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


    #Helper methods for Tkinter interactions
    def get_file(self, app_window):
        self.file_path = fd.askopenfilename()
        file_label = Label(app_window,text = self.file_path)
        file_label.pack()

    #Get list of friends from db and insert it into a listbox
    def show_friends(self):
        top = Tk()
        friends_listbox = Listbox(top)
        friends = self.list_friends()
        print(friends)
        i=0
        for friend in friends:
            friends_listbox.insert(i,friend)
            i+=1
        friends_listbox.pack()
        top.mainloop()

    #Takes regular file and prepares it to be sent via the app
    def prepare_file(self, file_path,target):
        return load_file(file_path,target)
    
    #Gets currently selected file from a listbox
    def get_selected_file_from_listbox(self,ListBox):
        get_selected_file = ListBox.get(ACTIVE)
        #Make sure to always just use the database file index, since file might have a different index in the files list, listbox and db
        selected_file_index = re.search("\d+", get_selected_file).group(0)
        print("Index selected:", selected_file_index)
        #Passing files as arg doesnt work, so it has to be listed again
        files = self.list_outgoing_queue()
        for file in files:
            if int(file.idx) == int(selected_file_index):
                return file
        
    
    #Pulls the outgoing queue from the db and inserts it into a listbox, currently also testing file saving from queue here
    def show_outgoing_queue(self):
        top = Tk()
        outgoing_listbox = Listbox(top)
        files = self.list_outgoing_queue()
        print(files)
        for file in files:
            outgoing_listbox.insert(file.idx,file)
        outgoing_listbox.pack()
        top.mainloop()

    # Lists incoming queue, with the options to either save all the files, save a specific one, or to remote a file
    def show_incoming_queue(self):
        top = Tk()
        incoming_listbox = Listbox(top, selectmode=SINGLE)
        incoming_listbox.pack()  
        files = self.list_incoming_queue()
        print(files)
        for file in files:
            incoming_listbox.insert(file.idx,file)
        
        path_to_save = fd.askdirectory()

        save_incoming_button= Button(top, text='SAVE', command=lambda:[self.save_file_from_queue(self.get_selected_file_from_listbox(incoming_listbox), path_to_save)])
        ignore_incoming_button= Button(top, text='Ignore file', command=lambda:[self.ignore_incoming_file(self.get_selected_file_from_listbox(incoming_listbox))])
        save_all = Button(top, text='SAVE ALL', command=lambda:[self.save_all_files_from_queue(path_to_save)])
        ignore_incoming_button.pack()
        save_incoming_button.pack()
        save_all.pack()
        incoming_listbox.pack()
        top.mainloop()


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
        open_file_button = Button(app_window, text="Choose a file to be sent", command=lambda:self.get_file(app_window))
        open_file_button.pack()
        #List friends usernames
        list_friends_button = Button(app_window, text='List friends', command=lambda:self.show_friends())
        list_friends_button.pack()

        #Choose target for file sending
        transfer_target_entry = Entry(app_window)
        target= transfer_target_entry.get()
        transfer_target_entry.pack()

        #Send file  
        send_file_button = Button(app_window, text='SEND FILE', command=lambda:self.send_sync(self.prepare_file(self.file_path,target)))
        send_file_button.pack()

        #Show outbound queue
        show_outbound_button = Button(app_window, text='List outgoing queue', command=lambda:self.show_outgoing_queue())
        show_outbound_button.pack()

        #Show inbound queue
        show_inbound_button = Button(app_window, text='List incoming queue', command=lambda:self.show_incoming_queue())
        show_inbound_button.pack()

        app_window.mainloop()

    def stop(self):
        for thread in self.threads:
            thread.stop()

    async def send(self, file: DecryptedFile) -> bool: #Implemented
        """Asynchronous send method."""
        return await send_or_store_file(self.token, file, self.database)

    def send_sync(self, file: DecryptedFile) -> bool: 
        """Same as method send, but is synchronous."""
        return asyncio.run(self.send(file))

    def list_incoming_queue(self) -> list[Files]: #Implemented
        """List all files that are waiting in the incoming queue."""
        return self.database.get_all_files(True)

    def list_outgoing_queue(self) -> list[Files]: #I#Implementedmplemented
        """List all files that are waiting in the outgoing queue."""
        return self.database.get_all_files(False)

    def save_file_from_queue(self, file: Files, path: Union[str, Path]): #Implemented
        """Save an incoming file."""
        try:
            decrypted_file = self.database.decrypt_file(file.idx, self.token)
            decrypted_file.save(path)
            self.database.remove_file_from_queue(file.idx)
        except OSError as e:
            print(f"File {file.filename} could not be saved.", e)

    def save_all_files_from_queue(self, path: Union[str, Path]): #NOT Implemented
        """Save all files in the queue to the specified location."""
        if isinstance(path, str):
            path = Path(path)
        if not path.is_dir():
            path = path.parent
        for file in self.database.get_all_files(True):
            self.save_file_from_queue(file, path)

    def ignore_incoming_file(self, file: Files) -> bool: # Implemented
        """Ignore a file that is incoming and remove it from the database."""
        if not file.incoming:
            return False
        self.database.remove_file_from_queue(idx=file.idx)
        return True

    def list_friends(self) -> list[str]: #Implemented, probably
        """Returns a list of all known friends' usernames."""
        return self.database.get_all_users()

    def list_non_friends(self) -> list[str]: #NOT implemented
        """Returns all users that are known but are not our friends."""
        return self.database.get_all_users(False)

    def befriend(self, username: str) -> bool: #NOT implemented
        """Make a friend out of the user. Returns False if the user was already our friend."""
        return self.database.befriend(username)

    def check_ip(self, ip_address: str) -> Optional[str]: #NOT implemented
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
    