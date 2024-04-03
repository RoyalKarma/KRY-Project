from tkinter import * 
from file_share.definitions import (
    my_username,
)
from file_share.app.init_app import is_first_init, first_init_app, init_app
def login(password):
    fs_app = init_app('piesek', config)
    print("Callback")
    login_window.destroy()
    fs_app.start()

def register(username, password):
    fs_app = first_init_app(my_username, "piesek", config)

if __name__ == "__main__":
    config = {"visible": True, "audible": True}
    login_window = Tk()
    
    if is_first_init():
        fs_app = first_init_app(my_username, "piesek", config)
    else:
        password_label = Label(login_window, text="Password:")
        password_label.pack()
        password_entry = Entry(login_window, show="*")
        password_entry.pack()
        password=password_entry.get()
        login_button = Button(login_window, text="Login", command=(lambda:login(password)))
        login_button.pack()
        login_window.mainloop()
     
    for thread in fs_app.threads:
        thread.join()
