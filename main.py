import tkinter.messagebox
from tkinter import *

from file_share.app.init_app import is_first_init, first_init_app, init_app

config = {"visible": True, "audible": True}


def main():
    login_window = Tk()
    login_window.title("Login Window")
    is_this_first_init = is_first_init()

    if is_this_first_init:
        username_label = Label(login_window, text="Choose username:")
        username_label.pack()
        username_entry = Entry(login_window)
        username_entry.pack()
    password_label = Label(login_window, text="Password:")
    password_label.pack()
    password_entry = Entry(login_window, show="*")
    password_entry.pack()

    def start_app():
        try:
            if is_this_first_init:
                fs_app = first_init_app(
                    username_entry.get(), password_entry.get(), config
                )
            else:
                fs_app = init_app(password_entry.get(), config)
        except ValueError:
            message = tkinter.messagebox.Message(
                message="Invalid password!", icon=tkinter.messagebox.ERROR
            )
            message.show()
            return
        login_window.destroy()
        fs_app.start()
        fs_app.stop()

    login_button = Button(login_window, text="Login", command=(lambda: start_app()))
    login_button.pack()
    login_window.mainloop()


if __name__ == "__main__":
    main()
