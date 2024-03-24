from file_share.app.init_app import init_app
from file_share.definitions.procedures import load_file

app = init_app("piesek", {})
app.send_sync(load_file("testfile.txt", "alice"))
