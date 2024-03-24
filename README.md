# KRY Project

## Local installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pdm
pdm install
```

## Run the application

```bash
python3 main.py
```

Visit [Swagger](https://localhost:42069/docs).

In another window, run:

```bash
source .venv/bin/activate
python3 file_share/app/test_send_file.py
```
