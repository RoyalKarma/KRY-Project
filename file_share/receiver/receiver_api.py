from fastapi import FastAPI, UploadFile


app = FastAPI(name="FileShare")


@app.post("/")
async def create_upload_file(file: UploadFile):
    file_bytes = file.file.read()
    print(file_bytes)
    file.file.close()
    return {"filename": file.filename}

