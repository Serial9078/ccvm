from fastapi import FastAPI

app = FastAPI(title="CCVM API", version="0.1.0")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "CCVM",
        "version": "0.1.0"
    }
