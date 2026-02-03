from fastapi import FastAPI, UploadFile, File
from detector import detect_attacks
from database import fetch_stats

app = FastAPI(title="Server Log Intrusion Detector")

@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    content = await file.read()
    lines = content.decode(errors="ignore").splitlines()

    suspicious_ips = detect_attacks(lines)

    return {
        "message": "Log analyzed successfully",
        "suspicious_ips": list(suspicious_ips)
    }

@app.get("/stats")
def stats():
    return fetch_stats()

@app.get("/")
def root():
    return {
        "status": "Running",
        "description": "Server Log Intrusion Detection API"
    }
