from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from tshark_parse3 import start

app = FastAPI()

# --- 데이터 클래스 정의 ---
class StartRequest(BaseModel):
    device: str

class StartResponse(BaseModel):
    success: bool
    error: str

class CollectorInfo(BaseModel):
    name: str
    device: str
    version: str
    ip: str
    started: bool
    collected_size: float
    start_time: float

class CollectorsResponse(BaseModel):
    collectors: List[CollectorInfo]

# --- 임시 메모리 데이터베이스 ---
collectors = {
    "collector1": {
        "name": "collector1",
        "device": "enp3s0",
        "version": "1.0.0",
        "ip": "192.168.0.101",
        "started": False,
        "collected_size": 0.0,
        "start_time": 0.0
    }
}

VALID_INTERFACES = ["Ethernet", "Wi-Fi", "enp3s0"]
# --- API 구현 ---

@app.post("/api/v1/start", response_model=StartResponse)
def start_device(req: StartRequest):
    if req.device not in VALID_INTERFACES:
        return StartResponse(success=False, error="interface not found")
    start()
    return StartResponse(success=True, error="")
