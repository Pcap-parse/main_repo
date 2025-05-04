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


VALID_INTERFACES = ["Ethernet", "Wi-Fi", "enp3s0"]

@app.post("/api/v1/tshark", response_model=StartResponse)
def start_device(req: StartRequest):
    if req.device not in VALID_INTERFACES:
        return StartResponse(success=False, error="interface not found")
    start()
    return StartResponse(success=True, error="")
