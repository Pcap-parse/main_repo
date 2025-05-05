from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from tshark_parse3 import start
from filter_conversations_test import filter_data

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


#############################################################################
# 에러 코드 설정 공통 api
def generate_error_response(status_code: int, detail: str):
    return {
        "message": "request failed",
        "error_code": status_code,
        "error_detail": detail
    }

# 공통 반환 값 설정 api
def make_response(message: str, **kwargs):
    response = {"message": message}
    response.update(kwargs)
    return response


# 필터링 적용 api
@app.get("/api/v1/filter/{name}")
def search_endpoint(name: str, condition: str):
    try:
        # 필터링 적용
        result = filter_data(name, condition)

        return make_response(
          "filter success",
          data=result,
        )

    except HTTPException as e:
        return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")