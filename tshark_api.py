from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from tshark_parse3 import start
from filter_conversations_test import filter_data
import json
import os

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
@app.post("/api/v1/filter/{name}")
def search_endpoint(name: str, condition: str):
    try:
        # 경로에 있는 파일 읽기
        file_path = os.path.join("D:\\script\\wireshark\\pcap_results", f"{name}.json")
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Not Found")
        
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # 필터링 적용
        result = filter_data(data, condition)

        # 결과 저장
        output_dir = "D:\\script\\wireshark\\pcap_parse"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{name}_filtered_result.json")
        
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=4)

        return make_response(
          "filter success",
          saved_file=output_file,
        )

    except HTTPException as e:
        return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")