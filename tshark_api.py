from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from tshark_parse3 import start
from filter_conversations_test import filter_data, save_filtered_data, delete_filtered_data, retrieve_filtered_data

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
@app.get("/api/v1/filter/apply/{name}")
def search_endpoint(name: str, condition: str):
    try:
        # 필터링 적용
        result, msg, data = filter_data(name, condition)

        if result == True:
            return make_response(msg, data=data)
        
        else:
            return generate_error_response(404, msg)

    # except FileNotFoundError as e:
    #     # 파일이 없는 경우 404 응답
    #     return generate_error_response(404, str(e))
    
    # except HTTPException as e:
    #     return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")
    

# 필터링 저장 api
@app.put("/api/v1/filter/save/{name}")
def search_endpoint(name: str, condition: str):
    try:
        # 필터링 적용
        result, msg, data = save_filtered_data(name, condition)

        if result == True:
            return make_response(msg, data=data)
        
        else:
            return generate_error_response(404, msg)

    # except FileNotFoundError as e:
    #     # 파일이 없는 경우 404 응답
    #     return generate_error_response(404, str(e))
    
    # except HTTPException as e:
    #     return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")
    

# 필터링 삭제 api
@app.delete("/api/v1/filter/delete/{name}")
def search_endpoint(name: str):
    try:
        # 필터링 적용
        result, msg, data = delete_filtered_data(name)

        if result == True:
            return make_response(msg, data=data)
        
        else:
            return generate_error_response(404, msg)

    # except FileNotFoundError as e:
    #     # 파일이 없는 경우 404 응답
    #     return generate_error_response(404, str(e))
    
    # except HTTPException as e:
    #     return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")
    

# 명세 조회 api(저장된 정보 조회)
@app.get("/api/v1/filter/retrieve/{name}")
def search_endpoint(name: str):
    try:
        # 필터링 적용
        result, msg, data = retrieve_filtered_data(name)

        if result == True:
            return make_response(msg, data=data)
        
        else:
            return generate_error_response(404, msg)

    # except FileNotFoundError as e:
    #     # 파일이 없는 경우 404 응답
    #     return generate_error_response(404, str(e))
    
    # except HTTPException as e:
    #     return generate_error_response(e.status_code, e.detail)
    
    except Exception as e:
        return generate_error_response(500, "Internal Server Error")