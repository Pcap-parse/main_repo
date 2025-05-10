from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import api_tshark_parse3
from filter_conversations_test import filter_data
from typing import List, Dict, Any

app = FastAPI()

# --- 데이터 클래스 정의 ---
class StartRequest(BaseModel):
    save_name: str

class DefaultResponse(BaseModel):
    success: bool
    msg: str

class FileInfo(BaseModel):
    name: str
    filter: str
    timestamp: str

class FlowInfo2(BaseModel):
    address_A: str
    port_A: int
    address_B: str
    port_B: int
    bytes: int
    packets: int
    protocol: str
    entropy: float

class TsharkInfoResponse(BaseModel):
    success: bool
    msg: str
    data: List[FileInfo]

class JsonSearchResponse(BaseModel):
    success: bool
    msg: str
    data: Dict[str, List[FlowInfo2]]



@app.get("/api/v1/tshark_search_test/{name}", response_model=JsonSearchResponse)
def serch_info(name: str):
    import json
    target_json = f"tshark_json//{name}"
    with open(target_json, "r", encoding="utf-8") as f:
        result = json.load(f)
    return JsonSearchResponse(success=True, msg="ok", data=result)

# parse3 추출
@app.get("/api/v1/tshark", response_model=DefaultResponse)
def start_info():
    check = api_tshark_parse3.start()
    if check == "success":
        return DefaultResponse(success=True, msg="")
    else:
        return DefaultResponse(success=False, msg="tshark start fail")

# parse3 정보 조회
@app.get("/api/v1/tshark_info", response_model=TsharkInfoResponse)
def serch_info():
    check_err = api_tshark_parse3.check_info()
    if check_err == "success":
        check, result = api_tshark_parse3.load_json_list()
        if check == "success":
            return TsharkInfoResponse(success=True, msg="", data=result)
        else:
            return TsharkInfoResponse(success=False, msg="Tshark Info Fail", data=[])
    else:
        return TsharkInfoResponse(success=False, msg=check_err, data=[])
    
# parse3 특징 조회
@app.get("/api/v1/tshark_search/{name}", response_model=JsonSearchResponse)
def serch_info(name: str):
    result = api_tshark_parse3.json_search(name)
    if result != None:
        return JsonSearchResponse(success=True, msg="", data=result)
    else:
        return JsonSearchResponse(success=False, msg="Json Search Fail", data=[])

# parse3 정보 전체 삭제
@app.get("/api/v1/tshark_all_delete", response_model=DefaultResponse)
def start_info():
    result = api_tshark_parse3.all_delete()
    if result=="success":
        return DefaultResponse(success=True, msg="")
    else:
        return DefaultResponse(success=False, msg=result)
    
# parse3 정보 선택 삭제
@app.get("/api/v1/tshark_delete/{name}", response_model=DefaultResponse)
def start_info(name: str):
    result = api_tshark_parse3.delete_json(name)
    if result=="success":
        return DefaultResponse(success=True, msg="")
    else:
        return DefaultResponse(success=False, msg=f"{name} delete fail")

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