from fastapi import FastAPI, HTTPException, Query, Body
from pydantic import BaseModel
from typing import List
from filter_conversations_test import filter_data, save_filtered_data, delete_filtered_data, retrieve_filtered_data, modify_filtered_data
from typing import Union, List, Literal
import tshark_parse3

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

class FileInfo(BaseModel):
    name: str
    filter: str
    timestamp: str

class TsharkInfoResponse(BaseModel):
    success: bool
    msg: str
    data: List[FileInfo]


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
class SimpleCondition(BaseModel):
    key: str
    operator: str
    value: Union[str, int, float, bool]

class ConditionGroup(BaseModel):
    logic: Literal["and", "or"]
    conditions: List[Union["ConditionGroup", SimpleCondition]]

# forward reference 해결
ConditionGroup.model_rebuild()

@app.post("/api/v1/filter/apply/{name}")
def apply_filter(name: str, condition: Union[SimpleCondition, ConditionGroup]):
    try:
        result, msg, data = filter_data(name, condition)
        if result:
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
def save_filter(name: str, condition: str):
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


# class FilterUpdateRequest(BaseModel):
#     name: str
#     filter: str
#     id: int


# 필터링 수정 api
@app.put("/api/v1/filtera/modify")
def modify_filter(req: dict = Body(...)):
    try:
        # 필터링 적용
        result, msg, data = modify_filtered_data(req)
        
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
def delete_filter(name: str, id: int):
    try:
        # 필터링 적용
        result, msg, data = delete_filtered_data(name, id)

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
def retrieve_filter(name: str, id: int):
    try:
        # 필터링 적용
        result, msg, data = retrieve_filtered_data(name,id)

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
    
# parse3 정보 조회
@app.get("/api/v1/tshark_info", response_model=TsharkInfoResponse)
def serch_info():
    check_err = tshark_parse3.check_info()
    if check_err == "success":
        check, result = tshark_parse3.load_json_list()
        if check == "success":
            return TsharkInfoResponse(success=True, msg="", data=result)
        else:
            return TsharkInfoResponse(success=False, msg="Tshark Info Fail", data=[])
    else:
        return TsharkInfoResponse(success=False, msg=check_err, data=[])

# parse3 추출
@app.get("/api/v1/tshark", response_model=StartResponse)
def parse_start():
    check = tshark_parse3.start()
    if check == "success":
        return StartResponse(success=True, error="")
    else:
        return StartResponse(success=False, error="tshark start fail")
   
# parse3 정보 선택 삭제
@app.delete("/api/v1/tshark_delete/{name}", response_model=StartResponse)
def select_delete(name: str):
    result = tshark_parse3.delete_json(name)
    if result=="success":
        return StartResponse(success=True, error="")
    else:
        return StartResponse(success=False, error=f"{name} delete fail")