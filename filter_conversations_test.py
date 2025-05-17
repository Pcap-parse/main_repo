import re
import operator as op
import json
import os
from datetime import datetime
# from dotenv import load_dotenv

OPERATOR_PRECEDENCE = {
    "!": 3,
    "&&": 2,
    "||": 1
}

JSON_FOLDER = "tshark_json//"
FILTER_INFO_JSON = "filter_list.json"
# 명세 정보 저장 json 경로
#FILTER_JSON_PATH="D:\\script\\wireshark\\pcap_results"
#json_file = os.path.join(FILTER_JSON_PATH, "filter_list.json")

# 정상 트래픽 특징 추출 결과 저장 경로
# PARSE_JSON_PATH="D:\\script\\wireshark\\pcap_results"

# .env 파일 설정
# load_dotenv()
# FILTER_JSON_PATH = os.getenv("FILTER_JSON_PATH")
# json_file = os.path.join(FILTER_JSON_PATH, "filter_list.json")
# PARSE_JSON_PATH = os.getenv("PARSE_JSON_PATH")

def convert_value(value):
    if isinstance(value, str):
        if value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            return value
    return value


def apply_operator(entry_value, operator, condition_value):
    entry_value = convert_value(entry_value)
    condition_value = convert_value(condition_value)

    if isinstance(entry_value, str) and isinstance(condition_value, str):
        entry_value = entry_value.lower()
        condition_value = condition_value.lower()

    ops = {
        "==": op.eq,
        "!=": op.ne,
        ">": op.gt,
        "<": op.lt,
        ">=": op.ge,
        "<=": op.le
    }

    return ops.get(operator, lambda x, y: False)(entry_value, condition_value)


def evaluate_condition(entry, condition):
    match = re.match(r"(\w+)\s*(==|!=|>=|<=|>|<)\s*(.*)", condition.strip())
    if match:
        field, operator, value = match.groups()
        value = value.strip(' "')
        if field in entry:
            return apply_operator(entry[field], operator, value)
    return False


def tokenize_condition(condition_str):
    return re.findall(r"!|\(|\)|&&|\|\||\s*\w+\s*(?:==|!=|>=|<=|>|<)\s*[^&|()]+|\w+", condition_str)


def convert_to_postfix(tokens):
    output, stack = [], []
    for token in tokens:
        if token in OPERATOR_PRECEDENCE:
            while (stack and stack[-1] in OPERATOR_PRECEDENCE and 
                   OPERATOR_PRECEDENCE[stack[-1]] > OPERATOR_PRECEDENCE[token]):
                output.append(stack.pop())
            stack.append(token)
        elif token == "(":
            stack.append(token)
        elif token == ")":
            while stack and stack[-1] != "(":
                output.append(stack.pop())
            stack.pop()
        else:
            output.append(token)

    while stack:
        output.append(stack.pop())
    return output


def evaluate_postfix(entry, postfix_tokens):
    stack = []
    for token in postfix_tokens:
        if token == "!":
            a = stack.pop()
            stack.append(not a)
        elif token in ["&&", "||"]:
            b, a = stack.pop(), stack.pop()
            stack.append(a and b if token == "&&" else a or b)
        else:
            stack.append(evaluate_condition(entry, token))
    return stack[0] if stack else False


def normalize_logic(logic: str) -> str:
    return {
        "and": "&&",
        "or": "||",
    }.get(logic.lower(), logic)


def condition_to_string(cond) -> str:
    operator_symbols = {
        "eq": "==",
        "ne": "!=",
        "gt": ">",
        "lt": "<",
        "ge": ">=",
        "le": "<="
    }

    if isinstance(cond, dict) and 'logic' in cond:
        logic = normalize_logic(cond['logic'])  # && 또는 ||
        inner = f" {logic} ".join(
            condition_to_string(c) for c in cond['conditions']
        )
        return f"({inner})"
    else:
        op_str = cond['operator'].lower()
        symbol = operator_symbols.get(op_str, cond['operator'])  # 매핑 없으면 원본 사용
        return f"{cond['key']} {symbol} {cond['value']}"
    

# 필터 값 입력 적용 함수
def filter_data(name, condition_str):
    # print(condition)
    # if hasattr(condition, "model_dump"):
    #     condition_str = condition_to_string(condition.model_dump())

    # # 문자열로 직접 전달된 경우
    # elif isinstance(condition, str):
    #     condition_str = condition

    file_path = os.path.join(JSON_FOLDER, f"{name}.json")
    if not os.path.exists(file_path):
        return False, "Conversations File Not Found", {}

    with open(file_path, 'r') as file:
        data = json.load(file)
        
    condition_str = re.sub(r"(\'|\")", "", condition_str)
    tokens = tokenize_condition(condition_str)
    postfix_tokens = convert_to_postfix(tokens)

    filtered_result = {}
    for key, entries in data.items():
        filtered_entries = [entry for entry in entries if evaluate_postfix(entry, postfix_tokens)]
        if filtered_entries:
            filtered_result[key] = filtered_entries

    result = {
        "filter": condition_str,
        "result": filtered_result
    }

    return True, "Success", result


# 필터 적용 결과 저장 함수
def save_filtered_data(name, condition):
    data = []

    # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
    if os.path.exists(FILTER_INFO_JSON):
        with open(FILTER_INFO_JSON , 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                data = []
    else:
        data = []

    # 동일한 name + filter 조건이 이미 존재하면 추가하지 않음
    for item in data:
        if item.get("name") == name and item.get("filter") == condition:
            return False, "Existed data", data

    # 같은 name 중 가장 큰 id 찾기
    max_id = max(
        [item.get("id", 0) for item in data if item.get("name") == name],
        default=0
    )
    new_id = max_id + 1

    # 새 항목 추가
    new_entry = {
        "name": name,
        "filter": condition,
        "timestamp": datetime.now().isoformat(),
        "id": new_id
    }
    data.append(new_entry)
    """
    # 동일한 name이 있는지 검사하고 업데이트 또는 추가
    updated = False
    for i, item in enumerate(data):
        if item.get("name") == new_entry["name"]:
            data[i] = new_entry
            updated = True
            break

    # 새 항목 추가
    if not updated:
        data.append(new_entry)"""

    # 파일에 저장
    with open(FILTER_INFO_JSON , 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    return True, "Success", data


# 필터 수정 api
def modify_filtered_data(name, id, filter):
    new_entry = {
        "name": name,
        "filter": filter,
        "timestamp": datetime.now().isoformat(),
        "id": id
    }
    # new_entry["timestamp"] = datetime.now().isoformat()
    # print(new_entry["id"])
    # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
    if os.path.exists(FILTER_INFO_JSON):
        with open(FILTER_INFO_JSON , 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        return False, "File Not Found", ""

    for i, item in enumerate(data):
        if item.get("name") == new_entry["name"] and item.get("id") == new_entry["id"]:
            data[i] = new_entry
            break
    else:
        return False, "Entry Not Found", ""
    
    # 파일에 저장
    with open(FILTER_INFO_JSON , 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    return True, "Success", data


# 명세 조회 함수
def retrieve_filtered_data(file_name, id):
    if os.path.exists(FILTER_INFO_JSON):
        with open(FILTER_INFO_JSON , 'r', encoding='utf-8') as f:
            data = json.load(f)

        condition = None
        for entry in data:
            if entry.get("name") == file_name and entry.get("id") == id:
                condition = entry.get("filter")
                break
        if condition is None:
            return False, "Entry Not Found", {}
        # print(condition)
        return True, "Success", filter_data(file_name, condition)
    
    else:
        return False, "File Not Found", {}
    
def all_filtered_data():
    if os.path.exists(FILTER_INFO_JSON):
        with open(FILTER_INFO_JSON , 'r', encoding='utf-8') as f:
            data = json.load(f)
            return True, "Success", data
    else:
        return False, "File Not Found", []



# 명세 삭제 함수
def delete_filtered_data(file_name, id):
    if os.path.exists(FILTER_INFO_JSON):
        with open(FILTER_INFO_JSON , 'r', encoding='utf-8') as f:
            data = json.load(f)

        def is_match(entry):
            return entry.get("name") == file_name and entry.get("id") == id

        if not any(is_match(entry) for entry in data):
            return False, "Entry Not Found", []

        updated_data = [entry for entry in data if not is_match(entry)]

        with open(FILTER_INFO_JSON, 'w', encoding='utf-8') as f:
            json.dump(updated_data, f, indent=4, ensure_ascii=False)

        return True, "Success", updated_data
    
    else:
        return False, "File Not Found", []