import re
import operator as op
import json
import os
from datetime import datetime
from dotenv import load_dotenv

OPERATOR_PRECEDENCE = {
    "!": 3,
    "&&": 2,
    "||": 1
}

load_dotenv()

FILTER_JSON_PATH = os.getenv("FILTER_JSON_PATH")
json_file = os.path.join(FILTER_JSON_PATH, "filter_list.json")
PARSE_JSON_PATH = os.getenv("PARSE_JSON_PATH")

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


# 필터 값 입력 적용 함수
def filter_data(name, condition_str):

    file_path = os.path.join(PARSE_JSON_PATH, f"{name}.json")

    if not os.path.exists(file_path):
        return False, "File Not Found", ""

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


# 필터 적용 결과 저장(or 수정) 함수
def save_filtered_data(name, condition):
    # 추가할 데이터
    new_entry = {
        "name": name,
        "filter": condition,
        "timestamp": datetime.now().isoformat()
    }
    data = []

    # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
    if os.path.exists(json_file):
        with open(json_file , 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                data = []
    else:
        data = []

    # 동일한 name이 있는지 검사하고 업데이트 또는 추가
    updated = False
    for i, item in enumerate(data):
        if item.get("name") == new_entry["name"]:
            data[i] = new_entry
            updated = True
            break

    # 새 항목 추가
    if not updated:
        data.append(new_entry)

    # 파일에 저장
    with open(json_file , 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    return True, "Success", data


# 명세 조회 함수
def retrieve_filtered_data(file_name):
    if os.path.exists(json_file):
        with open(json_file , 'r', encoding='utf-8') as f:
            data = json.load(f)

        for entry in data:
            if entry.get("name") == file_name:
                condition = entry.get("filter")
                break
        print(condition)
        return filter_data(file_name, condition)
    
    else:
        return False, "File Not Found", ""


# 명세 삭제 함수
def delete_filtered_data(file_name):
    if os.path.exists(json_file):
        with open(json_file , 'r', encoding='utf-8') as f:
            data = json.load(f)

        data = [entry for entry in data if entry.get("name") != file_name]

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return True, "Success", ""
    
    else:
        return False, "File Not Found", ""