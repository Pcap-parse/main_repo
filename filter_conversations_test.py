import re
import operator as op
import json
import os
from datetime import datetime

OPERATOR_PRECEDENCE = {
    "!": 3,
    "&&": 2,
    "||": 1
}


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


def filtered_data(data, condition_str):
    condition_str = re.sub(r"(\'|\")", "", condition_str)
    tokens = tokenize_condition(condition_str)
    postfix_tokens = convert_to_postfix(tokens)

    filtered_result = {}
    for key, entries in data.items():
        filtered_entries = [entry for entry in entries if evaluate_postfix(entry, postfix_tokens)]
        if filtered_entries:
            filtered_result[key] = filtered_entries

    return filtered_result


# 필터 적용 함수
def filter_data(name, condition):
    # 추출 결과 저장된 경로
    file_path = os.path.join("D:\\script\\wireshark\\pcap_results", f"{name}.json")

    if not os.path.exists(file_path):
        raise FileNotFoundError("Not Found")

    with open(file_path, 'r') as file:
        data = json.load(file)

    # 필터링 적용
    return filtered_data(data, condition)


# 필터 적용 결과 저장 함수
def save_filtered_data(name, result):
    # 결과 저장하는 경로
    output_dir = "D:\\script\\wireshark\\pcap_parse"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)

    # 결과 파일 저장 이름
    output_file = os.path.join(output_dir, f"{name}_filtered_result-{timestamp}.json")

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"✅ 필터링 결과 저장 완료: {output_file}")