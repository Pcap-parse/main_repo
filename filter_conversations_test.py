import json
import re
import operator as op
import os

# 연산자 우선순위 설정
OPERATOR_PRECEDENCE = {
    "!": 3,
    "&&": 2,
    "||": 1
}

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

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
    return re.findall(r"\(|\)|&&|\|\||!\s*\w+\s*(?:==|!=|>=|<=|>|<)\s*[^&|()]+|\w+\s*(?:==|!=|>=|<=|>|<)\s*[^&|()]+|!", condition_str)

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
        if token == "!":  # 단항 연산자 처리
            a = stack.pop()
            stack.append(not a)
        elif token in ["&&", "||"]:
            b, a = stack.pop(), stack.pop()
            stack.append(a and b if token == "&&" else a or b)
        else:
            stack.append(evaluate_condition(entry, token))
    
    return stack[0] if stack else False

def filter_data(data, condition_str):
    tokens = tokenize_condition(condition_str)
    postfix_tokens = convert_to_postfix(tokens)

    filtered_result = {}
    for key, entries in data.items():
        filtered_entries = [entry for entry in entries if evaluate_postfix(entry, postfix_tokens)]
        if filtered_entries:  # 필터링된 데이터가 있으면 추가
            filtered_result[key] = filtered_entries

    return filtered_result  # 리스트가 아닌 원본 구조 유지

# def display_filtered_data(filtered_data):
#     if filtered_data:
#         for item in filtered_data:
#             print(json.dumps(item, indent=4))
#     else:
#         print("조건에 맞는 데이터가 없습니다.")

def save_filtered_data(filtered_data, output_file):
    filtered_file = "D:\\script\\wireshark\\pcap_parse"
    os.makedirs(filtered_file, exist_ok=True)

    # 파일 전체 경로 생성
    output_path = os.path.join(filtered_file, output_file)

    with open(output_path, 'w') as file:
        json.dump(filtered_data, file, indent=4)
    print(f"필터링된 데이터가 '{output_file}'에 저장되었습니다.")

def main():
    file_path = "D:\\script\\wireshark\\pcap_results\\"
    file_name = input("JSON 파일 명을 입력하세요(확장자 포함): ")
    data = load_json(file_path+file_name)
    conditions_input = input("필터링할 조건을 입력하세요: ")
    conditions_input = re.sub(r"(\'|\")","",conditions_input)
    filtered_data = filter_data(data, conditions_input)

    # 데이터 출력
    # display_filtered_data(filtered_data)

    # save_option = input("필터링된 데이터를 파일에 저장할까요? (y/n): ")
    # if save_option.lower() == 'y':
    output_file = input("저장할 JSON 파일 명을 입력하세요(확장자 포함): ")
    save_filtered_data(filtered_data, output_file)

if __name__ == "__main__":
    main()
