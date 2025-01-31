import json
import re
import operator as op

# 연산자 우선순위 설정
OPERATOR_PRECEDENCE = {
    "!": 3,  # NOT 연산자 (단항)
    "&&": 2, # AND 연산자
    "||": 1  # OR 연산자
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
    tokens = re.findall(r"!|\(|\)|&&|\|\||\w+\s*(?:==|!=|>=|<=|>|<)\s*[^&|()]+", condition_str)
    return tokens

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
        if token in ["&&", "||"]:
            b, a = stack.pop(), stack.pop()
            stack.append(a and b if token == "&&" else a or b)
        elif token == "!":
            a = stack.pop()
            stack.append(not a)
        else:
            stack.append(evaluate_condition(entry, token))
    
    return stack[0] if stack else False

def filter_data(data, condition_str):
    tokens = tokenize_condition(condition_str)
    postfix_tokens = convert_to_postfix(tokens)

    return [entry for prefix in data.values() for entry in prefix if evaluate_postfix(entry, postfix_tokens)]

def save_filtered_data(filtered_data, output_file):
    with open(output_file, 'w') as file:
        json.dump(filtered_data, file, indent=4)
    print(f"필터링된 데이터가 '{output_file}'에 저장되었습니다.")

def main():
    file_path = input("JSON 파일 경로를 입력하세요: ")
    data = load_json(file_path)
    conditions_input = input("필터링할 조건을 입력하세요: ")
    filtered_data = filter_data(data, conditions_input)

    save_option = input("필터링된 데이터를 파일에 저장할까요? (y/n): ")
    if save_option.lower() == 'y':
        output_file = input("저장할 파일 경로를 입력하세요: ")
        save_filtered_data(filtered_data, output_file)

if __name__ == "__main__":
    main()
