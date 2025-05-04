import re
import operator as op

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


def filter_data(data, condition_str):
    condition_str = re.sub(r"(\'|\")", "", condition_str)
    tokens = tokenize_condition(condition_str)
    postfix_tokens = convert_to_postfix(tokens)

    filtered_result = {}
    for key, entries in data.items():
        filtered_entries = [entry for entry in entries if evaluate_postfix(entry, postfix_tokens)]
        if filtered_entries:
            filtered_result[key] = filtered_entries

    return filtered_result