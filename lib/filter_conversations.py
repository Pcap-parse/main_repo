import re
from lib.util import convert_value
from config import operator_precedence, operator_symbols, ops


class filter_conversations:
    def apply_operator(self, entry_value, operator, condition_value):
        entry_value = convert_value(entry_value)
        condition_value = convert_value(condition_value)

        if isinstance(entry_value, str) and isinstance(condition_value, str):
            entry_value = entry_value.lower()
            condition_value = condition_value.lower()

        return ops.get(operator, lambda x, y: False)(entry_value, condition_value)


    def evaluate_condition(self, entry, condition):
        match = re.match(r"(\w+)\s*(==|!=|>=|<=|>|<)\s*(.*)", condition.strip())
        if match:
            field, operator, value = match.groups()
            value = value.strip(' "')
            if field in entry:
                return self.apply_operator(entry[field], operator, value)
        return False


    def tokenize_condition(self, condition_str):
        return re.findall(r"!|\(|\)|&&|\|\||\s*\w+\s*(?:==|!=|>=|<=|>|<)\s*[^&|()]+|\w+", condition_str)


    def convert_to_postfix(self, tokens):
        output, stack = [], []
        for token in tokens:
            if token in operator_precedence:
                while (stack and stack[-1] in operator_precedence and 
                    operator_precedence[stack[-1]] > operator_precedence[token]):
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


    def evaluate_postfix(self, entry, postfix_tokens):
        stack = []
        for token in postfix_tokens:
            if token == "!":
                a = stack.pop()
                stack.append(not a)
            elif token in ["&&", "||"]:
                b, a = stack.pop(), stack.pop()
                stack.append(a and b if token == "&&" else a or b)
            else:
                stack.append(self.evaluate_condition(entry, token))
        return stack[0] if stack else False


    def normalize_logic(self, logic: str) -> str:
        return {
            "and": "&&",
            "or": "||",
        }.get(logic.lower(), logic)


    def condition_to_string(self, cond) -> str:

        if isinstance(cond, dict) and 'logic' in cond:
            logic = self.normalize_logic(cond['logic'])  # && 또는 ||
            inner = f" {logic} ".join(
                self.condition_to_string(c) for c in cond['conditions']
            )
            return f"({inner})"
        else:
            op_str = cond['operator'].lower()
            symbol = operator_symbols.get(op_str, cond['operator'])  # 매핑 없으면 원본 사용
            return f"{cond['key']} {symbol} {cond['value']}"
    
