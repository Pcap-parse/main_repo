from datetime import datetime
import os
import shutil
import math
from functools import lru_cache
import binascii
import ipaddress
from itertools import chain
import re
import uuid
import json


def validate_command(command):
    if command in ["save", "delete", "read", "apply", "modify", "list"]:
        return True
    return False


def validate_target(command):
    if command in ["parse", "filter", "pcapng"]:
        return True
    return False


def response(result, msg="", data=""):
    res = {
        "success": result,
        "msg": msg,
        "data": data
    }
    return res


def get_time():
    return datetime.now()


def delete_split_dir(dir_name):
    if os.path.isdir(dir_name):
        shutil.rmtree(dir_name)
        # print(f"[INFO] Deleted split directory: {dir_name}")
        return True
    else:
        # print(f"[WARNING] Directory does not exist: {dir_name}")
        return False


def normalize_protocol(proto):
    if '/' in proto:
        proto = proto.split('/')[0]
    return proto


@lru_cache(maxsize=256)
def fast_log2(count: int, length: int) -> float:
    return math.log2(count / length)


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count > 0:
            prob = count / length
            entropy -= prob * fast_log2(count, length)

    return entropy


def hex_to_byte(payload):
    return binascii.unhexlify(payload)


def convert_value(value):
    if isinstance(value, str):
        if value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            return value
    return value


def entry_format(name, filter_name, condition, id):
    entry = {
        "name": name,
        "filter_name": filter_name,
        "filter": condition,
        "timestamp": get_time().isoformat(),
        "id": id
    }
    return entry


def format_ip_field(value: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(value)
        if ip_obj.version == 4:
            return "ip.addr"
        else:
            return "ipv6.addr"
    except ValueError:
        return ""  # IP가 아니면 빈 문자열 반환


def change_list(pcap_list):
    if not isinstance(pcap_list, list):
        raise TypeError(f"Expected list of lists, got {type(pcap_list).__name__}")
    return list(chain.from_iterable(pcap_list))


def clean_logical_operators(expr):
    def clean_and_edges(text):
        # 앞뒤 또는 단독 &&, || 제거
        text = re.sub(r'^\s*(&&|\|\|)\s*', '', text)
        text = re.sub(r'\s*(&&|\|\|)\s*$', '', text)
        if re.fullmatch(r'\s*(&&|\|\|)\s*', text):
            return ''
        return text

    def process(text):
        result = ''
        stack = []
        start = 0

        i = 0
        while i < len(text):
            if text[i] == '(':
                if not stack:
                    result += text[start:i]
                    start = i
                stack.append(i)
            elif text[i] == ')':
                stack.pop()
                if not stack:
                    inner = text[start + 1:i]
                    cleaned_inner = process(inner)
                    cleaned_inner = clean_and_edges(cleaned_inner)

                    # 빈 괄호 처리
                    if cleaned_inner.strip():
                        result += f'({cleaned_inner})'
                    else:
                        # !() 패턴 확인
                        if result.rstrip().endswith('!'):
                            # !와 빈 괄호 모두 제거
                            result = result.rstrip()[:-1]
                        # 괄호는 아예 제거
                    start = i + 1
            i += 1

        result += text[start:]
        return clean_and_edges(result)

    return process(expr)


def extract_num_and_op(s):
    # 숫자만 추출 (정수)
    uuids = re.findall(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', s)
    # 연산자만 추출 (&&, ||)
    operators = re.findall(r'&&|\|\|', s)
    return uuids, operators


def apply_logical_ops(sets, operators):
    if not sets:
        return []

    result = sets[0].copy()

    for i, op in enumerate(operators):
        next_set = sets[i + 1]
        if op == '&&':
            result = result & next_set  # 교집합
        elif op == '||':
            result = result | next_set  # 합집합

    return list(result)


def create_uuid():
    return str(uuid.uuid4())


def find_uuid(file_path, target_uuid, target):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    target_data = ""
    for item in data:
        if isinstance(item, dict) and item.get("id") == target_uuid:
            target_data = item.get(target)
            break

    return target_data

def cyber_path(base_dir):
    current_path = base_dir
    while not current_path.endswith("cyber"):
        parent = os.path.dirname(current_path)
        if parent == current_path:  # 루트 디렉토리에 도달
            raise Exception("No such Directory 'cyber'")
        current_path = parent
        
    return current_path