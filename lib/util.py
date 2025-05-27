from datetime import datetime
import os
import shutil
import math
from functools import lru_cache
import binascii
import ipaddress
from itertools import chain
import re

def validate_command(command):
    if command in ["save", "delete", "read", "apply", "modify", "list"]:
        return True
    return False

def validate_target(command):
    if command in ["parse", "filter", "pcapng"]:
        return True
    return False

def response(result, msg = "", data = ""):
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
        print(f"[INFO] Deleted split directory: {dir_name}")
        return True
    else:
        print(f"[WARNING] Directory does not exist: {dir_name}")
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

def entry_format(name, condition, id):
    entry = {
        "name": name,
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
        # 앞뒤 또는 단독 && 제거
        text = re.sub(r'^\s*&&\s*', '', text)
        text = re.sub(r'\s*&&\s*$', '', text)
        if re.fullmatch(r'\s*&&\s*', text):
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
                    # 괄호 내부 추출 및 정리
                    inner = text[start + 1:i]
                    cleaned_inner = process(inner)
                    cleaned_inner = clean_and_edges(cleaned_inner)
                    if cleaned_inner.strip():  # 빈 문자열이 아닌 경우에만 괄호 유지
                        result += f'({cleaned_inner})'
                    # 빈 괄호는 아예 제거
                    start = i + 1
            i += 1

        result += text[start:]
        return clean_and_edges(result)

    return process(expr)