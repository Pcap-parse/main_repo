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
    if command in ["save", "delete", "read", "apply", "modify"]:
        return True
    return False

def validate_target(command):
    if command in ["parse", "filter","all-filter","pcapng", "parse-list"]:
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
    while True:
        # 중복된 연산자 1개로 축소
        new_expr = re.sub(r'(\&\&|\|\|)\s*(\&\&|\|\|)+', r'\1', expr)
        # 맨 앞 연산자 제거
        new_expr = re.sub(r'^\s*(\&\&|\|\|)\s*', '', new_expr)
        # 맨 뒤 연산자 제거 (괄호와 공백 제외외 처리)
        new_expr = re.sub(r'(\&\&|\|\|)\s*$', '', new_expr)
        # 괄호 바로 앞 연산자 제거 (ex: ... && ) )
        new_expr = re.sub(r'\(\s*(?:\&\&|\|\|)(?:\s*(?:\&\&|\|\|))*\s*\)', '', new_expr)
        # 빈 괄호 제거
        new_expr = re.sub(r'\(\s*\)', '', new_expr)
        
        if new_expr == expr:
            break
        expr = new_expr

    # 연산자만 남았을 경우 빈 문자열로
    if expr.strip() in ['&&', '||']:
        expr = ''

    return expr