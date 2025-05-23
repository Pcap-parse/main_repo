from datetime import datetime
import os
import shutil
import math
from functools import lru_cache
import binascii

def validate_command(command):
    if command in ["save", "delete", "read", "apply", "modify"]:
        return True
    return False

def validate_target(command):
    if command in ["parse", "filter","all-filter","pcapng"]:
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
