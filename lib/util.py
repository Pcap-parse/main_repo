from datetime import datetime
import os
import shutil
from config import config

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

def delete_split_dir(pcap_file):
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    split_dir = os.path.join(config['split_pcaps'], base_name)

    if os.path.isdir(split_dir):
        shutil.rmtree(split_dir)
        print(f"[INFO] Deleted split directory: {split_dir}")
        return True
    else:
        print(f"[WARNING] Directory does not exist: {split_dir}")
        return False