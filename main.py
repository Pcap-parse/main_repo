import sys
from lib.util import validate_command, validate_target, response
from lib.parse_menu import parse_menu
from lib.filter_menu import filter_menu
from lib.extract_pcapng import extract_pcapng
from config import config

def parse_save(param):
    # 파라미터 수 검증
    if len(param) != 1:
        return False, "Invalid parameter", ""
    
    pcap_filename = f"{param[0]}"
    result, msg, data = parse_menu(config).start(pcap_filename)

    return result, msg, data


def parse_delete(param):
    # 파라미터 수 검증
    if len(param) != 1:
        return False, "Invalid parameter", ""
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"

    result, msg, data = parse_menu(config).delete_json(parse_filename)
    return result, msg, data


def parse_read_list(param):
    if len(param) != 0:
        return False, "Invalid parameter", ""
    
    result, msg, data = parse_menu(config).load_json_list()
    return result, msg, data


def parse_read(param):
    if len(param) != 1:
        return False, "Invalid parameter", ""
    file_name = param[0]
    
    result, msg, data = parse_menu(config).load_json(file_name)
    return result, msg, data


def filter_save(param):
    # 파라미터 수 검증
    if len(param) != 4:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_name = param[1]
    filter_str = param[2]
    entropy_str = param[3] if param[3] else ""

    result, msg, data = filter_menu(config).save_filtered_data(parse_filename, filter_name, filter_str, entropy_str)
    return result, msg, data


def filter_delete(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])

    result, msg, data = filter_menu(config).delete_filtered_data(parse_filename, filter_id)
    return result, msg, data


def filter_read(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", {}
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])

    result, msg, data = filter_menu(config).retrieve_filtered_data(parse_filename, filter_id)
    return result, msg, data


def filter_read_all(param):
    # 파라미터 수 검증
    if len(param) != 0:
        return False, "Invalid parameter", []

    result, msg, data = filter_menu(config).all_filtered_data()
    return result, msg, data


def filter_apply(param):
    # 파라미터 수 검증
    if len(param) != 3:
        return False, "Invalid parameter", {}
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_str = param[1]
    entropy_str = param[2]

    result, msg, data = filter_menu(config).filter_data(parse_filename, filter_str, entropy_str)
    return result, msg, data
    

def filter_modify(param):
    # 파라미터 수 검증
    if len(param) != 4:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])
    filter_str = param[2]
    entropy_str = param[3]

    result, msg, data = filter_menu(config).modify_filtered_data(parse_filename, filter_id, filter_str, entropy_str)
    return result, msg, data


def save_pcapng(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", []

    # 파라미터 정의
    parse_filename = f"{param[0]}"
    ids_and_ops = param[1]

    result, msg, data = extract_pcapng(config).start(parse_filename, ids_and_ops)
    return result, msg, data


def pcapng_read_list(param):
    if len(param) != 0:
        return False, "Invalid parameter", []
    
    list_filename = "extract_list.json" # pcapng_list 파일

    result, msg, data = extract_pcapng(config).load_json(list_filename)
    return result, msg, data

def main():
    handler = {
        "save": {
            "parse": parse_save,
            "filter": filter_save,
            "pcapng": save_pcapng
        },
        "delete": {
            "parse": parse_delete,
            "filter": filter_delete,
        },
        "read": {
            "parse": parse_read,
            "filter": filter_read,
        },
        "list": {
            "parse": parse_read_list,
            "filter": filter_read_all,
            "pcapng": pcapng_read_list
        },
        "apply": {
            "filter": filter_apply,
        },
        "modify": {
            "filter": filter_modify,
        },
    }

    if len(sys.argv) < 2:
        return response(False, "Missing arguments", "")
        
    
    command = sys.argv[1]
    target = sys.argv[2]

    if not validate_command(command):
        return response(False, "Invalid command", "")
    
    
    if not validate_target(target):
        return response(False, "Invalid target", "")
    

    result, msg, data = handler[command][target](sys.argv[3:])
    return response(result, msg, data)

if __name__ ==  "__main__":
    result = main()
    print(result)