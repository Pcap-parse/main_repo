from lib.filter_conversations import filter_conversations
import sys
from lib.util import validate_command, validate_target, response, delete_split_dir
from lib.parse_menu import parse_menu
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


def parse_read(param):
    if len(param) != 0:
        return False, "Invalid parameter", ""
    
    result, msg, data = parse_menu(config).load_json_list()
    return result, msg, data


def filter_save(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_str = param[1]

    result, msg, data = filter_conversations.save_filtered_data(parse_filename, filter_str)
    return result, msg, data


def filter_delete(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])

    result, msg, data = filter_conversations.delete_filtered_data(parse_filename, filter_id)
    return result, msg, data


def filter_read(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", {}
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])

    result, msg, data = filter_conversations.retrieve_filtered_data(parse_filename, filter_id)
    return result, msg, data


def filter_read_all(param):
    # 파라미터 수 검증
    if len(param) != 0:
        return False, "Invalid parameter", []

    result, msg, data = filter_conversations.all_filtered_data()
    return result, msg, data


def filter_apply(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, "Invalid parameter", {}
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_str = param[1]

    result, msg, data = filter_conversations.filter_data(parse_filename, filter_str)
    return result, msg, data
    

def filter_modify(param):
    # 파라미터 수 검증
    if len(param) != 3:
        return False, "Invalid parameter", []
    
    # 파라미터 정의
    parse_filename = f"{param[0]}.json"
    filter_id = int(param[1])
    filter_str = param[2]

    result, msg, data = filter_conversations.modify_filtered_data(parse_filename, filter_id, filter_str)
    return result, msg, data


def save_pcapng(param):
    delete_split_dir(param[0])
    return False, "Invalid parameter", []


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
            "all-filter": filter_read_all
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
    print(main())