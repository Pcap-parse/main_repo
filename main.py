import tshark_parse3
import filter_conversations_test
import sys


def parse_save(param):
    # 파라미터 수 검증
    if len(param) != 1:
        return False, 'Invalid parameter', ''
    
    pcap_filename = param[0]
    result, msg, data = tshark_parse3.start(pcap_filename)
    return result, msg, data

def parse_delete(param):
    # 파라미터 수 검증
    if len(param) != 1:
        return False, 'Invalid parameter', ''
    
    # 파라미터 정의
    parse_filename = param[0]

    result, msg, data = tshark_parse3.delete_json(parse_filename)
    return result, msg, data

def parse_read(param):
    # 파라미터 수 검증
    if len(param) != 1:
        return False, 'Invalid parameter', []
    
    # 파라미터 정의
    parse_filename = param[0]

    result, msg, data = tshark_parse3.json_search(parse_filename)
    return result, msg, data

def filter_save(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, 'Invalid parameter', []
    
    # 파라미터 정의
    parse_filename = param[0]
    filter_str = param[1]

    result, msg, data = filter_conversations_test.save_filtered_data(parse_filename, filter_str)
    return result, msg, data

def filter_delete(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, 'Invalid parameter', []
    
    # 파라미터 정의
    parse_filename = param[0]
    filter_id = param[1]

    result, msg, data = filter_conversations_test.delete_filtered_data(parse_filename, filter_id)
    return result, msg, data

def filter_read(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, 'Invalid parameter', {}
    
    # 파라미터 정의
    parse_filename = param[0]
    filter_id = param[1]

    result, msg, data = filter_conversations_test.retrieve_filtered_data(parse_filename, filter_id)
    return result, msg, data

def filter_read_all(param):
    # 파라미터 수 검증
    if len(param) != 0:
        return False, 'Invalid parameter', []

    result, msg, data = filter_conversations_test.all_filtered_data()
    return result, msg, data

def filter_apply(param):
    # 파라미터 수 검증
    if len(param) != 2:
        return False, 'Invalid parameter', {}
    
    # 파라미터 정의
    parse_filename = param[0]
    filter_str = param[1]

    result, msg, data = filter_conversations_test.filter_data(parse_filename, filter_str)
    return result, msg, data
    
def filter_modify(param):
    # 파라미터 수 검증
    if len(param) != 3:
        return False, 'Invalid parameter', []
    
    # 파라미터 정의
    parse_filename = param[0]
    filter_id = param[1]
    filter_str = param[2]

    result, msg, data = filter_conversations_test.modify_filtered_data(parse_filename, filter_id, filter_str)
    return result, msg, data

def save_pcapng(param):
    return False, 'Invalid parameter', []


def response(result, msg = '', data = ''):
    res = {
        'success': result,
        'msg': msg,
        'data': data
    }
    return res

def validate_command(command):
    if command in ['create', 'delete', 'read', 'apply', 'modify']:
        return True
    return False

def validate_target(command):
    if command in ['parse', 'filter']:
        return True
    return False

def main():
    handler = {
        'save': {
            'parse': parse_save,
            'filter': filter_save,
            'pcapng': save_pcapng
        },
        'delete': {
            'parse': parse_delete,
            'filter': filter_delete,
            'all-filter': filter_read_all
        },
        'read': {
            'parse': parse_read,
            'filter': filter_read,
        },
        'apply': {
            'filter': filter_apply,
        },
        'modify': {
            'filter': filter_modify,
        },
    }

    if len(sys.argv) < 2:
        return response(False, 'Missing arguments', '')
        
    
    command = sys.argv[1]
    target = sys.argv[2]

    if not validate_command(command):
        return response(False, 'Invalid command', '')
    
    
    if not validate_target(target):
        return response(False, 'Invalid target', '')
    

    result, msg, data = handler[command][target](sys.argv[3:])
    return response(result, msg, data)

if __name__ ==  '__main__':
    main()