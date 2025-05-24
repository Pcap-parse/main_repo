import os
import json
import re
from lib.util import entry_format
from lib.filter_conversations import filter_conversations

base_dir = os.path.dirname(os.path.abspath(__file__))

class filter_menu:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])
        self.filter_list_dir = os.path.join(self.basedir, config['filter_list'])
    
    
    # 필터 값 입력 적용 함수
    def filter_data(self, name, condition_str):

        file_path = os.path.join(self.result_dir, name)
        if not os.path.exists(file_path):
            return False, "Conversations File Not Found", {}

        with open(file_path, 'r') as file:
            data = json.load(file)
            
        condition_str = re.sub(r"(\'|\")", "", condition_str)
        tokens = filter_conversations().tokenize_condition(condition_str)
        postfix_tokens = filter_conversations().convert_to_postfix(tokens)

        filtered_result = {}
        for key, entries in data.items():
            filtered_entries = [entry for entry in entries if filter_conversations().evaluate_postfix(entry, postfix_tokens)]
            if filtered_entries:
                filtered_result[key] = filtered_entries

        result = {
            "filter": condition_str,
            "result": filtered_result
        }

        return True, "Success", result


    # 필터 적용 결과 저장 함수
    def save_filtered_data(self, name, condition):
        data = []

        # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
        # else:
        #     return False, "File Not Found", ""

        # 동일한 name + filter 조건이 이미 존재하면 추가하지 않음
        for item in data:
            if item.get("name") == name and item.get("filter") == condition:
                return False, "Existed data", data

        # 같은 name 중 가장 큰 id 찾기
        max_id = max(
            [item.get("id", 0) for item in data if item.get("name") == name],
            default=0
        )
        new_id = max_id + 1

        # 새 항목 추가
        new_entry = entry_format(name, condition, new_id)
        data.append(new_entry)

        # 파일에 저장
        with open(self.filter_list_dir , 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return True, "Success", data


    # 필터 수정 api
    def modify_filtered_data(self, name, id, filter):
        new_entry = entry_format(name, filter, id)

        # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            return False, "File Not Found", ""

        for i, item in enumerate(data):
            if item.get("name") == new_entry["name"] and item.get("id") == new_entry["id"]:
                data[i] = new_entry
                break
        else:
            return False, "Entry Not Found", ""
        
        # 파일에 저장
        with open(self.filter_list_dir , 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return True, "Success", data


    # 명세 조회 함수
    def retrieve_filtered_data(self, file_name, id):
        print(file_name)
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
                data = json.load(f)

            condition = None
            for entry in data:
                if entry.get("name") == file_name and entry.get("id") == id:
                    condition = entry.get("filter")
                    break
            if condition is None:
                return False, "Entry Not Found", {}
            # print(condition)
            _, _, data = self.filter_data(file_name, condition)
            return True, "Success", data
        
        else:
            return False, "File Not Found", {}
        

    def all_filtered_data(self):
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
                data = json.load(f)
                return True, "Success", data
        else:
            return False, "File Not Found", []


    # 명세 삭제 함수
    def delete_filtered_data(self, file_name, id):
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
                data = json.load(f)

            def is_match(entry):
                return entry.get("name") == file_name and entry.get("id") == id

            if not any(is_match(entry) for entry in data):
                return False, "Entry Not Found", []

            updated_data = [entry for entry in data if not is_match(entry)]

            with open(self.filter_list_dir, 'w', encoding='utf-8') as f:
                json.dump(updated_data, f, indent=4, ensure_ascii=False)

            return True, "Success", updated_data
        
        else:
            return False, "File Not Found", []
