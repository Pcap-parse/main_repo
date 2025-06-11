import os
import json
import re
from lib.util import entry_format, create_uuid, find_uuid
from lib.filter_conversations import filter_conversations

base_dir = os.path.dirname(os.path.abspath(__file__))


class filter_menu:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])
        self.filter_list_dir = os.path.join(self.basedir, config['filter_list'])
        self.parse_filter_info = os.path.join(self.basedir, config['parse_list'])


    # 필터 값 입력 적용 함수
    def filter_data(self, name, condition_str):

        file_path = os.path.join(self.result_dir, name)
        if not os.path.exists(file_path):
            return False, "Conversations File Not Found", {}

        with open(file_path, 'r') as file:
            data = json.load(file)

        condition_str = condition_str
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
    def save_filtered_data(self, parse_uuid, filter_name, condition):
        data = []
        name = find_uuid(self.parse_filter_info, parse_uuid, "name")
        # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
        # else:
        #     return False, "File Not Found", ""

        # 동일한 name + filter 조건이 이미 존재하면 추가하지 않음
        for item in data:
            if item.get("name") == name and item.get("filter") == condition:
                return False, "Existed data", data

        new_id = create_uuid()

        # 새 항목 추가
        new_entry = entry_format(name, filter_name, condition, new_id)
        data.append(new_entry)

        # 파일에 저장
        with open(self.filter_list_dir, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return True, "Success", new_entry


    # 필터 수정 api
    def modify_filtered_data(self, filter_uuid, filter_name, filter):
        # 파일이 존재하면 기존 내용 불러오기, 없으면 빈 리스트로 시작
        entry = {}
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            return False, "File Not Found", ""

        for i, item in enumerate(data):
            if item.get("id") == filter_uuid:
                data[i]["filter_name"] = filter_name
                data[i]["filter"] = filter
                entry = item
                break
        else:
            return False, "Entry Not Found", ""

        # 파일에 저장
        with open(self.filter_list_dir, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return True, "Success", entry


    # 명세 조회 함수
    def retrieve_filtered_data(self, filter_uuid):
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)

            filter_data = None
            for entry in data:
                if entry.get("id") == filter_uuid:
                    filter_data = entry
                    break

            if filter_data is None:
                return False, "Entry Not Found", {}

            # feature_id 추가
            feature_id = None
            feature_name = filter_data.get("name")

            if os.path.exists(self.parse_filter_info):
                with open(self.parse_filter_info, 'r', encoding='utf-8') as pf:
                    parse_info = json.load(pf)
                    matched_feature = next((f for f in parse_info if f.get("name") == feature_name), None)
                    if matched_feature:
                        feature_id = matched_feature.get("id")

            filter_data["feature_id"] = feature_id

            return True, "Success", filter_data

        else:
            return False, "File Not Found", {}


    def all_filtered_data(self, feature_uuid=None):
        with open(self.parse_filter_info, 'r', encoding='utf-8') as pf:
            parse_info = json.load(pf)

        feature_name = None
        if feature_uuid:
            feature_name = find_uuid(self.parse_filter_info, feature_uuid, "name")
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)

                if feature_name:
                    filtered = [item for item in data if item.get("name") == feature_name]

                    # filtered에 feature_id 추가
                    for item in filtered:
                        item["feature_id"] = feature_uuid

                    return True, "Success", filtered
                else:
                    for item in data:
                        matching_feature = next(
                            (f for f in parse_info if f.get("name") == item.get("name")), None
                        )
                        item["feature_id"] = matching_feature.get("id") if matching_feature else None

                    return True, "Success", data
        else:
            return False, "File Not Found", []


    # 명세 삭제 함수
    def delete_filtered_data(self, filter_uuid):
        if not os.path.exists(self.filter_list_dir):
            return False, "File Not Found", "Failed"

        with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
            data = json.load(f)

        deleted_name = None
        updated_data = []

        for entry in data:
            if entry.get("id") == filter_uuid:
                deleted_name = entry.get("filter_name")
            else:
                updated_data.append(entry)

        if deleted_name is None:
            return False, "Entry Not Found", "Failed"

        with open(self.filter_list_dir, 'w', encoding='utf-8') as f:
            json.dump(updated_data, f, indent=4, ensure_ascii=False)

        return True, "Success", f"Successfully deleted {deleted_name}"