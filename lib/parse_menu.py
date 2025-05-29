import json
import os
from lib.util import get_time, delete_split_dir, create_uuid, find_uuid
from lib.parse_pcapng import parse_pcapng

class parse_menu:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.parse_json = os.path.join(self.basedir, config['parse_result_dir'])
        self.parse_filter_info = os.path.join(self.basedir, config['parse_list'])
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.filter_list_dir = os.path.join(self.basedir, config['filter_list'])


    def start(self, file_name):
        start = get_time()
        result, msg, data = parse_pcapng(self.config).analyze_pcap_file(file_name)
        if not result:
            return result, msg, data
        end = get_time()

        base_filename = os.path.basename(file_name)
        name_only = os.path.splitext(base_filename)[0]
        json_name = f"{name_only}.json"
        new_data = self.add_entry(json_name, file_name)

        dir_path = os.path.join(self.split_dir, name_only)
        delete_split_dir(dir_path)

        print(f'startTime : {start.strftime("%H:%M:%S")}')
        print(f'endTime : {end.strftime("%H:%M:%S")}')

        return result, msg, new_data
    

    # json 조회
    def load_json_list(self):
        if not os.path.exists(self.parse_filter_info):
            return False, "File Not Found", ""
        with open(self.parse_filter_info, "r", encoding="utf-8") as f:
            return True, "success", self.flatten_results(json.load(f))
            
        
    def save_json_list(self, data):
        with open(self.parse_filter_info, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


    # json append
    def add_entry(self, name, file_path):
        check, msg, data = self.load_json_list()
        data = data or []
        new_entry = {}
        

        # name을 기준으로 기존 항목이 있는지 확인
        found = False
        for entry in data:
            if entry["feature_name"] == name:
                entry["timestamp"] = get_time().isoformat()
                new_entry = entry
                found = True
                break

        # 없으면 새로 추가
        if not found:
            new_entry = {
                "feature_name": name,
                "pcap_path": file_path,
                "uuid": create_uuid(),
                "timestamp": get_time().isoformat()
            }
            data.append(new_entry)

        self.save_json_list(data)
        return new_entry["uuid"]


    def flatten_results(self, result):
        flat = []
        for item in result:
            if isinstance(item, list):
                flat.extend(item)
            else:
                flat.append(item)
        return flat


    def load_json(self, file_uuid):
        file_name = find_uuid(self.parse_filter_info, file_uuid, "feature_name")
        file_path = os.path.join(self.parse_json, file_name)
        if not os.path.exists(file_path):
            return False, "File Not Found", ""
        with open(file_path, "r", encoding="utf-8") as f:
            return True, "success", json.load(f)
        

    def delete_json(self, file_uuid):
        target_name = find_uuid(self.parse_filter_info, file_uuid, "feature_name")
        with open(self.parse_filter_info, "r", encoding="utf-8") as f:
            data = json.load(f)

        target_file_path = os.path.join(self.parse_json, target_name)
        if os.path.exists(target_file_path):
            os.remove(target_file_path)
            original_len = len(data)
            data = [entry for entry in data if entry.get("feature_name") != target_name]
            removed_count = original_len - len(data)
            if removed_count > 0:
                with open(self.parse_filter_info, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                with open(self.filter_list_dir, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    filtered_data = [item for item in data if item.get("feature_name") != target_name]
                with open(self.filter_list_dir, "w", encoding="utf-8") as f:
                    json.dump(filtered_data, f, indent=4, ensure_ascii=False)
                    
            with open(self.parse_filter_info, "r", encoding="utf-8") as f:
                list_data = self.flatten_results(json.load(f))
            return True, "success", list_data
        else:
            return False, "File Not Found", ""


    # json 파일 존재 확인
    def check_info(self):
        if not os.path.exists(self.parse_json):
            return "not create json"
        else:
            return "success"


    def json_search(self, target_name):
        target_json = f"{self.parse_json}{target_name}"
        try:
            with open(target_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            return True, "success", data
        except FileNotFoundError:
            return False, "File Not Found", ""
    