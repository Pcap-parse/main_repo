import os
import json
import re
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from lib.wireshark_api import wireshark_api
from lib.util import delete_split_dir, get_time, format_ip_field, calculate_entropy, hex_to_byte, clean_logical_operators, apply_logical_ops, extract_num_and_op
from config import ops, filter_pkt_default


class extract_pcapng:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.ext_pcapng = os.path.join(self.basedir, config['filtered_pcapng_dir'])
        self.filter_list_dir = os.path.join(self.basedir, config['filter_list'])
        self.pcap_file = os.path.join(self.basedir, config['pcapng_data_dir'])
        self.filtered_list = os.path.join(self.basedir, config["filtered_list"])
        self.entropy_conditions = []


    def ext_files(self, pcap_file, combined_pairs, operators):
        frame_sets = []  # 각 쌍에 대한 frame 결과 집합을 저장

        for filter_pkt, entropy_filter in combined_pairs:
            results = wireshark_api(self.config).extract_pcap(pcap_file, filter_pkt)
            lines = results.splitlines()

            frame_set = set()

            for line in lines:
                fields = line.split('\t')
                if len(fields) != 3:
                    continue

                frame_number = fields[0]
                payload = fields[1] if fields[1] else fields[2]
                satisfied = True

                if payload:
                    payload = hex_to_byte(payload)
                    payload_entropy = calculate_entropy(payload)
                    satisfied = self._check_conditions(payload_entropy, entropy_filter)

                if satisfied:
                    frame_set.add(frame_number)

            frame_sets.append(frame_set)

        # 연산자 적용
        res_set = apply_logical_ops(frame_sets, operators)

        # 최종 결과 리스트
        res_list = list(res_set)

        if res_list:
            results_list = wireshark_api(self.config).extract_matched_frames(pcap_file, res_list)
        else:
            results_list = []  # 혹은 빈 리스트 등 적절한 기본값

        return results_list


    def _check_conditions(self, entropy_val, entropy_filter):
        try:
            if not entropy_filter:
                return True

            def eval_condition(cond, variables):
                pattern = r'^(entropy)\s*(==|!=|>=|<=|>|<)\s*([\d\.]+)$'
                m = re.match(pattern.strip(), cond.strip())
                if not m:
                    return False

                var_name, operator_str, value_str = m.groups()
                value = float(value_str)
                actual = variables[var_name]

                if operator_str not in ops:
                    return False

                return ops[operator_str](actual, value)

            for cond in entropy_filter:
                if not eval_condition(cond, {'entropy': entropy_val}):
                    return False

            return True

        except Exception as e:
            print(f"Error in _check_conditions: {e}")
            return False
    

    # 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
    def analyze_pcap_file(self, pcap_file, filter_pkt, file_name, operators, ids_and_ops):
        print(f"Splitting {pcap_file}...")

        split_pcaps = wireshark_api(self.config).split_pcap(pcap_file)

        if not split_pcaps:
            print(f"분할된 파일이 없습니다: {pcap_file}")
            delete_split_dir(pcap_file)
            return False, "No Splitted File", ""
        
        base_name= os.path.splitext(os.path.basename(pcap_file))[0]
        args = [(pcap, filter_pkt, operators) for pcap in split_pcaps]
        results_list = []

        try:
            # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
            with Pool(processes=cpu_count()) as pool:
                results_list = pool.starmap(self.ext_files, args)

            # 필터링된 결과 파일들을 병합
            merged_output = os.path.splitext(os.path.basename(pcap_file))[0]
            idx = 1
            if os.path.exists(self.filtered_list):
                with open(self.filtered_list , 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    if item.get('name') == f"{merged_output}_filtered_{idx}.pcapng":
                        idx = item.get('id') + 1

            output_file = wireshark_api(self.config).merge_pcaps(results_list, merged_output, idx)
            
            entry = {
                "name": os.path.basename(output_file),
                "file_path": output_file,
                "feature_name": file_name,
                "timestamp": get_time().isoformat(),
                "filter_ids": ids_and_ops,
                "id": idx
            }
            if os.path.exists(self.filtered_list):
                # JSON 파일 열고 기존 데이터에 entry 추가
                with open(self.filtered_list, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = []

                # entry 추가
                data.append(entry)

                # 다시 저장
                with open(self.filtered_list, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                # 파일이 없으면 entry를 리스트로 감싸서 생성
                with open(self.filtered_list, 'w', encoding='utf-8') as f:
                    json.dump([entry], f, indent=2, ensure_ascii=False)

            return True, "success", f"{output_file}"

        except Exception as e:
            print(f"[ERROR] 분석 중 오류 발생: {e}")
            return False, str(e), ""

        finally:
            base_name= os.path.splitext(os.path.basename(pcap_file))[0]
            delete_split_dir(os.path.join(self.ext_pcapng, "split"))
            delete_split_dir(os.path.join(self.split_dir, base_name))


    def convert_to_wireshark_filter(self, expression: str) -> str:
        # 괄호 제거 전 ! 연산자 위치 파악
        negation = expression.strip().startswith('!')
        if re.match(r'^\s*!\s*\(.*\)', expression):
            expression = expression.strip()[1:].strip()
            
            # 첫 괄호 쌍만 제거
            if expression.startswith('(') and expression.endswith(')'):
                # 괄호 짝이 맞는 가장 바깥쪽 괄호 한 쌍만 제거
                depth = 0
                for i, c in enumerate(expression):
                    if c == '(':
                        depth += 1
                    elif c == ')':
                        depth -= 1
                    if depth == 0 and i == len(expression) - 1:
                        # 올바른 괄호 쌍이 맨 앞과 맨 뒤에 있는 경우만 제거
                        expression = expression[1:-1].strip()
                        break

        def extract_special_conditions(match):
            key, op, value = match.groups()
            value = value.strip('"')
            condition_str = f"{key} {op} {value}"
            if key == "entropy":
                self.entropy_conditions.append(condition_str)
            return ""

        special_cond_pattern = re.compile(r'\b(entropy)\s*(==|!=|<=|>=|<|>)\s*([0-9.]+)')
        expression = special_cond_pattern.sub(extract_special_conditions, expression)

        # 나머지 조건 변환
        cond_pattern = re.compile(r'(\w+)\s*(==|!=|<=|>=|<|>)\s*("[^"]*"|[^\s&|)]+)')
        def convert_condition(match):
            key, op, value = match.groups()
            value = value.strip('"')
            if key in ["address_a", "address_b"]:
                ip_field = format_ip_field(value)
                return f"{ip_field} {op} {value}"
            elif key in ["port_a", "port_b"]:
                return f"(tcp.port {op} {value} || udp.port {op} {value})"
            elif key in ["bytes"]:
                return f"(tcp.len {op} {value} || udp.length {op} {str(int(value)+8)})"
            elif key == "protocol" and op == "==":
                return f"_ws.col.protocol contains {value}"
            elif key == "packets":
                return ""
            else:
                return f"{key} {op} {value}"

        result = cond_pattern.sub(convert_condition, expression)
        result = clean_logical_operators(result)

        # 앞에 ! 다시 붙이기
        if negation and result:
            result = f"!({result})"

        return result

    def start(self, file_name, ids_and_ops):
        file_json = f"{file_name}.json"
        file_pcap = f"{file_name}.pcapng"
        ids, operators = extract_num_and_op(ids_and_ops)
        
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            return False, "File Not Found", ""

        matched_filters = []
        combined_pairs = []

        for item in data:
            if item.get("name") == file_json and item.get("id") in ids:
                if "filter" in item:
                    filters = item["filter"]

                    # 문자열이면 리스트로 변환
                    if isinstance(filters, str):
                        filters = [filters]

                    for filt in filters:
                        self.entropy_conditions = []
                        ws_filter = self.convert_to_wireshark_filter(filt)
                        if ws_filter:
                             matched_filters.append((ws_filter.strip(), list(self.entropy_conditions)))

        if not matched_filters:
            return False, "No Matching Filters Found", ""

        for filt, entropy in matched_filters:
            # 각 필터를 base_filter와 결합
            filter_pkt = filter_pkt_default + " &&" + filt

            # (filter_pkt, entropy) 쌍을 리스트에 저장
            combined_pairs.append((filter_pkt, entropy))

        # print(combined_pairs)
        input_folder = os.path.join(self.pcap_file, file_pcap)
        start = get_time()
        result, msg, data = self.analyze_pcap_file(input_folder, combined_pairs, file_json, operators, ids_and_ops)
        end = get_time()

        print(f'시작시간 : {start.strftime("%H:%M:%S")}')
        print(f'종료시간 : {end.strftime("%H:%M:%S")}')

        return result, msg, data

    def load_json(self, file_name):
        file_path = os.path.join(self.basedir, file_name)
        if not os.path.exists(file_path):
            return False, "File Not Found", ""
        with open(file_path, "r", encoding="utf-8") as f:
            return True, "success", json.load(f)