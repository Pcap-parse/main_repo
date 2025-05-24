import os
import json
import re
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from lib.wireshark_api import wireshark_api
from lib.util import delete_split_dir, get_time, format_ip_field, calculate_entropy, hex_to_byte, clean_logical_operators
from config import ops


class extract_pcapng:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.ext_pcapng = os.path.join(self.basedir, config['filtered_pcapng_dir'])
        self.filter_list_dir = os.path.join(self.basedir, config['filter_list'])
        self.pcap_file = os.path.join(self.basedir, config['pcapng_data_dir'])
        self.entropy_conditions = []
        self.bytes_conditions = []


    def ext_files(self, pcap_file, filter_pkt):
        results = wireshark_api(self.config).extract_pcap(pcap_file, filter_pkt)
        lines = results.splitlines()
        matched_frames = []
        results_list = []

        for line in lines:
            fields = line.split('\t')  # 각 필드를 탭으로 분리
            if len(fields) != 3:
                continue
            frame_number = fields[0]
            payload = fields[1] if fields[1] else fields[2]
            satisfied = True

            if payload:
                payload = hex_to_byte(payload)
                payload_len = len(payload)
                payload_entropy = calculate_entropy(payload)
                satisfied = self._check_conditions(payload_entropy, payload_len)

            if satisfied:
                matched_frames.append(frame_number)

        # print(len(matched_frames))
        results_list = wireshark_api(self.config).extract_matched_frames(pcap_file, matched_frames)

        return results_list


    def _check_conditions(self, entropy_val, byte_len):
        try:
            if not self.entropy_conditions and not self.bytes_conditions:
                return True

            def eval_condition(cond, variables):
                pattern = r'^(entropy|bytes)\s*(==|!=|>=|<=|>|<)\s*([\d\.]+)$'
                m = re.match(pattern, cond.strip())
                if not m:
                    # 조건 형식이 맞지 않으면 False 처리
                    return False
                
                var_name, operator_str, value_str = m.groups()
                value = float(value_str)
                actual = variables[var_name]
                
                if operator_str not in ops:
                    return False
                
                return ops[operator_str](actual, value)
            
            for cond in self.entropy_conditions:
                if not eval_condition(cond, {'entropy': entropy_val, 'bytes': byte_len}):
                    return False
            
            for cond in self.bytes_conditions:
                if not eval_condition(cond, {'entropy': entropy_val, 'bytes': byte_len}):
                    return False
            
            return True

        except Exception as e:
            print(f"Error in _check_conditions: {e}")
            return False
    

    # 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
    def analyze_pcap_file(self, pcap_file, filter_pkt):
        print(f"Splitting {pcap_file}...")

        split_pcaps = wireshark_api(self.config).split_pcap(pcap_file)

        if not split_pcaps:
            print(f"분할된 파일이 없습니다: {pcap_file}")
            delete_split_dir(pcap_file)
            return False, "No Splitted File", ""
        
        base_name= os.path.splitext(os.path.basename(pcap_file))[0]
        args = [(pcap, filter_pkt) for pcap in split_pcaps]
        results_list = []

        try:
            # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
            with Pool(processes=cpu_count()) as pool:
                results_list = pool.starmap(self.ext_files, args)

            # 필터링된 결과 파일들을 병합
            merged_output = os.path.splitext(os.path.basename(pcap_file))[0]
            wireshark_api(self.config).merge_pcaps(results_list, merged_output)
            return True, "success", ""

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
        if negation:
            expression = expression.strip()[1:].strip()
            # 괄호 제거
            expression = expression.replace('(', '').replace(')', '')

        def extract_special_conditions(match):
            key, op, value = match.groups()
            value = value.strip('"')
            condition_str = f"{key} {op} {value}"
            if key == "entropy":
                self.entropy_conditions.append(condition_str)
            elif key == "bytes":
                self.bytes_conditions.append(condition_str)
            return ""

        special_cond_pattern = re.compile(r'\b(entropy|bytes)\s*(==|!=|<=|>=|<|>)\s*("[^"]*"|[^\s\)]+)')
        expression = special_cond_pattern.sub(extract_special_conditions, expression)

        # 나머지 조건 변환
        cond_pattern = re.compile(r'(\w+)\s*(==|!=|<=|>=|<|>)\s*("[^"]*"|[^\s\)]+)')
        def convert_condition(match):
            key, op, value = match.groups()
            value = value.strip('"')
            if key in ["address_a", "address_b"]:
                ip_field = format_ip_field(value)
                return f"{ip_field} {op} {value}"
            elif key in ["port_a", "port_b"]:
                return f"(tcp.port {op} {value} || udp.port {op} {value})"
            elif key == "protocol" and op == "==":
                return f"_ws.col.protocol contains {value}"
            elif key == "packets":
                return ""
            else:
                return f"{key} {op} {value}"

        result = cond_pattern.sub(convert_condition, expression)
        print(result)
        result = clean_logical_operators(result)

        # 앞에 ! 다시 붙이기
        if negation and result:
            result = f"!({result})"

        return result

    def start(self, file_name, ids):
        file_json = f"{file_name}.json"
        file_pcap = f"{file_name}.pcapng"
        if os.path.exists(self.filter_list_dir):
            with open(self.filter_list_dir, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            return False, "File Not Found", ""

        matched_filters = []

        for item in data:
            if item.get("name") == file_json and item.get("id") in ids:
                if "filter" in item:
                    filters = item["filter"]

                    # 문자열이면 리스트로 변환
                    if isinstance(filters, str):
                        filters = [filters]

                    for filt in filters:
                        ws_filter = self.convert_to_wireshark_filter(filt)
                        if ws_filter:
                            matched_filters.append(ws_filter)

        if not matched_filters:
            return False, "No Matching Filters Found", ""
        
        combined_filter = " && ".join(f"{f}" for f in matched_filters)
        print(combined_filter)

        filter_pkt = (
            "!tcp.analysis.retransmission && "
            "!tcp.analysis.fast_retransmission && "
            "!tcp.analysis.spurious_retransmission && "
            "!_ws.malformed && "
            "(tcp.srcport || udp.srcport) &&"
            f"{combined_filter}"
        )

        input_folder = os.path.join(self.pcap_file, file_pcap)
        start = get_time()
        result, msg, data = self.analyze_pcap_file(input_folder, filter_pkt)
        end = get_time()

        print(f'시작시간 : {start.strftime("%H:%M:%S")}')
        print(f'종료시간 : {end.strftime("%H:%M:%S")}')

        return result, msg, data
