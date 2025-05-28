import json
import os
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from lib.util import normalize_protocol, calculate_entropy, hex_to_byte
from lib.wireshark_api import wireshark_api
from config import filter_pkt_default


class parse_pcapng:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])


    # tshark 출력 결과를 JSON 데이터로 변환
    def parse_conv(self, tshark_output):
        data = {
            "tcp": [],
            "udp": []
        }

        for line in tshark_output.splitlines():
            fields = line.split("\t")
            if len(fields) != 11:
                continue
            
            src_ip = fields[0] if fields[0] else fields[1]
            dst_ip = fields[4] if fields[4] else fields[5]

            tcp_src, udp_src = fields[2], fields[3]
            tcp_dst, udp_dst = fields[6], fields[7]
            tcp_payload, udp_payload = fields[8], fields[9]
            payload_len = 0
            if tcp_src and tcp_dst:
                src_port, dst_port = tcp_src, tcp_dst
                layer="tcp"
                binary_data = hex_to_byte(tcp_payload)
                payload_len = len(binary_data) if tcp_payload else 0
            elif udp_src and udp_dst:
                src_port, dst_port = udp_src, udp_dst
                layer="udp"
                binary_data = hex_to_byte(udp_payload)
                payload_len = len(binary_data) if udp_payload else 0

            entropy = calculate_entropy(binary_data)
            protocol = normalize_protocol(fields[10])

            conversation = {
                "address_a": src_ip,
                "port_a": int(src_port),
                "address_b": dst_ip,
                "port_b": int(dst_port),
                "bytes": payload_len,
                "packets": 1,
                "protocol": protocol,
                "entropy": entropy,
            }

            data[layer].append(conversation)

        return data


    # 하나의 레이어를 처리하는 함수
    def process_layer(self, pcap_chunk, filter_pkt):
        convs = {}
        try:
            tshark_output = wireshark_api(self.config).extract_conv(pcap_chunk, filter_pkt)
            convs = self.parse_conv(tshark_output)
            return convs
        except Exception as e:
            print(f"Error processing {pcap_chunk}: {e}")
            return {}


    # 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
    def analyze_pcap_file(self, pcap_file):
        print(f"Splitting {pcap_file}...")

        split_pcaps = wireshark_api(self.config).split_pcap(pcap_file)

        if not split_pcaps:
            print(f"분할된 파일이 없습니다: {pcap_file}")
            return False, "No Splitted File", ""

        args = [(pcap, filter_pkt_default) for pcap in split_pcaps]

        # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
        with Pool(processes=cpu_count()) as pool:
            results_list = pool.starmap(self.process_layer, args)

        merged_results = self.merge_results(results_list)

        json_name = os.path.basename(pcap_file)
        output_file = os.path.join(self.result_dir, f"{os.path.splitext(json_name)[0]}.json")
        os.makedirs(self.result_dir, exist_ok=True)
        with open(output_file, "w") as json_file:
            json.dump(merged_results, json_file, indent=4)

        return True, "success", f"{output_file}"
        

    def merge_results(self, all_results):
        merged_data = {layer: {} for layer in ["tcp", "udp"]}
        # seen_pkt = set()

        # 리스트 안에 여러 딕셔너리가 있는 경우 해결
        for result in all_results:
            for layer, conversations in result.items():
                if layer not in merged_data:
                    merged_data[layer] = {}

                for conv in conversations:
                    ip_pair = tuple(sorted([(conv["address_a"], conv["port_a"]), (conv["address_b"], conv["port_b"])]))
                    proto = conv["protocol"]
                    #proto = conv["protocol"]

                    key = (ip_pair, proto)
                    if key not in merged_data[layer]:
                        merged_data[layer][key] = {
                            **conv.copy(),  # 전체 데이터를 복사
                        }

                    else:
                        existing = merged_data[layer][key]
                        
                        # 나머지 데이터도 합침
                        existing["bytes"] += conv["bytes"]
                        existing["packets"] += conv["packets"]
                        existing["entropy"] += conv["entropy"]

        # merged_data의 value가 dict인 경우, list로 변환
        for layer in merged_data:
            if isinstance(merged_data[layer], dict):
                for conv in merged_data[layer].values():
                    if conv["packets"] > 0:
                        conv["entropy"] = conv["entropy"] / conv["packets"]
                        conv["bytes"] = conv["bytes"] / conv["packets"]
                merged_data[layer] = list(merged_data[layer].values())

        return merged_data
