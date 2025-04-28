import json
import subprocess
import os
from glob import glob
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import shutil
import math
from functools import lru_cache
import binascii


# tshark를 이용해 특정 레이어의 대화(conversation) 정보를 추출
def extract_conv(pcap_file):
    program = "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로
    filter_pkt = "!_ws.malformed && (http || dns || ftp || imap || pop || smtp || rtsp || telnet || vnc || snmp) && (tcp.srcport || udp.srcport)"

    command = [
        program,
        "-r", pcap_file, 
        "-Y", filter_pkt,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "tcp.payload",
        "-e", "udp.payload",
        "-e", "_ws.col.Protocol",
        "-o", "nameres.mac_name:FALSE"
    ]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise Exception(f"Error: {result.stderr}")
    
    return result.stdout


# editcap을 이용해 pcap 파일을 chunk_size 개의 패킷 단위로 분할
def split_pcap(input_file, output_dir, chunk_size=1000000):
    program = "C:\\Program Files\\Wireshark\\editcap.exe"
    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.basename(input_file)
    base_name_no_ext = os.path.splitext(base_name)[0]
    output_pattern = os.path.join(output_dir, base_name_no_ext)
    split_file_pcap = output_pattern + os.path.splitext(base_name)[1]

    command = [program, "-c", str(chunk_size), input_file, split_file_pcap]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print(f"editcap Error: {result.stderr}")
        return []

    split_files = glob(os.path.join(output_dir, f"{base_name_no_ext}_*"))
    return split_files


# tshark 출력 결과를 JSON 데이터로 변환
def parse_conv(tshark_output):
    data = {
        "tcp": [],
        "udp": []
    }

    for line in tshark_output.strip().splitlines():
        fields = line.strip().split('\t')
        if len(fields) != 12:
            continue

        src_ip = fields[0] if fields[0] else fields[1]
        dst_ip = fields[4] if fields[4] else fields[5]

        tcp_src, udp_src = fields[2], fields[3]
        tcp_dst, udp_dst = fields[6], fields[7]
        tcp_payload, udp_payload = fields[9], fields[10]

        if tcp_src and tcp_dst:
            src_port, dst_port = tcp_src, tcp_dst
            layer="tcp"
            binary_data = binascii.unhexlify(tcp_payload)
        elif udp_src and udp_dst:
            src_port, dst_port = udp_src, udp_dst
            layer="udp"
            binary_data = binascii.unhexlify(udp_payload)

        entropy = calculate_entropy(binary_data)
        
        conversation = {
            "address_A": src_ip,
            "port_A": int(src_port),
            "address_B": dst_ip,
            "port_B": int(dst_port),
            "bytes": int(fields[8]),
            "packets": 1,
            "protocol": fields[11],
            "entropy": entropy
        }

        data[layer].append(conversation)

    return data

@lru_cache(maxsize=256)
def fast_log2(x):
    return math.log2(x)

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count > 0:
            prob = count / length
            entropy -= prob * fast_log2(prob)

    return entropy

# 하나의 레이어를 처리하는 함수
def process_layer(pcap_chunk):
    try:
        tshark_output = extract_conv(pcap_chunk)
        convs = parse_conv(tshark_output)
        return convs
    except Exception as e:
        print(f"Error processing {pcap_chunk}: {e}")
        return {}


# 하나의 pcap 조각을 분석하는 함수
def process_pcap_chunk(pcap_chunk):
    result = {}
    result = process_layer(pcap_chunk)

    return result


# 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
def analyze_pcap_file(pcap_file, output_folder):
    print(f"Splitting {pcap_file}...")

    split_dir = os.path.join(output_folder, "split")
    split_pcaps = split_pcap(pcap_file, split_dir)

    if not split_pcaps:
        print(f"분할된 파일이 없습니다: {pcap_file}")
        return

    # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
    with Pool(processes=cpu_count()) as pool:
        results_list = pool.map(process_pcap_chunk, split_pcaps)

    merged_results = merge_results(results_list)

    output_file = os.path.join(output_folder, f"{os.path.basename(pcap_file)}_test2.json")
    with open(output_file, 'w') as json_file:
        json.dump(merged_results, json_file, indent=4)

    shutil.rmtree(split_dir, ignore_errors=True)


def merge_results(all_results):
    merged_data = {layer: {} for layer in ["tcp", "udp"]}

    # 리스트 안에 여러 딕셔너리가 있는 경우 해결
    for result in all_results:
        for layer, conversations in result.items():
            if layer not in merged_data:
                merged_data[layer] = {}

            for conv in conversations:
                key = tuple(sorted([(conv["address_A"], conv["port_A"]), (conv["address_B"], conv["port_B"])]))

                # 대화가 처음이면 복사해서 추가, 기존에 있으면 데이터 병합
                if key not in merged_data[layer]:
                    merged_data[layer][key] = {
                        **conv.copy(),  # 전체 데이터를 복사
                    }

                else:
                    existing = merged_data[layer][key]

                    # 나머지 데이터도 합침
                    existing["bytes"] += conv["bytes"]
                    existing["packets"] += conv["packets"]

    # merged_data의 value가 dict인 경우, list로 변환
    for layer in merged_data:
        if isinstance(merged_data[layer], dict):
            merged_data[layer] = list(merged_data[layer].values())

    return merged_data

# PCAP 및 PCAPNG 파일 단위로 멀티프로세싱을 수행하는 함수
def analyze_pcap_files(input_folder, output_folder):
    pcap_files = [os.path.join(input_folder, f) for f in os.listdir(input_folder) if f.endswith((".pcap", ".pcapng"))]

    if not pcap_files:
        print("No PCAP or PCAPNG files found.")
        return

    # 순차적으로 각 pcap 파일을 처리
    for pcap_file in pcap_files:
        analyze_pcap_file(pcap_file, output_folder)


if __name__ == "__main__":
    input_folder = "D:\\script\\wireshark\\pcaps"   # pcap 파일 모아놓은 폴더 경로
    output_folder = "D:\\script\\wireshark\\pcap_results" # 결과 파일 저장 폴더 경로
    os.makedirs(output_folder, exist_ok=True)

    start = datetime.now()
    analyze_pcap_files(input_folder, output_folder)
    end = datetime.now()

    print(f"시작시간 : {start.strftime('%H:%M:%S')}")
    print(f"종료시간 : {end.strftime('%H:%M:%S')}")