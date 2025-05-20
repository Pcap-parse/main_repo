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

base_dir = os.path.dirname(os.path.abspath(__file__))
JSON_FOLDER = os.path.join(base_dir,"tshark_json")
INFO_JSON = os.path.join(base_dir,"tshark_list.json")
PCAP_FOLDER = os.path.join(base_dir,"pcaps")

# tshark를 이용해 특정 레이어의 대화(conversation) 정보를 추출
def extract_conv(pcap_file):
    program = "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로
    filter_pkt = "!tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && !tcp.analysis.spurious_retransmission && !_ws.malformed && (tcp.srcport || udp.srcport)"

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
def split_pcap(input_file, output_dir, chunk_size=500000):
    program = "C:\\Program Files\\Wireshark\\editcap.exe"
    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.basename(input_file)
    base_name_no_ext = os.path.splitext(base_name)[0]
    output_pattern = os.path.join(output_dir, base_name_no_ext)
    split_file_pcap = output_pattern + os.path.splitext(base_name)[1]

    command = [program, "-c", str(chunk_size), input_file, split_file_pcap]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        shutil.rmtree(output_dir)
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
            binary_data = binascii.unhexlify(tcp_payload)
            payload_len = len(binary_data) if tcp_payload else 0
        elif udp_src and udp_dst:
            src_port, dst_port = udp_src, udp_dst
            layer="udp"
            binary_data = binascii.unhexlify(udp_payload)
            payload_len = len(binary_data) if udp_payload else 0

        entropy = calculate_entropy(binary_data)
        
        conversation = {
            "address_a": src_ip,
            "port_a": int(src_port),
            "address_b": dst_ip,
            "port_b": int(dst_port),
            "bytes": payload_len,
            "packets": 1,
            "protocol": fields[10],
            "entropy": entropy,
        }

        data[layer].append(conversation)

    return data

@lru_cache(maxsize=256)
def fast_log2(count: int, length: int) -> float:
    return math.log2(count / length)

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
            entropy -= prob * fast_log2(count, length)

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
        return False, "No Splitted File", ""

    # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
    with Pool(processes=cpu_count()) as pool:
        results_list = pool.map(process_pcap_chunk, split_pcaps)

    merged_results = merge_results(results_list)

    json_name = os.path.basename(pcap_file)
    output_file = os.path.join(JSON_FOLDER, f"{os.path.splitext(json_name)[0]}.json")
    with open(output_file, "w") as json_file:
        json.dump(merged_results, json_file, indent=4)

    shutil.rmtree(split_dir, ignore_errors=True)

    return True, "success", ""


def normalize_protocol(proto):
    proto = proto.lower()
    known_protocols = ["http", "dns", "ftp", "imap", "pop", "smtp", "rtsp", "telnet", "vnc", "snmp"]
    for keyword in known_protocols:
        if keyword in proto:
            return keyword
    return proto
    

def merge_results(all_results):
    merged_data = {layer: {} for layer in ["tcp", "udp"]}
    # seen_pkt = set()

    # 리스트 안에 여러 딕셔너리가 있는 경우 해결
    for result in all_results:
        for layer, conversations in result.items():
            if layer not in merged_data:
                merged_data[layer] = {}

            for conv in conversations:
                ip_pair = tuple(sorted([(conv["address_a"], conv["port_a"]), (conv["address_b"], conv["port_b"])]))
                proto = normalize_protocol(conv["protocol"])
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

# PCAP 및 PCAPNG 파일 단위로 멀티프로세싱을 수행하는 함수
def analyze_pcap_files(input_folder, output_folder):
    pcap_files = [os.path.join(input_folder, f) for f in os.listdir(input_folder) if f.endswith((".pcap", ".pcapng"))]

    if not pcap_files:
        print("No PCAP or PCAPNG files found.")
        return

    # 순차적으로 각 pcap 파일을 처리
    for pcap_file in pcap_files:
        analyze_pcap_file(pcap_file, output_folder)

def start(file_name):
    output_folder = f"{JSON_FOLDER}" # 결과 파일 저장 폴더 경로
    os.makedirs(output_folder, exist_ok=True)

    pcap_dir = f"{PCAP_FOLDER}\\{file_name}"

    start = datetime.now()
    result, msg, data = analyze_pcap_file(pcap_dir, output_folder)
    if not result:
        return result, msg, data
    end = datetime.now()

    if not os.path.exists(JSON_FOLDER):
        os.makedirs(JSON_FOLDER)

    base_filename = os.path.basename(file_name)
    name_only = os.path.splitext(base_filename)[0]
    json_name = f"{name_only}.json"
    add_entry(json_name)

    print(f'시작시간 : {start.strftime("%H:%M:%S")}')
    print(f'종료시간 : {end.strftime("%H:%M:%S")}')

    return result, msg, data

# json 조회
def load_json_list():
    if not os.path.exists(INFO_JSON):
        return False, "File Not Found", ""
    with open(INFO_JSON, "r", encoding="utf-8") as f:
        return True, "success", flatten_results(json.load(f))
        
    
def save_json_list(data):
    with open(INFO_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# json append
def add_entry(name):
    check, msg, data = load_json_list()
    data = data or []

    # name을 기준으로 기존 항목이 있는지 확인
    found = False
    for entry in data:
        if entry["name"] == name:
            entry["timestamp"] = datetime.now().isoformat()
            found = True
            break

    # 없으면 새로 추가
    if not found:
        data.append({
            "name": name,
            "timestamp": datetime.now().isoformat()
        })

    save_json_list(data)

def flatten_results(result):
    flat = []
    for item in result:
        if isinstance(item, list):
            flat.extend(item)
        else:
            flat.append(item)
    return flat

def delete_json(target_name):
    with open(INFO_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    target_file_path = os.path.join(JSON_FOLDER, target_name)
    if os.path.exists(target_file_path):
        os.remove(target_file_path)
        original_len = len(data)
        data = [entry for entry in data if entry.get("name") != target_name]
        removed_count = original_len - len(data)
        if removed_count > 0:
            with open(INFO_JSON, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        return True, "success", ""
    else:
        return False, "File Not Found", ""

    
# json 파일 존재 확인
def check_info():
    if not os.path.exists(JSON_FOLDER):
        return "not create json"
    else:
        return "success"

def json_search(target_name):
    target_json = f"{JSON_FOLDER}{target_name}"
    try:
        with open(target_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        return True, "success", data
    except FileNotFoundError:
        return False, "File Not Found", ""
    
if __name__ == "__main__":
    input_folder = f"D:\\script\\wireshark\\pcaps"   # pcap 파일 모아놓은 폴더 경로
    output_folder = f"D:\\script\\wireshark\\pcap_results" # 결과 파일 저장 폴더 경로
    os.makedirs(output_folder, exist_ok=True)

    start = datetime.now()
    analyze_pcap_files(input_folder, output_folder)
    end = datetime.now()

    # print(f"시작시간 : {start.strftime("%H:%M:%S")}")
    # print(f"종료시간 : {end.strftime("%H:%M:%S")}")