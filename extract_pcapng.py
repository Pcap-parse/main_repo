import os
import json
import subprocess
from datetime import datetime
import re
from multiprocessing import Pool, cpu_count

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # 현재 스크립트 기준 디렉터리
JSON_FOLDER = os.path.join(BASE_DIR, "tshark_json")
FILTER_INFO_JSON = os.path.join(BASE_DIR, "filter_list.json")

# 프로토콜 매핑
PROTOCOL_MAP = {
    "HTTP": "http",
    "SMTP": "smtp",
    "FTP": "ftp",
    "DNS": "dns",
    "POP": "pop",
    "IMAP": "imap",
    "TELNET": "telnet",
    "SNMP": "snmp",
    "VNC": "vnc",
    "RTSP": "rtsp",
    "OCSP": "ocsp"
}

def generate_filter(flow):
    ip_src = flow["address_A"]
    ip_dst = flow["address_B"]
    port_src = flow["port_A"]
    port_dst = flow["port_B"]
    proto = flow["layer"].lower()

    #base_filter = "(ip.src=={ip_src} && ip.dst=={ip_dst} && {proto}.srcport=={port_src} && {proto}.dstport=={port_dst})"
    base_filter = (
    f"((ip.src=={ip_src} && ip.dst=={ip_dst} && {proto}.srcport=={port_src} && {proto}.dstport=={port_dst}) || "
    f"(ip.src=={ip_dst} && ip.dst=={ip_src} && {proto}.srcport=={port_dst} && {proto}.dstport=={port_src}))")
    return base_filter

def build_combined_filter(flows):
    conditions = []
    for flow in flows:
        f = generate_filter(flow)
        conditions.append(f)
    combined = " || ".join(conditions)
    final_filter = (
        "!( _ws.malformed ) "
        f"&& ({combined})"
    )
    return final_filter

def tshark_extract_frame_numbers(pcap_file, display_filter, output_txt):
    # tshark로는 프레임 번호만 추출, 시간 소요 문제
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number"
    ]
    print(command)
    with open(output_txt, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.PIPE, text=True)

def extract_pcapng_by_frame_filter(pcap_file, output_pcapng, display_filter):
    temp_txt =os.path.join(BASE_DIR, "matched_frames.txt")
    tshark_extract_frame_numbers(pcap_file, display_filter, temp_txt)
    parallel_editcap_extract(pcap_file, output_pcapng, temp_txt)
    #editcap_extract_frames_merge(pcap_file, temp_txt, output_pcapng)
    os.remove(temp_txt)

def get_filter(name, id):
    name = f"{name}.json"
    # 인자로 json, 필터 id 받아서, 해당 pcap에서 필터 명령어 입력 (엔트로피값 대상은 코드 짜야될듯)
    if not os.path.exists(FILTER_INFO_JSON):
        return False, "File Not Found"
    with open(FILTER_INFO_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for entry in data:
        if entry.get("name") == name and entry.get("id") == id:
            return True, entry.get("filter")
    return False, "Entry Not Found"

# layer 판단 함수
def determine_layer(filter_str, json_data):
    matched_layers = set()

    for layer in ['tcp', 'udp']:
        for item in json_data.get(layer, []):
            match = True
            for cond in filter_str.split("&&"):
                cond = cond.strip()
                if "==" not in cond:
                    continue
                try:
                    key, value = map(str.strip, cond.split("==", 1))
                except ValueError:
                    continue  # 잘못된 조건은 무시
                if key not in item or str(item[key]) != value:
                    match = False
                    break
            if match:
                matched_layers.add(layer)
                break
    return "all" if len(matched_layers) == 2 else (matched_layers.pop() if matched_layers else "")

# 각 필드를 tshark용 필드로 변환
def map_filter_key(key, layer="tcp"):
    if key.startswith("address_"):
        return "ip.addr"
    elif key.startswith("port_"):
        if layer == "all":
            return ["tcp.port", "udp.port"]
        return f"{layer}.port"
    elif key == "protocol":
        return "protocol"
    return key

# 필터 문자열 파싱 및 tshark 필터로 변환
def convert_to_display_filter(filter_str, layer="tcp"):
    def replace_expr(match):
        key, op, val = match.group(1), match.group(2), match.group(3)
        key = key.strip()
        op = op.strip()
        val = val.strip().strip('"').strip("'")
        mapped_key = map_filter_key(key, layer)

        if mapped_key == "protocol":
            proto = PROTOCOL_MAP.get(val.upper(), val.lower())
            return proto
        elif isinstance(mapped_key, list):  # for layer == all
            return f"({mapped_key[0]}{op}{val} || {mapped_key[1]}{op}{val})"
        else:
            return f"{mapped_key}{op}{val}"

    # Step 1: 조건 항목을 변환하고 괄호로 묶음
    pattern = r'\b(address_[AB]|port_[AB]|protocol)\s*(==|!=)\s*([^\s&|()]+)'
    replaced = re.sub(pattern, lambda m: f"({replace_expr(m)})", filter_str)

    # Step 2: 논리 연산자 주변에 괄호 정리 필요 시 → 사용자 괄호 기준 유지
    # 괄호 우선순위 보장은 사용자 입력 전제로 하되, 전체 식은 감싸줌
    return f"({replaced})"

# 전역으로 빼기!
def run_editcap(args):
    idx, chunk, pcap_file, output_pcapng = args
    temp_output = output_pcapng if idx == 0 else f"{output_pcapng}_part{idx}"
    command = [
        "C:\\Program Files\\Wireshark\\editcap.exe",
        "-r", pcap_file,
        temp_output
    ] + chunk
    subprocess.run(command, stderr=subprocess.PIPE, text=True)
    return temp_output

def parallel_editcap_extract(pcap_file, output_pcapng, frame_txt):
    with open(frame_txt, "rb") as f:
        content = f.read()

    frame_numbers = [
        line.decode(errors="ignore").strip()
        for line in content.splitlines()
        if line.decode(errors="ignore").strip().isdigit()
    ]

    if not frame_numbers:
        print("[INFO] No frames to extract.")
        return

    MAX_ARGS = 1000
    chunks = [frame_numbers[i:i + MAX_ARGS] for i in range(0, len(frame_numbers), MAX_ARGS)]

    args_list = [(idx, chunk, pcap_file, output_pcapng) for idx, chunk in enumerate(chunks)]

    with Pool(cpu_count()) as pool:
        part_files = pool.map(run_editcap, args_list)

    if len(part_files) > 1:
        merged_output = output_pcapng.replace(".pcapng", "_merged.pcapng")
        merge_command = ["C:\\Program Files\\Wireshark\\mergecap.exe", "-w", merged_output] + part_files
        subprocess.run(merge_command, stderr=subprocess.PIPE, text=True)

        for i, part_file in enumerate(part_files):
            if i != 0 and os.path.exists(part_file):
                try:
                    os.remove(part_file)
                except Exception as e:
                    print(f"[WARNING] Failed to delete {part_file}: {e}")

        print(f"[SUCCESS] Merged output: {merged_output}")
    else:
        print(f"[SUCCESS] Output: {output_pcapng}")

if __name__ == "__main__":
    start = datetime.now()
    json_file=f"{JSON_FOLDER}\\10gb_sample.json" # 필터 적용한 json
    with open(json_file, "r", encoding="utf-8") as f:
        json_data = json.load(f)    
    # tshark로 필터링 → frame.number 추출 → editcap으로 pcapng 저장   
    success, filter_str = get_filter("10gb_sample",3)
    layer = determine_layer(filter_str, json_data)
    print(filter_str)
    print(layer)
    extract_display_filter = convert_to_display_filter(filter_str, layer)
    
    if success:
        extract_pcapng_by_frame_filter(
            pcap_file="D:\\script\\wireshark\\pcaps\\10gb_sample.pcap",
            output_pcapng="D:\\script\\wireshark\\pcaps\\10gb_sample_filterd.pcapng",
            display_filter = extract_display_filter
        )
    end = datetime.now()
    print(f"시작시간 : {start.strftime('%H:%M:%S')}")
    print(f"종료시간 : {end.strftime('%H:%M:%S')}")
    
