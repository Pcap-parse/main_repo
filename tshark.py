import re
import json
import subprocess
import os
from glob import glob
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import shutil


def extract_conv(layer, pcap_file):
    """tshark를 이용해 특정 레이어의 대화(conversation) 정보를 추출"""
    program = "C:\\Program Files\\Wireshark\\tshark.exe"

    command = [
        program,
        "-r", pcap_file, 
        "-q", 
        "-z", f"conv,{layer}",
        "-o", "nameres.mac_name:FALSE"
    ]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise Exception(f"Layer {layer} Error: {result.stderr}")
    
    return result.stdout


def split_pcap(input_file, output_dir, chunk_size=1000000):
    """editcap을 이용해 pcap 파일을 chunk_size 개의 패킷 단위로 분할"""
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


def change_byte(bytes):
    """'10 MB', '5 kB' 같은 문자열을 바이트 단위 정수로 변환"""
    data = bytes.split()
    unit_map = {"bytes": 1, "kB": 1024, "MB": 1024**2, "GB": 1024**3}
    return int(data[0].replace(",", "")) * unit_map[data[1]]


def parse_conv(layer, tshark_output):
    """tshark 출력 결과를 JSON 데이터로 변환"""
    pattern = re.compile(
        r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)'
    )

    data = []
    for match in pattern.findall(tshark_output):
        src_ip, dst_ip = match[0], match[1]

        if layer in ["tcp", "udp"]:
            src_ip, src_port = src_ip.rsplit(":", 1)
            dst_ip, dst_port = dst_ip.rsplit(":", 1)
            conversation = {
                "address A": src_ip,
                "port A": src_port,
                "address B": dst_ip,
                "port B": dst_port
            }
        else:
            conversation = {
                "address A": src_ip,
                "address B": dst_ip
            }

        conversation.update({
            "bytes": change_byte(match[7]),
            "bytes_atob": change_byte(match[5]),
            "bytes_btoa": change_byte(match[3]),
            "packets": int(match[6]),
            "packets_atob": int(match[4]),
            "packets_btoa": int(match[2]),
            "rel_start": float(match[8]),
            "duration": float(match[9]),
            "stream_id": -1
        })

        data.append(conversation)

    return {layer: data}


def process_layer(layer, pcap_chunk):
    """하나의 레이어를 처리하는 함수 (멀티스레딩용)"""
    try:
        tshark_output = extract_conv(layer, pcap_chunk)
        convs = parse_conv(layer, tshark_output)
        return layer, convs
    except Exception as e:
        print(f"Error processing {pcap_chunk} for {layer}: {e}")
        return layer, {}


def process_pcap_chunk(pcap_chunk):
    """하나의 pcap 조각을 분석하는 함수 (멀티스레딩)"""
    layers = ["eth", "ip", "ipv6", "tcp", "udp"]
    result = {}

    # 각 레이어에 대해 멀티스레딩을 사용
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(process_layer, layer, pcap_chunk) for layer in layers]

    # 각 스레드의 결과를 합침
    for future in futures:
        layer, convs = future.result()
        if convs:
            result[layer] = convs[layer]

    return result


def analyze_pcap_file(pcap_file, output_folder):
    """하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기"""
    print(f"Splitting {pcap_file}...")

    split_dir = os.path.join(output_folder, "split")
    split_pcaps = split_pcap(pcap_file, split_dir)

    if not split_pcaps:
        print(f"분할된 파일이 없습니다: {pcap_file}")
        return

    # 🔹 `ThreadPoolExecutor`를 사용하여 멀티스레딩 처리
    results = []
    with Pool(processes=cpu_count()) as pool:
        results = pool.map(process_pcap_chunk, split_pcaps)

    merged_results = merge_results(results)

    output_file = os.path.join(output_folder, f"{os.path.basename(pcap_file)}.json")
    with open(output_file, 'w') as json_file:
        json.dump(merged_results, json_file, indent=4)

    shutil.rmtree(split_dir, ignore_errors=True)

def combine_packets(layer, convs, tsp_min):
    combined = {}  # 송수신 쌍을 저장하는 딕셔너리
    after_combined = []  # 최종 결과를 저장할 리스트
    
    for conv in convs:
        if layer in ["tcp", "udp"]:
            key = frozenset([
                (conv["Address A"], conv["Port A"]), 
                (conv["Address B"], conv["Port B"])
            ])  # TCP/UDP의 경우, 포트까지 포함한 키 생성
        else:
            key = frozenset([conv["Address A"], conv["Address B"]])  # 일반적인 MAC 주소 비교

        if key in combined:
            combined[key]["bytes"] += conv["bytes"]
            combined[key]["bytes_atob"] += conv["bytes_atob"]
            combined[key]["bytes_btoa"] += conv["bytes_btoa"]
            combined[key]["packets"] += conv["packets"]
            combined[key]["packets_atob"] += conv["packets_atob"]
            combined[key]["packets_btoa"] += conv["packets_btoa"]
            combined[key]["duration"] = max(combined[key]["duration"], conv["duration"])

            # after_combined에서 Address A, B가 동일한 항목을 찾아 업데이트
            for pk in after_combined:
                if layer in ["tcp", "udp"]:
                    match = frozenset([
                        (pk["Address A"], pk["Port A"]), 
                        (pk["Address B"], pk["Port B"])
                    ]) == key
                else:
                    match = frozenset([pk["Address A"], pk["Address B"]]) == key

                if match:
                    pk["bytes"] = combined[key]["bytes"]
                    pk["bytes_atob"] = combined[key]["bytes_atob"]
                    pk["bytes_btoa"] = combined[key]["bytes_btoa"]
                    pk["packets"] = combined[key]["packets"]
                    pk["packets_atob"] = combined[key]["packets_atob"]
                    pk["packets_btoa"] = combined[key]["packets_btoa"]
                    # 가장 큰 duration 값 유지
                    pk["duration"] = max(pk["duration"], combined[key]["duration"])
                    break  # 업데이트가 완료되면 루프 종료 (성능 향상)
        else:
            new_entry = {
                "Address A": conv["Address A"],
                "Address B": conv["Address B"],
                "bytes": conv["bytes"],
                "bytes_atob": conv["bytes_atob"],
                "bytes_btoa": conv["bytes_btoa"],
                "packets": conv["packets"],
                "packets_atob": conv["packets_atob"],
                "packets_btoa": conv["packets_btoa"],
                "rel_start": conv["rel_start"],  # 최초값 그대로 저장
                "duration": conv["duration"],
                "stream_id": -1
            }
            if layer in ["tcp", "udp"]:
                new_entry["Port A"] = conv["Port A"]
                new_entry["Port B"] = conv["Port B"]

            combined[key] = new_entry  # 딕셔너리에도 저장
            after_combined.append(new_entry)  # 리스트에도 저장
            
    # 딕셔너리를 rel_start 기준으로 정렬 후 순서대로 인덱스 부여
    after_combined.sort(key=lambda x: float(x["rel_start"]))
    for index, i in enumerate(after_combined):        
        i["duration"] = i["duration"] - i["rel_start"] # 상대 시간으로 변경
        i["rel_start"] = i["rel_start"] - tsp_min # 상대 시간으로 변경       
        i["stream_id"] = index

    return after_combined  # 리스트 형태 유지

def merge_results(all_results):
    merged_data = {layer: {} for layer in ["eth", "ip", "ipv6", "tcp", "udp"]}

    # 리스트 안에 여러 딕셔너리가 있는 경우 해결
    for result in all_results:
        for layer, conversations in result.items():
            if layer not in merged_data:
                merged_data[layer] = {}

            for conv in conversations:
                # 'tcp' 또는 'udp'일 경우, port 정보를 포함한 key 생성
                if layer in ["tcp", "udp"]:
                    key = tuple(sorted([conv["address A"], conv["port A"], conv["address B"], conv["port B"]]))
                else:
                    # 다른 레이어일 경우, 포트 정보 없이 address A, address B만 비교
                    key = tuple(sorted([conv["address A"], conv["address B"]]))

                # 대화가 처음이면 복사해서 추가, 기존에 있으면 데이터 병합
                if key not in merged_data[layer]:
                    merged_data[layer][key] = {
                        **conv.copy(),  # 전체 데이터를 복사
                        "rel_start": conv["rel_start"]  # rel_start는 따로 처리
                    }

                else:
                    existing = merged_data[layer][key]

                    # address A, address B가 바뀌었을 경우 처리
                    if (conv["address A"], conv.get("port A", "")) == (existing["address B"], existing.get("port B", "")) and \
                       (conv["address B"], conv.get("port B", "")) == (existing["address A"], existing.get("port A", "")):
                        # 바뀐 경우에는 bytes_atob, packets_atob와 bytes_btoa, packets_btoa를 교환해서 합침
                        existing["bytes_atob"] += conv["bytes_btoa"]
                        existing["bytes_btoa"] += conv["bytes_atob"]
                        existing["packets_atob"] += conv["packets_btoa"]
                        existing["packets_btoa"] += conv["packets_atob"]
                    else:
                        # 바뀌지 않은 경우는 기존 방식대로 합침
                        existing["bytes_atob"] += conv["bytes_atob"]
                        existing["bytes_btoa"] += conv["bytes_btoa"]
                        existing["packets_atob"] += conv["packets_atob"]
                        existing["packets_btoa"] += conv["packets_btoa"]

                    # 나머지 데이터도 합침
                    existing["bytes"] += conv["bytes"]
                    existing["packets"] += conv["packets"]
                    existing["duration"] = existing["duration"]

    # stream_id 재정렬
    for layer in merged_data:
        sorted_convs = sorted(merged_data[layer].values(), key=lambda x: x["rel_start"])
        for i, conv in enumerate(sorted_convs):
            conv["stream_id"] = i
        merged_data[layer] = sorted_convs  # 딕셔너리를 리스트로 변환

    return merged_data


def analyze_pcap_files(input_folder, output_folder):
    """PCAP 및 PCAPNG 파일 단위로 멀티프로세싱을 수행하는 함수"""
    pcap_files = [os.path.join(input_folder, f) for f in os.listdir(input_folder) if f.endswith((".pcap", ".pcapng"))]

    if not pcap_files:
        print("No PCAP or PCAPNG files found.")
        return

    # 순차적으로 각 pcap 파일을 처리
    for pcap_file in pcap_files:
        analyze_pcap_file(pcap_file, output_folder)


if __name__ == "__main__":
    input_folder = "D:\\script\\wireshark\\pcaps"
    output_folder = "D:\\script\\wireshark\\pcap_results"
    os.makedirs(output_folder, exist_ok=True)

    start = datetime.now()
    analyze_pcap_files(input_folder, output_folder)
    end = datetime.now()

    print(f"시작시간 : {start.strftime('%H:%M:%S')}")
    print(f"종료시간 : {end.strftime('%H:%M:%S')}")
