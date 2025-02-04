import re
import json
import subprocess
import os
from glob import glob
from multiprocessing import Pool, cpu_count
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
        raise Exception(f"layer {layer}: {result.stderr}")
    
    return result.stdout


def split_pcap(input_file, output_dir, chunk_size=1000000):
    """editcap을 이용해 pcap 파일을 chunk_size 개의 패킷 단위로 분할"""
    program = "C:\\Program Files\\Wireshark\\editcap.exe"
    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.basename(input_file)  # 파일 이름만 추출 (test_5gb.pcapng)
    base_name_no_ext = os.path.splitext(base_name)[0]  # 확장자 제거 (test_5gb)
    output_pattern = os.path.join(output_dir, base_name_no_ext)  # 출력 파일 패턴

    split_file_pcap = output_pattern + os.path.splitext(base_name)[1]

    # editcap 실행
    command = [program, "-c", str(chunk_size), input_file, split_file_pcap]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print(f" editcap Error: {result.stderr}")
        return []

    # 파일 찾을 때 확장자 없는 `base_name_no_ext` 사용
    split_files = glob(os.path.join(output_dir, f"{base_name_no_ext}_*"))  # test_5gb_* 형식으로 검색

    if not split_files:
        print(f" 분할된 파일이 감지되지 않음. 경로 확인 필요: {output_pattern}_*")
    else:
        print(f" {input_file} -> {len(split_files)} 개의 파일로 분할 완료")

    return split_files


def change_byte(bytes):
    """'10 MB', '5 kB' 같은 문자열을 바이트 단위 정수로 변환"""
    data = bytes.split()
    if data[1] == "bytes":
        return int(data[0])
    elif data[1] == "kB":
        return int(data[0]) * 1024
    elif data[1] == "MB":
        return int(data[0]) * 1024 * 1024
    elif data[1] == "GB":
        return int(data[0]) * 1024 * 1024 * 1024


def parse_conv(layer, tshark_output):
    """tshark 출력 결과를 JSON 데이터로 변환"""
    pattern = re.compile(r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)')

    data = []
    matches = pattern.findall(tshark_output)

    for match in matches:
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


def process_pcap_chunk(pcap_chunk):
    """하나의 pcap 조각을 분석하는 함수"""
    layers = ["eth", "ip", "ipv6", "tcp", "udp"]
    result = {}

    for layer in layers:
        try:
            tshark_output = extract_conv(layer, pcap_chunk)
            convs = parse_conv(layer, tshark_output)
            for key, value in convs.items():
                if key in result:
                    result[key].extend(value)
                else:
                    result[key] = value
        except Exception as e:
            print(f" Error processing {pcap_chunk}: {e}")

    return result


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
                    merged_data[layer][key] = conv.copy()
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
                    existing["rel_start"] += conv["rel_start"]
                    existing["duration"] += conv["duration"]

    # stream_id 재정렬
    for layer in merged_data:
        sorted_convs = sorted(merged_data[layer].values(), key=lambda x: x["rel_start"])
        for i, conv in enumerate(sorted_convs):
            conv["stream_id"] = i
        merged_data[layer] = sorted_convs  # 딕셔너리를 리스트로 변환

    return merged_data


def analyze_pcap(input_file, output_folder):
    """하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기"""
    print(f" Splitting {input_file}...")

    split_dir = os.path.join(output_folder, "split")
    split_pcaps = split_pcap(input_file, split_dir)

    if not split_pcaps:
        print(f" 분할된 파일이 없습니다: {input_file}")
        return

    print(f" Processing {len(split_pcaps)} chunks in parallel...")

    with Pool(processes=cpu_count()) as pool:
        results = pool.map(process_pcap_chunk, split_pcaps)

    print("Merging results...")
    merged_results = merge_results(results)

    # 최종 결과 저장
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    output_file = os.path.join(output_folder, f"{base_name}.json")
    
    with open(output_file, 'w') as json_file:
        json.dump(merged_results, json_file, indent=4)

    print(f" Results saved to {output_file}")

    # 분석이 끝난 후 split 폴더 삭제
    try:
        shutil.rmtree(split_dir)
        print(f" Deleted split folder: {split_dir}")
    except Exception as e:
        print(f" Failed to delete split folder: {e}")


if __name__ == "__main__":
    input_folder = "D:\\script\\wireshark\\pcaps"   # pcap 파일들 있는 폴더 경로(안에 있는 pcap 파일 전부 분석)
    output_folder = "D:\\script\\wireshark\\pcap_results" # 결과 파일 저장 폴더 경로로

    os.makedirs(output_folder, exist_ok=True)

    pcap_files = glob(os.path.join(input_folder, "*.pcap*"))

    start = datetime.now()

    for pcap_file in pcap_files:
        analyze_pcap(pcap_file, output_folder)

    end = datetime.now()

    print(f" 시작시간 : {start.strftime('%H:%M:%S')}")
    print(f" 종료시간 : {end.strftime('%H:%M:%S')}")
