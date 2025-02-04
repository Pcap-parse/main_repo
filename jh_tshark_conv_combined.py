import re
import json
import os
import glob
import subprocess
from multiprocessing import Pool
from datetime import datetime
from functools import partial

def extract_conv(layer, pcap_file):

    program = "C:\\Program Files\\Wireshark\\tshark.exe"  # 실행할 프로그램

    # 명령어
    command = [
        program,
        "-r", pcap_file, 
        "-q", 
        "-z", f"conv,{layer}",
        "-o", "nameres.mac_name:FALSE"
    ]

    # 프로그램 실행
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)

    # 에러 확인
    if result.returncode != 0:
        raise Exception(f"layer {layer}: {result.stderr}")
    
    # 결과 반환
    return result.stdout

def run_editcap(input_file, output_file):

    program = "C:\\Program Files\\Wireshark\\editcap.exe"

    # 명령어
    command = [
        program,
        "-c", "1000000", # 패킷 10만개 단위로 분할(더 크게 분할해도 될듯?)
        input_file, # 분할 대상 파일
        output_file # 분할 결과 파일 (여러개면 뒤에 숫자 붙여지면서 만들어짐)
    ]

    result = subprocess.run(command)
    if result.returncode != 0:
        raise Exception(f"editcap Error: {result.stderr}")

def change_byte(bytes):
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

    # 정규표현식 패턴 (각 항목을 정확히 추출)
    pattern = re.compile(r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+) +([\d,]+ (?:GB|MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:GB|MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)')  

    # 데이터 리스트로 저장
    data = []

    # 정규표현식으로 데이터 추출
    for output in tshark_output:
        if isinstance(output, list): # 첫번째 요소가 문자열이 아니라 리스트 타입이여서 변환 필요.
            output = " ".join(output)

        matches = pattern.findall(output)

        # 추출한 값들을 리스트에 저장
        for match in matches:
            # 공통 부분: IP 및 포트 관련 정보 추출
            src_ip, dst_ip = match[0], match[1]

            # TCP/UDP의 경우 포트 포함
            if layer in ["tcp", "udp"]:
                src_ip, src_port = src_ip.rsplit(":", 1)
                dst_ip, dst_port = dst_ip.rsplit(":", 1)
                conversation = {
                    "Address A": src_ip,
                    "Port A": src_port,
                    "Address B": dst_ip,
                    "Port B": dst_port
                }
            else:
                conversation = {
                    "Address A": src_ip,
                    "Address B": dst_ip
                }

            # 딕셔너리로 변환 + 각 값 저장
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
                        
            # 리스트에 추가
            data.append(conversation)

    # 딕셔너리를 시간순으로 정렬 후 순서대로 인덱스 주입
    data.sort(key=lambda x: float(x["rel_start"]))
    index=0
    for i in data:
        i["stream_id"] = index
        index += 1

    return {layer : data}

def combine_packets(layer, convs):
    combined = {}  # 송수신 쌍을 저장하는 딕셔너리
    after_combined = []  # 최종 결과를 저장할 리스트
    
    for conv in convs:
        if layer in ["tcp", "udp"]:
            print(end="")
        else:
            key = frozenset([conv["Address A"], conv["Address B"]])  # 송수신 관계를 무시하는 키 생성

            if key in combined:
                combined[key]["bytes"] += conv["bytes"]
                combined[key]["bytes_atob"] += conv["bytes_atob"]
                combined[key]["bytes_btoa"] += conv["bytes_btoa"]
                combined[key]["packets"] += conv["packets"]
                combined[key]["packets_atob"] += conv["packets_atob"]
                combined[key]["packets_btoa"] += conv["packets_btoa"]
                combined[key]["duration"] += conv["duration"]
                            
                # after_combined에서 Address A, B가 동일한 항목을 찾아 업데이트
                for pk in after_combined:
                    if frozenset([pk["Address A"], pk["Address B"]]) == key:
                        pk["bytes"] = combined[key]["bytes"]
                        pk["bytes_atob"] = combined[key]["bytes_atob"]
                        pk["bytes_btoa"] = combined[key]["bytes_btoa"]
                        pk["packets"] = combined[key]["packets"]
                        pk["packets_atob"] = combined[key]["packets_atob"]
                        pk["packets_btoa"] = combined[key]["packets_btoa"]
                        if combined[key]["rel_start"] < conv["rel_start"]:
                            pk["rel_start"] = combined[key]["rel_start"]                   
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
                    "rel_start": conv["rel_start"],
                    "duration": conv["duration"],
                    "stream_id": -1
                }
                combined[key] = new_entry  # 딕셔너리에도 저장
                after_combined.append(new_entry)  # 리스트에도 저장
    return after_combined  # 리스트 형태 유지

def main():
    # pcap 파일 경로
    pcap_file = r"D:\downloads\wrccdc.2017-03-24.010540000000000.pcap\1gb.pcap"
    # JSON 형식으로 추출된 데이터를 저장할 파일
    output_file = r"D:\downloads\wrccdc.2017-03-24.010540000000000.pcap\1gb.json"

    start = datetime.now()
    
    # pcap 분할 경로    
    split_file = r"D:\downloads\wrccdc.2017-03-24.010540000000000.pcap\output\split\\"
    split_name = r"split.pcap"
    run_editcap(pcap_file, (f"{split_file}{split_name}"))

    pcap_files = glob.glob(f"{split_file}split_*.pcap")

    # 레이어 목록
    layers = ["eth", "ip", "ipv6", "tcp", "udp"]
    all_conv = {}
    
    # 각 레이어의 데이터를 추출 및 파싱
    for layer in layers:
        tshark_output = []
        print(f"Extracting {layer} conversations...")
        extract_with_layer = partial(extract_conv, layer)
        with Pool(processes=os.cpu_count()) as pool:  # CPU 코어 개수만큼 병렬 실행
            tshark_output.append(pool.map(extract_with_layer, pcap_files))
        convs = parse_conv(layer, tshark_output)
        convs[layer] = combine_packets(layer, convs[layer])
        all_conv.update(convs)

    # JSON 형식으로 저장
    with open(output_file, 'w') as json_file:
        json.dump(all_conv, json_file, indent=4)

    for pcap in pcap_files:
        try:
            os.remove(pcap)  # 파일 삭제
        except Exception as e:
            print(f"Error deleting {pcap}: {e}")

    print(f"Data saved to {output_file}")
    print(f"시작시간 : {start.hour}시 {start.minute}분 {start.second}초")
    end = datetime.now()
    print(f"종료시간 : {end.hour}시 {end.minute}분 {end.second}초")

if __name__ == "__main__":
    main()