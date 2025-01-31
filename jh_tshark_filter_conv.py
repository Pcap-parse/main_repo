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
    addr_comp = []
    conv_list = []
    for conv in convs:
        if layer in ["tcp", "udp"]:
            print()
        else:
            if frozenset([conv["Address A"], conv["Address B"]]) in addr_comp:
                for conv_comp in conv_list:
                    if frozenset([conv_comp["Address A"], conv_comp["Address B"]]) in conv:
                        conv_list["bytes]"] += conv.get("bytes", 0)
                        conv_list["packets"] += conv.get("packets", 0)
                        conv_list["duration"] += conv.get("duration", 0)
                        if conv_list["rel_start"] > conv["rel_start"]:
                            conv_list["rel_start"] = conv["rel_start"]
                        if conv_comp["Address A"] == conv["Address A"]:
                            conv_list["bytes_atob"] += conv.get("bytes_atob", 0)
                            conv_list["bytes_btoa"] += conv.get("bytes_btoa", 0)
                            conv_list["packets_atob"] += conv.get("packets_atob", 0)
                            conv_list["packets_btoa"] += conv.get("packets_btoa", 0)
                        elif conv_comp["Address A"] == conv["Address B"]:
                            conv_list["bytes_atob"] += conv.get("bytes_btoa", 0)
                            conv_list["bytes_btoa"] += conv.get("bytes_atob", 0)
                            conv_list["packets_atob"] += conv.get("packets_btoa", 0)
                            conv_list["packets_btoa"] += conv.get("packets_atob", 0)
                        convs.remove(conv)
            else:
                conv_list.append(conv)
                addr_comp.append(frozenset([conv["Address A"], conv["Address B"]]))
    for conv in convs:
        for conv_tmp in conv_list:
            if frozenset([conv_tmp["Address A"], conv_tmp["Address B"]]) in conv:
                conv["bytes"] = conv_tmp["bytes"]
                conv["bytes_atob"] = conv_tmp["bytes_atob"]
                conv["bytes_btoa"] = conv_tmp["bytes_btoa"]
                conv["packets"] = conv_tmp["packets"]
                conv["packets_atob"] = conv_tmp["packets_atob"]
                conv["packets_btoa"] = conv_tmp["packets_btoa"]
                conv["rel_start"] = conv_tmp["rel_start"]
                conv["duration"] = conv_tmp["duration"]
    return convs

def main():
    # pcap 파일 경로
    pcap_file = r"C:\Users\관리자\Desktop\hspace\py\OlympicDestroyer.exe.pcap"
    # JSON 형식으로 추출된 데이터를 저장할 파일
    output_file = r"C:\Users\관리자\Desktop\hspace\py\OlympicDestroyer.exe.json"

    start = datetime.now()
    
    # pcap 분할 경로    
    split_file = r"C:\Users\관리자\Desktop\hspace\py\split\\"
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