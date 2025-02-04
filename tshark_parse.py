import re
import json
import subprocess
import os
from glob import glob
from datetime import datetime

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
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 에러 확인
    if result.returncode != 0:
        raise Exception(f"layer {layer}: {result.stderr}")
    
    return result.stdout


def run_editcap(input_file, output_file):

    program = "C:\\Program Files\\Wireshark\\editcap.exe"

    # 명령어
    command = [
        program,
        "-c", "1000000", # 패킷 10만개 단위로 분할
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

    stream_id = 0
    for conv in sorted(data, key=lambda x: x["rel_start"]):
        conv["stream_id"] = stream_id
        stream_id += 1

    return {layer: data}


def analyze_pcaps(input_folder, output_folder):
    # 폴더 내 모든 pcap 파일 찾기
    pcap_files = glob(os.path.join(input_folder, "*.pcap*"))
    
    if not pcap_files:
        print("No PCAP files found in the directory.")
        return

    # 결과 저장 폴더가 없으면 생성
    os.makedirs(output_folder, exist_ok=True)

    layers = ["eth", "ip", "ipv6", "tcp", "udp"]

    for pcap_file in pcap_files:
        print(f"Analyzing {pcap_file}...")

        # 파일명에서 확장자 제거하고 JSON 파일명 생성
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        output_file = os.path.join(output_folder, f"{base_name}.json")

        all_conv = {}

        for layer in layers:
            print(f"Extracting {layer} conversations...")
            tshark_output = extract_conv(layer, pcap_file)
            convs = parse_conv(layer, tshark_output)
            all_conv.update(convs)

        with open(output_file, 'w') as json_file:
            json.dump(all_conv, json_file, indent=4)

        print(f"Results saved to {output_file}")


if __name__ == "__main__":
    input_folder = "D:\script\wireshark\pcaps"  # PCAP 파일이 있는 폴더
    output_folder = "D:\script\wireshark\pcap_results"  # 분석 결과를 저장할 폴더

    start = datetime.now()
    analyze_pcaps(input_folder, output_folder)


    print(f"시작시간 : {start.hour}시 {start.minute}분 {start.second}초")
    end = datetime.now()
    print(f"종료시간 : {end.hour}시 {end.minute}분 {end.second}초")
