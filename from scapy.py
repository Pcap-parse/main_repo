import re
import json
import subprocess

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
    
    # 결과 반환
    return result.stdout


def parse_conv(layer, tshark_output):

    # 정규표현식 패턴 (각 항목을 정확히 추출)
    pattern = re.compile(r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)')

    # 데이터 리스트로 저장
    data = []

    # 정규표현식으로 데이터 추출
    matches = pattern.findall(tshark_output)

    # 추출한 값들을 리스트에 저장
    for match in matches:
        # 공통 부분: IP 및 포트 관련 정보 추출
        src_ip, dst_ip = match[0], match[1]

        # TCP/UDP의 경우 포트 포함
        if layer in ["tcp", "udp"]:
            src_ip, src_port = src_ip.rsplit(":", 1)
            dst_ip, dst_port = dst_ip.rsplit(":", 1)
            conversation = {
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port
            }
        else:
            conversation = {
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }

        # 딕셔너리로 변환 + 각 값 저장
        conversation.update({
            "bytes": match[7],
            "bytes_atob": match[5],
            "bytes_btoa": match[3],
            "packets": match[6],
            "packets_atob": match[4],
            "packets_btoa": match[2],
            "rel_start": match[8],
            "duration": match[9],
            "stream_id": -1
        })

        # 리스트에 추가
        data.append(conversation)

    # 딕셔너리를 시간순으로 정렬 후 순서대로 인덱스 주입
    data.sort(key=lambda x: float(x["rel_start"]))
    for i in data:
        i["stream_id"] = data.index(i)

    return {layer : data}


def main():
    # pcap 파일 경로
    pcap_file = "D:\\downloads\\wrccdc.2017-03-24.010540000000000.pcap\\wrccdc.2017-03-24.010117000000000.pcap"
    # JSON 형식으로 추출된 데이터를 저장할 파일
    output_file = 'D:\\downloads\\wrccdc.2017-03-24.010540000000000.pcap\\output\\test.json'

    # 레이어 목록
    layers = ["eth", "ip", "ipv6", "tcp", "udp"]
    all_conv = {}

    # 각 레이어의 데이터를 추출 및 파싱
    for layer in layers:
        print(f"Extracting {layer} conversations...")
        tshark_output = extract_conv(layer, pcap_file)
        convs = parse_conv(layer, tshark_output)
        all_conv.update(convs)

    # JSON 형식으로 저장
    with open(output_file, 'w') as json_file:
        json.dump(all_conv, json_file, indent=4)

    print(f"Data saved to {output_file}")

if __name__ == "__main__":
    main()