import re
import json
import subprocess

# tshark 출력 파일에서 읽기
# tshark -r wrccdc.2017-03-24.010117000000000.pcap -q -z conv,udp > tshark3.txt -> tshark 명령어 실행(리눅스), udp만 추출
#input_file = 'D:\\downloads\\wrccdc.2017-03-24.010540000000000.pcap\\output\\test.txt'  # tshark 출력이 저장된 파일

# 실행할 프로그램과 인자들
program = "C:\\Program Files\\Wireshark\\tshark.exe"  # 실행할 프로그램
file_udp = "D:\\downloads\\wrccdc.2017-03-24.010540000000000.pcap\\wrccdc.2017-03-24.010117000000000.pcap" # pcap 파일 경로
arguments = ["-r", file_udp, "-q", "-z", "conv,udp"]  # 프로그램에 전달할 인자들
command = [program] + arguments
# 프로그램 실행
result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
# 출력 결과를 변수에 저장
output_txt = result.stdout

output_file = 'D:\\downloads\\wrccdc.2017-03-24.010540000000000.pcap\\output\\test.json'  # JSON 형식으로 추출된 데이터를 저장할 파일

# 정규표현식 패턴 (각 항목을 정확히 추출)
pattern = re.compile(r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)')

# 정규표현식으로 데이터 추출
matches = pattern.findall(output_txt)

# 데이터 리스트로 저장
data = []

# 추출한 값들을 리스트에 저장
for match in matches:
    # IP와 포트를 분리
    src_ip, src_port = match[0].rsplit(":", 1)
    dst_ip, dst_port = match[1].rsplit(":", 1)

    # 각 값 저장
    packet_count_src = match[2]
    src_bytes = match[3]
    packet_count_dst = match[4]
    dst_bytes = match[5]
    total_packets = match[6]
    total_bytes = match[7]
    duration = match[9]
    relative_start = match[8]

    # 딕셔너리로 변환
    conversation = {
        "addr_a": src_ip,
        "port_a": src_port,
        "addr_b": dst_ip,
        "port_b": dst_port,
        "bytes": total_bytes,
        "bytes_atob": dst_bytes,
        "bytes_btoa": src_bytes,
        "packets": total_packets,
        "packets_atob": packet_count_dst,
        "packets_btoa": packet_count_src,
        "rel_start": relative_start,
        "duration": duration,
        "stream_id": -1
    }
    # 리스트에 추가
    data.append(conversation)

# 딕셔너리를 시간순으로 정렬 후 순서대로 인덱스 주입
data.sort(key=lambda x: float(x["rel_start"]))
for i in data:
    i["stream_id"] = data.index(i)

# JSON 형식으로 저장
with open(output_file, 'w') as json_file:
    json.dump(data, json_file, indent=4)

print(f"Data saved to {output_file}")