import re
import json

# tshark 출력 파일에서 읽기
# tshark -r wrccdc.2017-03-24.010117000000000.pcap -q -z conv,udp > tshark3.txt -> tshark 명령어 실행(리눅스), udp만 추출
input_file = 'tshark3.txt'  # tshark 출력이 저장된 파일
output_file = 'udp_conversations.json'  # JSON 형식으로 추출된 데이터를 저장할 파일

# 정규표현식 패턴 (각 항목을 정확히 추출)
pattern = re.compile(r'([0-9a-fA-F.:]+(?:\:\d+)?) +<-> +([0-9a-fA-F.:]+(?:\:\d+)?) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +(\d+) +([\d,]+ (?:MB|kB|bytes)) +([\d,]+) +([\d,]+ (?:MB|kB|bytes)) +(\d+.\d+) +(\d+.\d+)')

# 파일 읽기
with open(input_file, 'r') as file:
    tshark_output = file.read()

# 정규표현식으로 데이터 추출
matches = pattern.findall(tshark_output)

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
    duration = match[8]
    relative_start = match[9]

    # 딕셔너리로 변환
    conversation = {
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "packet_count_source": packet_count_src,
        "source_bytes": src_bytes,
        "packet_count_destination": packet_count_dst,
        "destination_bytes": dst_bytes,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration": duration,
        "relative_start": relative_start
    }

    # 리스트에 추가
    data.append(conversation)

# JSON 형식으로 저장
with open(output_file, 'w') as json_file:
    json.dump(data, json_file, indent=4)

print(f"Data saved to {output_file}")
