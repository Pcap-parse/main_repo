import pyshark
import json
from collections import defaultdict

def extract_conversation_details(pcap_file, output_json):
    """
    PCAP 파일에서 대화 데이터를 추출하여 요청된 형식으로 JSON에 저장.

    :param pcap_file: 분석할 PCAP 파일 경로
    :param output_json: 저장할 JSON 파일 경로
    """
    try:
        # PCAP 파일 읽기
        cap = pyshark.FileCapture(pcap_file)

        # 프로토콜별 대화 데이터를 저장할 딕셔너리
        def default_conversation():
            return {
                "Bits/s A to B": "",
                "Bits/s B to A": "",
                "Bytes": 0,
                "Bytes A to B": 0,
                "Bytes B to A": 0,
                "Duration": 0.0,
                "Packets": 0,
                "Packets A to B": 0,
                "Packets B to A": 0,
                "Percent Filtered": 0.0,
                "Rel Start": 0.0,
                "Stream ID": "-1",
                "Total Packets": 0,
            }

        conversations = {
            "Ethernet": defaultdict(default_conversation),
            "IPv4": defaultdict(default_conversation),
            "IPv6": defaultdict(default_conversation),
            "TCP": defaultdict(default_conversation),
            "UDP": defaultdict(default_conversation)
        }

        # 첫 번째 패킷의 타임스탬프를 기준으로 상대 시간 계산
        start_time = None

        for pkt in cap:
            try:
                # 첫 패킷 시간 저장
                if start_time is None:
                    start_time = float(pkt.sniff_timestamp)

                timestamp = float(pkt.sniff_timestamp)
                rel_start = timestamp - start_time

                # Ethernet 처리
                if hasattr(pkt, "eth"):  # Ethernet 계층 존재 여부 확인
                    try:
                        eth_src = pkt.eth.src  # 소스 MAC 주소
                        eth_dst = pkt.eth.dst  # 목적지 MAC 주소
                        length = int(pkt.length)  # 패킷 길이

                        # Key 생성
                        key = tuple(sorted([eth_src, eth_dst]))

                        # 상대 시작 시간 업데이트
                        if conversations["Ethernet"][key]["Rel Start"] == 0.0:
                            conversations["Ethernet"][key]["Rel Start"] = rel_start

                        # 패킷 및 바이트 수 업데이트
                        conversations["Ethernet"][key]["Packets"] += 1
                        conversations["Ethernet"][key]["Bytes"] += length

                        # A → B 방향 (소스 < 목적지)
                        if eth_src < eth_dst:
                            conversations["Ethernet"][key]["Packets A to B"] += 1
                            conversations["Ethernet"][key]["Bytes A to B"] += length
                        else:  # B → A 방향
                            conversations["Ethernet"][key]["Packets B to A"] += 1
                            conversations["Ethernet"][key]["Bytes B to A"] += length

                        # Stream ID 추가
                        stream_id = getattr(pkt.eth, "stream", "-1")
                        conversations["Ethernet"][key]["Stream ID"] = stream_id

                        # Duration 업데이트
                        conversations["Ethernet"][key]["Duration"] = max(
                            conversations["Ethernet"][key]["Duration"],
                            timestamp - start_time
                        ) - conversations["Ethernet"][key]["Rel Start"]

                        # Bits/s 계산
                        if conversations["Ethernet"][key]["Duration"] > 0:
                            conversations["Ethernet"][key]["Bits/s A to B"] = (conversations["Ethernet"][key]["Bytes A to B"] * 8) / conversations["Ethernet"][key]["Duration"]
                            conversations["Ethernet"][key]["Bits/s B to A"] = (conversations["Ethernet"][key]["Bytes B to A"] * 8) / conversations["Ethernet"][key]["Duration"]

                    except AttributeError as e:
                        print(f"Ethernet 처리 중 예외 발생: {e}")
                        continue

                # IPv4 처리
                if hasattr(pkt, "ip"):  # IPv4 계층 존재 여부 확인
                    try:
                        src_ip = pkt.ip.src  # 소스 IP 주소
                        dst_ip = pkt.ip.dst  # 목적지 IP 주소
                        length = int(pkt.length)  # 패킷 길이

                        # Key 생성
                        key = tuple(sorted([src_ip, dst_ip]))

                        # 상대 시작 시간 업데이트
                        if conversations["IPv4"][key]["Rel Start"] == 0.0:
                            conversations["IPv4"][key]["Rel Start"] = rel_start

                        # 패킷 및 바이트 수 업데이트
                        conversations["IPv4"][key]["Packets"] += 1
                        conversations["IPv4"][key]["Bytes"] += length

                        # A → B 방향 (소스 < 목적지)
                        if src_ip < dst_ip:
                            conversations["IPv4"][key]["Packets A to B"] += 1
                            conversations["IPv4"][key]["Bytes A to B"] += length
                        else:  # B → A 방향
                            conversations["IPv4"][key]["Packets B to A"] += 1
                            conversations["IPv4"][key]["Bytes B to A"] += length

                        # Stream ID 추가
                        stream_id = getattr(pkt.ip, "stream", "-1")
                        conversations["IPv4"][key]["Stream ID"] = stream_id

                        # Duration 업데이트
                        conversations["IPv4"][key]["Duration"] = max(
                            conversations["IPv4"][key]["Duration"],
                            timestamp - start_time
                        ) - conversations["IPv4"][key]["Rel Start"]

                        # Bits/s 계산
                        if conversations["IPv4"][key]["Duration"] > 0:
                            conversations["IPv4"][key]["Bits/s A to B"] = (conversations["IPv4"][key]["Bytes A to B"] * 8) / conversations["IPv4"][key]["Duration"]
                            conversations["IPv4"][key]["Bits/s B to A"] = (conversations["IPv4"][key]["Bytes B to A"] * 8) / conversations["IPv4"][key]["Duration"]

                    except AttributeError as e:
                        print(f"IPv4 처리 중 예외 발생: {e}")
                        continue

                # IPv6 처리
                if hasattr(pkt, "ipv6"):  # IPv6 계층 존재 여부 확인
                    try:
                        src_ip = pkt.ipv6.src  # 소스 IPv6 주소
                        dst_ip = pkt.ipv6.dst  # 목적지 IPv6 주소
                        length = int(pkt.length)  # 패킷 길이

                        # Key 생성
                        key = tuple(sorted([src_ip, dst_ip]))

                        # 상대 시작 시간 업데이트
                        if conversations["IPv6"][key]["Rel Start"] == 0.0:
                            conversations["IPv6"][key]["Rel Start"] = rel_start

                        # 패킷 및 바이트 수 업데이트
                        conversations["IPv6"][key]["Packets"] += 1
                        conversations["IPv6"][key]["Bytes"] += length

                        # A → B 방향 (소스 < 목적지)
                        if src_ip < dst_ip:
                            conversations["IPv6"][key]["Packets A to B"] += 1
                            conversations["IPv6"][key]["Bytes A to B"] += length
                        else:  # B → A 방향
                            conversations["IPv6"][key]["Packets B to A"] += 1
                            conversations["IPv6"][key]["Bytes B to A"] += length

                        # Stream ID 추가
                        stream_id = getattr(pkt.ipv6, "stream", "-1")
                        conversations["IPv6"][key]["Stream ID"] = stream_id

                        # Duration 업데이트
                        conversations["IPv6"][key]["Duration"] = max(
                            conversations["IPv6"][key]["Duration"],
                            timestamp - start_time
                        ) - conversations["IPv6"][key]["Rel Start"]

                        # Bits/s 계산
                        if conversations["IPv6"][key]["Duration"] > 0:
                            conversations["IPv6"][key]["Bits/s A to B"] = (conversations["IPv6"][key]["Bytes A to B"] * 8) / conversations["IPv6"][key]["Duration"]
                            conversations["IPv6"][key]["Bits/s B to A"] = (conversations["IPv6"][key]["Bytes B to A"] * 8) / conversations["IPv6"][key]["Duration"]

                    except AttributeError as e:
                        print(f"IPv6 처리 중 예외 발생: {e}")
                        continue

                # TCP 처리
                if "TCP" in pkt:
                    src_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "src", None)
                    dst_ip = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "dst", None)
                    src_port = getattr(pkt.tcp, "srcport", None)
                    dst_port = getattr(pkt.tcp, "dstport", None)
                    if not src_ip or not dst_ip or not src_port or not dst_port:
                        continue
                    # 튜플 사용
                    key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                    if conversations["TCP"][key]["Rel Start"] == 0.0:
                        conversations["TCP"][key]["Rel Start"] = rel_start

                    # 패킷 및 바이트 수 업데이트
                    length = int(pkt.length)
                    conversations["TCP"][key]["Packets"] += 1
                    conversations["TCP"][key]["Bytes"] += length
                    if (src_ip, src_port) < (dst_ip, dst_port):  # A → B 방향
                        conversations["TCP"][key]["Packets A to B"] += 1
                        conversations["TCP"][key]["Bytes A to B"] += length
                    else:  # B → A 방향
                        conversations["TCP"][key]["Packets B to A"] += 1
                        conversations["TCP"][key]["Bytes B to A"] += length

                    # Stream ID 추가
                    stream_id = getattr(pkt.tcp, "stream", "-1")
                    conversations["TCP"][key]["Stream ID"] = stream_id

                    # Duration 업데이트
                    conversations["TCP"][key]["Duration"] = max(
                        conversations["TCP"][key]["Duration"],
                        timestamp - start_time
                    ) - conversations["TCP"][key]["Rel Start"]

                    # Bits/s 계산
                    if conversations["TCP"][key]["Duration"] > 0:
                        conversations["TCP"][key]["Bits/s A to B"] = (conversations["TCP"][key]["Bytes A to B"] * 8) / conversations["TCP"][key]["Duration"]
                        conversations["TCP"][key]["Bits/s B to A"] = (conversations["TCP"][key]["Bytes B to A"] * 8) / conversations["TCP"][key]["Duration"]

                # UDP 처리
                if "UDP" in pkt:
                    src_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "src", None)
                    dst_ip = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "dst", None)
                    src_port = getattr(pkt.udp, "srcport", None)
                    dst_port = getattr(pkt.udp, "dstport", None)
                    if not src_ip or not dst_ip or not src_port or not dst_port:
                        continue
                    # 튜플 사용
                    key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                    if conversations["UDP"][key]["Rel Start"] == 0.0:
                        conversations["UDP"][key]["Rel Start"] = rel_start

                    # 패킷 및 바이트 수 업데이트
                    length = int(pkt.length)
                    conversations["UDP"][key]["Packets"] += 1
                    conversations["UDP"][key]["Bytes"] += length
                    if (src_ip, src_port) < (dst_ip, dst_port):  # A → B 방향
                        conversations["UDP"][key]["Packets A to B"] += 1
                        conversations["UDP"][key]["Bytes A to B"] += length
                    else:  # B → A 방향
                        conversations["UDP"][key]["Packets B to A"] += 1
                        conversations["UDP"][key]["Bytes B to A"] += length

                    # Stream ID 추가
                    stream_id = getattr(pkt.udp, "stream", "-1")
                    conversations["UDP"][key]["Stream ID"] = stream_id

                    # Duration 업데이트
                    conversations["UDP"][key]["Duration"] = max(
                        conversations["UDP"][key]["Duration"],
                        timestamp - start_time
                    ) - conversations["UDP"][key]["Rel Start"]

                    # Bits/s 계산
                    if conversations["UDP"][key]["Duration"] > 0:
                        conversations["UDP"][key]["Bits/s A to B"] = (conversations["UDP"][key]["Bytes A to B"] * 8) / conversations["UDP"][key]["Duration"]
                        conversations["UDP"][key]["Bits/s B to A"] = (conversations["UDP"][key]["Bytes B to A"] * 8) / conversations["UDP"][key]["Duration"]

            except AttributeError:
                continue  # 필요한 속성이 없는 패킷은 스킵

        # 데이터를 JSON 형식으로 변환
        result = {protocol: [] for protocol in conversations}
        for protocol, convs in conversations.items():
            for key, stats in convs.items():
                if protocol in ["TCP", "UDP"]:
                    if len(key) != 2:
                        continue
                    (addr_a, port_a), (addr_b, port_b) = sorted(key)
                    result[protocol].append({
                        "Address A": addr_a,
                        "Port A": port_a,
                        "Address B": addr_b,
                        "Port B": port_b,
                        **stats
                    })
                else:
                    if len(key) != 2:
                        continue
                    (addr_a, addr_b) = sorted(key)
                    result[protocol].append({
                        "Address A": addr_a,
                        "Address B": addr_b,
                        **stats
                    })

        # JSON 파일 저장
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"대화 데이터가 {output_json}에 저장되었습니다.")

    except FileNotFoundError:
        print("PCAP 파일을 찾을 수 없습니다. 경로를 확인하세요.")
    except Exception as e:
        print(f"오류 발생: {e}")

# 사용 예제
pcap_path = "D:/script/wireshark/aaa.pcap"  # 분석할 PCAP 파일 경로
output_json = "D:/script/wireshark/conversation_details4.json"  # JSON 파일 경로
extract_conversation_details(pcap_path, output_json)
