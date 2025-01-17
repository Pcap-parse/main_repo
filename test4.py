import pyshark
import json
from collections import defaultdict


# 대화의 첫 번째 패킷 여부를 추적하는 외부 상태 관리 변수
rel_start_set_flags = {}

def update_conversation(conversations, protocol, key, length, direction, rel_start, timestamp, stream_id):
    """
    대화 데이터 업데이트.
    """
    conv = conversations[protocol][key]

    # 첫 번째 패킷인지 확인
    if key not in rel_start_set_flags:
        conv["Rel Start"] = rel_start
        rel_start_set_flags[key] = True  # 첫 번째 패킷 처리 완료 플래그 설정

    conv["Packets"] += 1
    conv["Bytes"] += length

    if direction == "A to B":
        conv["Packets A to B"] += 1
        conv["Bytes A to B"] += length
    else:
        conv["Packets B to A"] += 1
        conv["Bytes B to A"] += length

    conv["Stream ID"] = stream_id

    # Duration 계산
    current_duration = timestamp - conv["Rel Start"]
    conv["Duration"] = max(conv["Duration"], current_duration)

    if conv["Duration"] > 0:
        conv["Bits/s A to B"] = (conv["Bytes A to B"] * 8) / conv["Duration"]
        conv["Bits/s B to A"] = (conv["Bytes B to A"] * 8) / conv["Duration"]


def extract_conversation_details(pcap_file, output_json):
    """
    PCAP 파일에서 대화 데이터를 추출하여 요청된 형식으로 JSON에 저장.
    """
    try:
        cap = pyshark.FileCapture(pcap_file)
        start_time = None  # 패킷 캡처 시작 시간을 초기화
        
        def default_conversation():
            return {
                "Bits/s A to B": "", "Bits/s B to A": "", "Bytes": 0, "Bytes A to B": 0, "Bytes B to A": 0,
                "Duration": 0.0, "Packets": 0, "Packets A to B": 0, "Packets B to A": 0, "Percent Filtered": 0.0,
                "Rel Start": 0.0, "Stream ID": "-1", "Total Packets": 0,
            }
        
        conversations = {protocol: defaultdict(default_conversation) for protocol in ["Ethernet", "IPv4", "IPv6", "TCP", "UDP"]}
        
        for pkt in cap:
            try:
                if start_time is None:
                    start_time = float(pkt.sniff_timestamp)  # 첫 패킷의 시간 기록
                timestamp = float(pkt.sniff_timestamp)
                rel_start = timestamp - start_time

                # Ethernet
                if hasattr(pkt, "eth"):
                    eth_src, eth_dst, length = pkt.eth.src, pkt.eth.dst, int(pkt.length)
                    key = tuple(sorted([eth_src, eth_dst]))
                    direction = "A to B" if eth_src < eth_dst else "B to A"
                    stream_id = getattr(pkt.eth, "stream", "-1")
                    update_conversation(conversations, "Ethernet", key, length, direction, rel_start, timestamp, stream_id, start_time)

                # IPv4
                if hasattr(pkt, "ip"):
                    src_ip, dst_ip, length = pkt.ip.src, pkt.ip.dst, int(pkt.length)
                    key = tuple(sorted([src_ip, dst_ip]))
                    direction = "A to B" if src_ip < dst_ip else "B to A"
                    stream_id = getattr(pkt.ip, "stream", "-1")
                    update_conversation(conversations, "IPv4", key, length, direction, rel_start, timestamp, stream_id, start_time)

                # IPv6
                if hasattr(pkt, "ipv6"):
                    src_ip, dst_ip, length = pkt.ipv6.src, pkt.ipv6.dst, int(pkt.length)
                    key = tuple(sorted([src_ip, dst_ip]))
                    direction = "A to B" if src_ip < dst_ip else "B to A"
                    stream_id = getattr(pkt.ipv6, "stream", "-1")
                    update_conversation(conversations, "IPv6", key, length, direction, rel_start, timestamp, stream_id, start_time)

                # TCP
                if "TCP" in pkt:
                    src_ip, dst_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "src", None), \
                                      getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "dst", None)
                    src_port, dst_port, length = getattr(pkt.tcp, "srcport", None), getattr(pkt.tcp, "dstport", None), int(pkt.length)
                    if not src_ip or not dst_ip or not src_port or not dst_port:
                        continue
                    key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                    direction = "A to B" if (src_ip, src_port) < (dst_ip, dst_port) else "B to A"
                    stream_id = getattr(pkt.tcp, "stream", "-1")
                    update_conversation(conversations, "TCP", key, length, direction, rel_start, timestamp, stream_id, start_time)

                # UDP
                if "UDP" in pkt:
                    src_ip, dst_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "src", None), \
                                      getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else getattr(pkt.ipv6, "dst", None)
                    src_port, dst_port, length = getattr(pkt.udp, "srcport", None), getattr(pkt.udp, "dstport", None), int(pkt.length)
                    if not src_ip or not dst_ip or not src_port or not dst_port:
                        continue
                    key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                    direction = "A to B" if (src_ip, src_port) < (dst_ip, dst_port) else "B to A"
                    stream_id = getattr(pkt.udp, "stream", "-1")
                    update_conversation(conversations, "UDP", key, length, direction, rel_start, timestamp, stream_id, start_time)

            except AttributeError:
                continue  # 필요한 속성이 없는 패킷은 스킵

        # 데이터를 JSON 형식으로 변환
        result = {protocol: [] for protocol in conversations}
        for protocol, convs in conversations.items():
            for key, stats in convs.items():
                if protocol in ["TCP", "UDP"]:
                    (addr_a, port_a), (addr_b, port_b) = sorted(key)
                    result[protocol].append({
                        "Address A": addr_a, "Port A": port_a, "Address B": addr_b, "Port B": port_b, **stats
                    })
                else:
                    (addr_a, addr_b) = sorted(key)
                    result[protocol].append({
                        "Address A": addr_a, "Address B": addr_b, **stats
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
