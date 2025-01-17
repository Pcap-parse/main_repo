# main_repo

1. pcap 파싱
json 형식으로 파싱

2. 필터 만들기
블랙리스트, 화이트리스트 -> 원하는 값을 필터링 시킬수 있게



Wireshark에서 사용할 수 있는 필터는 크게 두 가지로 나뉩니다:

캡처 필터 (Capture Filter)
캡처할 데이터 패킷을 제한하는 데 사용됩니다. 캡처 시작 전에 설정하며, libpcap/BPF 구문을 사용합니다. 캡처 필터는 매우 제한적이고 패킷 캡처 시점에만 적용됩니다.

디스플레이 필터 (Display Filter)
이미 캡처된 패킷을 분석할 때 사용되며, Wireshark의 고유한 구문을 사용합니다. 캡처된 데이터를 상세히 분석하는 데 유용합니다.

아래는 각각의 필터링 조건을 구체적으로 나열한 내용입니다.

1. 캡처 필터 (Capture Filter)

캡처 필터는 다음과 같은 형식으로 사용됩니다:

IP 주소 관련 필터

특정 IP 주소: host 192.168.1.1

특정 네트워크: net 192.168.1.0/24

출발지 IP 주소: src host 192.168.1.1

목적지 IP 주소: dst host 192.168.1.1

포트 관련 필터

특정 포트: port 80

출발지 포트: src port 80

목적지 포트: dst port 80

포트 범위: portrange 1000-2000

프로토콜 관련 필터

특정 프로토콜: tcp, udp, icmp, arp, ip

MAC 주소 관련 필터

특정 MAC 주소: ether host 00:11:22:33:44:55

출발지 MAC 주소: ether src 00:11:22:33:44:55

목적지 MAC 주소: ether dst 00:11:22:33:44:55

패킷 크기 필터

특정 크기 이상의 패킷: greater 100

특정 크기 이하의 패킷: less 500

2. 디스플레이 필터 (Display Filter)

디스플레이 필터는 훨씬 더 세부적인 필터링이 가능합니다. Wireshark의 강력한 분석 도구입니다.

기본 조건

프로토콜: http, dns, tcp, udp, icmp

특정 IP 주소:

ip.addr == 192.168.1.1

ip.src == 192.168.1.1

ip.dst == 192.168.1.1

포트 필터:

tcp.port == 80

udp.port == 53

MAC 주소:

eth.addr == 00:11:22:33:44:55

eth.src == 00:11:22:33:44:55

eth.dst == 00:11:22:33:44:55

논리 연산

AND: && (또는 and)

예: ip.src == 192.168.1.1 && tcp.port == 80

OR: || (또는 or)

예: ip.src == 192.168.1.1 || ip.dst == 192.168.1.1

NOT: ! (또는 not)

예: !http

프로토콜 상세 필터

HTTP:

http.request (HTTP 요청)

http.response (HTTP 응답)

http.host == "example.com"

DNS:

dns.qry.name == "example.com" (쿼리 이름)

dns.flags.response == 1 (응답 패킷)

TCP:

tcp.flags.syn == 1 (SYN 플래그)

tcp.flags.ack == 1 (ACK 플래그)

tcp.analysis.retransmission (재전송 패킷)

ICMP:

icmp.type == 8 (Echo Request)

icmp.type == 0 (Echo Reply)

ARP:

arp.opcode == 1 (ARP 요청)

arp.opcode == 2 (ARP 응답)

시간 필터

특정 시간 이후: frame.time >= "Jan 17, 2025 12:00:00"

특정 시간 이전: frame.time <= "Jan 17, 2025 12:30:00"

패킷 크기 필터

frame.len > 1000 (패킷 크기 1000 바이트 이상)

frame.len < 500 (패킷 크기 500 바이트 이하)

오류 탐지 필터

tcp.analysis.lost_segment (손실된 세그먼트)

tcp.analysis.duplicate_ack (중복 ACK)

ip.checksum.bad (잘못된 체크섬)
