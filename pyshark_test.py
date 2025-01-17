import pyshark
import sys
import json

#select_layer = sys.argv[1]
# pcap 파일 경로
pcap_file_path = "C:\\Users\\관리자\\Desktop\\hspace\\py\\OlympicDestroyer.exe.pcap"  # 분석할 pcap 파일 경로 입력
capture = pyshark.FileCapture(pcap_file_path)

eth_id = []
ip_id = []
ipv6_id = []
tcp_id = []
udp_id = []

class pk_byte: # 여기를 Conversations 요소를 변수로
    addrA: str = None
    addrB: str = None
    portA: str = None
    portB: str = None
    total_packet: int = 0
    AtoB_packet: int = 0
    BtoA_packet: int = 0
    total_byte: int = 0
    AtoB_byte: int = 0
    BtoA_byte: int = 0
    min_time: str = "0.0"
    max_time: str = "0.0"
    relative: str = None
    status: int = 0

eth_list = [pk_byte()]
ip_list = [pk_byte()]
ipv6_list = [pk_byte()]
tcp_list = [pk_byte()]
udp_list = [pk_byte()]

def all_conv(packet, stream_index, type, src, dst):
    match type:
        case 1:
            global eth_list
            all_list = eth_list
        case 2:
            global ip_list
            all_list = ip_list
        case 3:
            global ipv6_list
            all_list = ipv6_list
        case 4:
            global tcp_list
            all_list = tcp_list
        case 5:
            global udp_list
            all_list = udp_list

    all_pk = all_list[stream_index]
    if all_pk.addrA == None:
        all_pk.addrA, all_pk.addrB = src, dst
    all_pk.total_packet += 1
    all_pk.total_byte += int(packet.length)
    if all_pk.addrA == src:
        all_pk.AtoB_packet += 1
        all_pk.AtoB_byte += int(packet.length)
    elif all_pk.addrA == dst:
        all_pk.BtoA_packet += 1
        all_pk.BtoA_byte += int(packet.length)
    if all_pk.min_time ==  "0.0":
        all_pk.min_time, all_pk.min_time = packet.sniff_timestamp, packet.sniff_timestamp
    if float(all_pk.min_time) > float(packet.sniff_timestamp):
        all_pk.min_time = packet.sniff_timestamp
    elif float(all_pk.max_time) < float(packet.sniff_timestamp):
        all_pk.max_time = packet.sniff_timestamp
    if all_pk.relative == None:
        all_pk.relative = packet.frame_info.time_relative

def eth_conv(packet):
    global eth_list
    stream_index = int(packet.eth.stream)
    while (len(eth_list) <= stream_index):
        eth_list.append(pk_byte())
    src, dst = packet.eth.src, packet.eth.dst
    all_conv(packet,stream_index, 1, src, dst)

def ip_conv(packet):
    global ip_list
    stream_index = int(packet.ip.stream)  
    while (len(ip_list) <= stream_index):
        ip_list.append(pk_byte()) 
    src, dst = packet.ip.src, packet.ip.dst
    all_conv(packet, stream_index, 2, src, dst)

def ipv6_conv(packet):
    global ipv6_list
    stream_index = int(packet.ipv6.stream)
    while (len(ipv6_list) <= stream_index):
        ipv6_list.append(pk_byte())   
    src, dst = packet.ipv6.src, packet.ipv6.dst
    all_conv(packet, stream_index, 3, src, dst)

def tcp_conv(packet):
    global tcp_list
    stream_index = int(packet.tcp.stream)
    while (len(tcp_list) <= stream_index):
        tcp_list.append(pk_byte())
    src, dst = packet.ip.src, packet.ip.dst
    if tcp_list[stream_index].portA == None:
        tcp_list[stream_index].portA, tcp_list[stream_index].portB= packet.tcp.srcport, packet.tcp.dstport
    all_conv(packet, stream_index, 4, src, dst)

def udp_conv(packet):
    global udp_list
    stream_index = int(packet.udp.stream)
    while (len(udp_list) <= stream_index):
        udp_list.append(pk_byte())
    if packet.eth.type == '0x86dd':
        src, dst = packet.ipv6.src, packet.ipv6.dst
    else:
        src, dst = packet.ip.src, packet.ip.dst
    if udp_list[stream_index].portA == None:
        udp_list[stream_index].portA, udp_list[stream_index].portB = packet.udp.srcport, packet.udp.dstport
    all_conv(packet, stream_index, 5, src, dst)

def byte_change(byte):
    if byte > 1000:
        return f"{str(round(byte/1000))} kB"
    else:
        return f"{str(round(byte))} 바이트"

def bit_per_sec(bytes, seconds):
    if seconds == 0:
        return "0 bits/s"
    bits = bytes * 8
    bits_per_sec = bits / seconds
    if bits_per_sec > 10000:
        return f"{round(bits_per_sec / 1000)} kbps"
    else:
        return f"{round(bits_per_sec)} bits/s"
  
for packet in capture:
    try:
        if 'ETH' in packet:
            if packet.eth.stream not in eth_id:
                eth_id.append(packet.eth.stream)
            eth_conv(packet)
        if 'IP' in packet:
            if packet.ip.stream not in ip_id:
                ip_id.append(packet.ip.stream)    
            ip_conv(packet)    
        if 'IPV6' in packet:
            if packet.ipv6.stream not in ipv6_id:
                ipv6_id.append(packet.ipv6.stream)
            ipv6_conv(packet)
        if 'TCP' in packet:
            if packet.tcp.stream not in tcp_id:
                tcp_id.append(packet.tcp.stream)
            tcp_conv(packet)
        if 'UDP' in packet:
            if packet.udp.stream not in udp_id:
                udp_id.append(packet.udp.stream)
            udp_conv(packet)
    except AttributeError:
        pass


eth_p = open("eth_packet.json","w", encoding='UTF-8-sig')
ip_p = open("ip_packet.json","w", encoding='UTF-8-sig')
ipv6_p = open("ipv6_packet.json","w", encoding='UTF-8-sig')
tcp_p = open("tcp_packet.json","w", encoding='UTF-8-sig')
udp_p = open("udp_packet.json","w", encoding='UTF-8-sig')
addr_p = [eth_p, ip_p, ipv6_p, tcp_p, udp_p]
addr_list = [eth_list, ip_list, ipv6_list, tcp_list, udp_list]

for i in range(0,len(addr_p)):
    for addr_pk in addr_list[i]:
        relative = round(float(addr_pk.relative),6)
        addr_dic = {
            "스트림 ID": str(addr_list[i].index(addr_pk)),
            "주소 A": addr_pk.addrA,
            "주소 B": addr_pk.addrB,
            "패킷": str(addr_pk.total_packet),
            "바이트": byte_change(addr_pk.total_byte),
            "Bytes A → B": byte_change(addr_pk.AtoB_byte),
            "Bytes B → A": byte_change(addr_pk.BtoA_byte),
            "Packets A → B": str(addr_pk.AtoB_packet),
            "Packets B → A": str(addr_pk.BtoA_packet),
            "상대 시작": f"{relative:.6f}",
            "지속 시간": str(round(float(addr_pk.max_time) - float(addr_pk.min_time), 4)),
            "Bits/s A → B": bit_per_sec(addr_pk.AtoB_byte, float(addr_pk.max_time) - float(addr_pk.min_time)),
            "Bits/s B → A": bit_per_sec(addr_pk.BtoA_byte, float(addr_pk.max_time) - float(addr_pk.min_time))
                }
            
        addr_p[i].write(json.dumps(addr_dic, ensure_ascii=False, indent=4))
        addr_p[i].write(",\n")

eth_p.close()
ip_p.close()
ipv6_p.close()
tcp_p.close()
udp_p.close()
capture.close()