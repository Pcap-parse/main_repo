import os
import json
import subprocess
from datetime import datetime

def generate_filter(flow):
    ip_src = flow["address_A"]
    ip_dst = flow["address_B"]
    port_src = flow["port_A"]
    port_dst = flow["port_B"]
    proto = flow["layer"].lower()

    #base_filter = f"(ip.src=={ip_src} && ip.dst=={ip_dst} && {proto}.srcport=={port_src} && {proto}.dstport=={port_dst})"
    base_filter = f"(ip.addr=={ip_src} && ip.addr=={ip_dst} && {proto}.port=={port_src} && {proto}.port=={port_dst})"
    return base_filter

def build_combined_filter(flows):
    conditions = []
    for flow in flows:
        f = generate_filter(flow)
        conditions.append(f)
    combined = " || ".join(conditions)
    final_filter = (
        "!( _ws.malformed ) "
        f"&& ({combined})"
    )
    return final_filter

def tshark_extract_frame_numbers(pcap_file, display_filter, output_txt):
    # tshark로는 프레임 번호만 추출, 시간 소요 문제
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number"
    ]
    with open(output_txt, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.PIPE, text=True)

def editcap_extract_frames(pcap_file, frame_txt, output_pcapng):
    """
    editcap을 사용해 특정 프레임만 추출하여 .pcapng 저장
    """
    with open(frame_txt, "r") as f:
        frame_numbers = f.read().splitlines()

    if not frame_numbers:
        print("[INFO] No frames matched the filter.")
        return

    frame_args = []
    for num in frame_numbers:
        frame_args.append(num)

    command = [
        "C:\\Program Files\\Wireshark\\editcap.exe",
        "-r", pcap_file,
        output_pcapng
    ] + frame_args

    subprocess.run(command, stderr=subprocess.PIPE, text=True)

def extract_pcapng_by_frame_filter(pcap_file, output_pcapng, display_filter):

    temp_txt =r"D:\script\wireshark\pcaps\matched_frames.txt"
    tshark_extract_frame_numbers(pcap_file, display_filter, temp_txt)
    editcap_extract_frames(pcap_file, temp_txt, output_pcapng)
    os.remove(temp_txt)

if __name__ == "__main__":
       # 통합 함수: tshark로 필터링 → frame.number 추출 → editcap으로 pcapng 저장

    start = datetime.now()
    json_file=r"D:\script\wireshark\pcaps\10gb.json" # 필터 적용한 json
    with open(json_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
        flows = []
        for layer in raw:
            for f in raw[layer]:
                f["layer"] = layer
                flows.append(f)

    json_display_filter = build_combined_filter(flows)

    extract_pcapng_by_frame_filter(
        pcap_file="D:\\script\\wireshark\\pcaps\\10gb.pcap",
        output_pcapng="D:\\script\\wireshark\\pcaps\\10gb_filterd.pcapng",
        display_filter=json_display_filter
    )
    end = datetime.now()
    print(f"시작시간 : {start.strftime('%H:%M:%S')}")
    print(f"종료시간 : {end.strftime('%H:%M:%S')}")