import re
import json
import subprocess
import os
from glob import glob
from datetime import datetime
from multiprocessing import Pool

def extract_conv(args):
    layer, pcap_file = args
    program = "C:\\Program Files\\Wireshark\\tshark.exe"

    command = [
        program,
        "-r", pcap_file, 
        "-q", 
        "-z", f"conv,{layer}",
        "-o", "nameres.mac_name:FALSE"
    ]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        return layer, None
    
    return layer, result.stdout

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

def process_pcap(pcap_file, output_folder):
    layers = ["eth", "ip", "ipv6", "tcp", "udp"]
    
    with Pool(processes=len(layers)) as pool:
        results = pool.map(extract_conv, [(layer, pcap_file) for layer in layers])
    
    all_conv = {}
    for layer, output in results:
        if output:
            all_conv.update(parse_conv(layer, output))
    
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_file = os.path.join(output_folder, f"{base_name}.json")
    
    with open(output_file, 'w') as json_file:
        json.dump(all_conv, json_file, indent=4)
    
    print(f"Results saved to {output_file}")

def analyze_pcaps(input_folder, output_folder):
    pcap_files = glob(os.path.join(input_folder, "*.pcap*"))
    
    if not pcap_files:
        print("No PCAP files found in the directory.")
        return
    
    os.makedirs(output_folder, exist_ok=True)
    
    for pcap_file in pcap_files:
        print(f"Analyzing {pcap_file}...")
        process_pcap(pcap_file, output_folder)

if __name__ == "__main__":
    input_folder = "D:\\script\\wireshark\\pcaps"
    output_folder = "D:\\script\\wireshark\\pcap_results"
    
    start = datetime.now()
    analyze_pcaps(input_folder, output_folder)
    end = datetime.now()
    
    print(f"시작시간 : {start.hour}시 {start.minute}분 {start.second}초")
    print(f"종료시간 : {end.hour}시 {end.minute}분 {end.second}초")
