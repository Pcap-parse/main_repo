import os
import json
import subprocess
from datetime import datetime
import re
from multiprocessing import Pool, cpu_count
import filter_conversations_test

def tshark_extract_streams(pcap_file, display_filter, output_txt):
    # tshark로는 프레임 번호만 추출, 시간 소요 문제
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "tcp.stream"
        "-e", "udp.stream"
    ]
    with open(output_txt, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.PIPE, text=True)