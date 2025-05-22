import subprocess
import os
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import shutil
from lib.wireshark_api import wireshark_api
from config import config
from lib.util import delete_split_dir

# base_dir = os.path.dirname(os.path.abspath(__file__))
# JSON_FOLDER = os.path.join(base_dir,"tshark_json")
# INFO_JSON = os.path.join(base_dir,"tshark_list.json")
# PCAP_FOLDER = os.path.join(base_dir,"pcaps")

merged_output = "D:\\script\\wireshark\\pcap_results\\merged_filtered.pcapng"
input_folder = f"D:\\script\\wireshark\\main_repo\\pcaps\\test_1gb.pcapng"   # pcap 파일 모아놓은 폴더 경로
output_folder = f"D:\\script\\wireshark\\pcap_results" # 결과 파일 저장 폴더 경로


# tshark를 이용해 특정 레이어의 대화(conversation) 정보를 추출
def extract_conv(pcap_file, filter_pkt):
    program = "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_file = f"D:\\script\\wireshark\\pcap_results\\{base_name}_filtered.pcapng"

    command = [
        program,
        "-2",
        "-r", pcap_file, 
        "-Y", filter_pkt,
        "-w", output_file
    ]

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        raise Exception(f"Error: {result.stderr}")
    
    return output_file

# 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
def analyze_pcap_file(pcap_file, filter_pkt):
    print(f"Splitting {pcap_file}...")

    split_pcaps = wireshark_api(config).split_pcap(pcap_file)

    if not split_pcaps:
        print(f"분할된 파일이 없습니다: {pcap_file}")
        return False, "No Splitted File", ""
    
    args = [(pcap, filter_pkt) for pcap in split_pcaps]

    # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
    with Pool(processes=cpu_count()) as pool:
        results_list = pool.starmap(extract_conv, args)

    # 필터링된 결과 파일들을 병합
    merged_output = os.path.splitext(os.path.basename(pcap_file))[0]
    wireshark_api(config).merge_pcaps(results_list, merged_output)
    delete_split_dir(pcap_file)

    return True, "success", ""

# def start(file_name):
#     output_folder = f"{JSON_FOLDER}" # 결과 파일 저장 폴더 경로
#     os.makedirs(output_folder, exist_ok=True)

#     pcap_dir = f"{PCAP_FOLDER}\\{file_name}"

#     start = datetime.now()
#     result, msg, data = analyze_pcap_file(pcap_dir, output_folder)
#     if not result:
#         return result, msg, data
#     end = datetime.now()

#     if not os.path.exists(JSON_FOLDER):
#         os.makedirs(JSON_FOLDER)

#     base_filename = os.path.basename(file_name)
#     name_only = os.path.splitext(base_filename)[0]
#     json_name = f"{name_only}.json"

#     print(f'시작시간 : {start.strftime("%H:%M:%S")}')
#     print(f'종료시간 : {end.strftime("%H:%M:%S")}')

#     return result, msg, data

    
if __name__ == "__main__":
    # os.makedirs(output_folder, exist_ok=True)

    filter_pkt = "!tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && !tcp.analysis.spurious_retransmission && !_ws.malformed && (tcp.srcport || udp.srcport) && ip.addr==10.10.8.168 && tcp.port==1444 && ip.addr==104.25.37.17 && tcp.port==443 && _ws.col.protocol contains TLS"
    start = datetime.now()
    analyze_pcap_file(input_folder, filter_pkt)
    # extract_conv(input_folder, filter_pkt)
    end = datetime.now()

    print(f'시작시간 : {start.strftime("%H:%M:%S")}')
    print(f'종료시간 : {end.strftime("%H:%M:%S")}')