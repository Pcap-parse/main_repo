import os
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from lib.wireshark_api import wireshark_api
from config import config
from lib.util import delete_split_dir, get_time

input_folder = f"D:\\script\\wireshark\\main_repo\\pcaps\\test_1gb.pcapng"   # pcap 파일 모아놓은 폴더 경로

# 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
def analyze_pcap_file(pcap_file, filter_pkt):
    print(f"Splitting {pcap_file}...")

    split_pcaps = wireshark_api(config).split_pcap(pcap_file)

    if not split_pcaps:
        print(f"분할된 파일이 없습니다: {pcap_file}")
        delete_split_dir(pcap_file)
        return False, "No Splitted File", ""
    
    base_name= os.path.splitext(os.path.basename(pcap_file))[0]
    args = [(pcap, filter_pkt, base_name) for pcap in split_pcaps]
    results_list = []

    try:
        # 멀티프로세싱을 사용하여 분할된 pcap 파일 처리
        with Pool(processes=cpu_count()) as pool:
            results_list = pool.starmap(wireshark_api(config).extract_pcap, args)

        # 필터링된 결과 파일들을 병합
        merged_output = os.path.splitext(os.path.basename(pcap_file))[0]
        wireshark_api(config).merge_pcaps(results_list, merged_output)
        return True, "success", ""

    except Exception as e:
        print(f"[ERROR] 분석 중 오류 발생: {e}")
        return False, str(e), ""

    finally:
        base_name= os.path.splitext(os.path.basename(pcap_file))[0]
        delete_split_dir(os.path.join(config['filtered_pcapng_dir'], base_name))
        delete_split_dir(os.path.join(config['split_pcaps'], base_name))

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

    filter_pkt = "!tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && !tcp.analysis.spurious_retransmission && !_ws.malformed && (tcp.srcport || udp.srcport)"
    start = get_time()
    analyze_pcap_file(input_folder, filter_pkt)
    # extract_conv(input_folder, filter_pkt)
    end = get_time()

    print(f'시작시간 : {start.strftime("%H:%M:%S")}')
    print(f'종료시간 : {end.strftime("%H:%M:%S")}')