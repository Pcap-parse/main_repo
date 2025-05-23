import os
import json
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from lib.wireshark_api import wireshark_api
from lib.util import delete_split_dir, get_time

input_folder = f"D:\\script\\wireshark\\main_repo\\pcaps\\test_1gb.pcapng"   # pcap 파일 모아놓은 폴더 경로

class extract_pcapng:
    def __init__(self, config):
        self.config = config
        self.basedir = config['basedir']
        # self.parse_json = os.path.join(self.basedir, config['parse_list'])
        # self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])
        # self.pcap_file = os.path.join(self.basedir, config['pcapng_data_dir'])
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.ext_pcapng = os.path.join(self.basedir, config['filtered_pcapng_dir'])


    # 하나의 PCAP 파일을 분할 후 병렬 분석 및 결과 합치기
    def analyze_pcap_file(self, pcap_file, filter_pkt):
        print(f"Splitting {pcap_file}...")

        split_pcaps = wireshark_api(self.config).split_pcap(pcap_file)

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
                results_list = pool.starmap(wireshark_api(self.config).extract_pcap, args)

            # 필터링된 결과 파일들을 병합
            merged_output = os.path.splitext(os.path.basename(pcap_file))[0]
            wireshark_api(self.config).merge_pcaps(results_list, merged_output)
            return True, "success", ""

        except Exception as e:
            print(f"[ERROR] 분석 중 오류 발생: {e}")
            return False, str(e), ""

        finally:
            base_name= os.path.splitext(os.path.basename(pcap_file))[0]
            delete_split_dir(os.path.join(self.ext_pcapng, base_name))
            delete_split_dir(os.path.join(self.split_dir, base_name))


    def start(self, file_name, id):
        json_name = f"{file_name}.json"
        # if os.path.exists(self.filter_list_dir):
        #     with open(self.filter_list_dir , 'r', encoding='utf-8') as f:
        #         data = json.load(f)
        #         if not isinstance(data, list):
        #             data = []
        # else:
        #     data = []
        filter_pkt = (
            "!tcp.analysis.retransmission && "
            "!tcp.analysis.fast_retransmission && "
            "!tcp.analysis.spurious_retransmission && "
            "!_ws.malformed && "
            "(tcp.srcport || udp.srcport)"
        )

        start = get_time()
        result, msg, data = self.analyze_pcap_file(input_folder, filter_pkt)
        end = get_time()

        print(f'시작시간 : {start.strftime("%H:%M:%S")}')
        print(f'종료시간 : {end.strftime("%H:%M:%S")}')

        return result, msg, data

    
# if __name__ == "__main__":

#     filter_pkt = "!tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && !tcp.analysis.spurious_retransmission && !_ws.malformed && (tcp.srcport || udp.srcport)"
#     start = get_time()
#     analyze_pcap_file(input_folder, filter_pkt)
#     # extract_conv(input_folder, filter_pkt)
#     end = get_time()

#     print(f'시작시간 : {start.strftime("%H:%M:%S")}')
#     print(f'종료시간 : {end.strftime("%H:%M:%S")}')