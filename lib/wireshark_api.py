import os
import subprocess
import glob
from lib.util import delete_split_dir, change_list, create_uuid

class wireshark_api:
    def __init__(self,config):
        self.basedir = config['basedir']
        self.parse_json = os.path.join(self.basedir, config['parse_list'])
        self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])
        self.pcap_file = os.path.join(self.basedir, config['pcapng_data_dir'])
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.ext_pcapng = os.path.join(self.basedir, config['filtered_pcapng_dir'])
        

    # editcap을 이용해 pcap 파일을 chunk_size 개의 패킷 단위로 분할
    def split_pcap(self, pcap_file, chunk_size=200000):
        program = "editcap"
        os.makedirs(self.split_dir, exist_ok=True)
        os.makedirs(self.pcap_file, exist_ok=True)

        if os.path.isabs(pcap_file):
            # 절대 경로
            pcap_file_path = pcap_file
        elif os.path.exists(pcap_file):
            # 상대 경로
            pcap_file_path = os.path.abspath(pcap_file)
        else:
            pcap_file_path = os.path.join(self.pcap_file, os.path.basename(pcap_file))

        if not os.path.exists(pcap_file_path):
            # print(f"[ERROR] File does not exist: {pcap_file_path}")
            return []

        file_name_only = os.path.basename(pcap_file_path)
        base_name = os.path.splitext(file_name_only)[0]

        split_dir_n = os.path.join(self.split_dir, base_name)
        os.makedirs(split_dir_n, exist_ok=True)

        output_pattern = os.path.join(split_dir_n, base_name)
        split_file_pcap = output_pattern + "-%05d.pcapng"

        command = [program, "-c", str(chunk_size), pcap_file_path, split_file_pcap]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            delete_split_dir(split_dir_n)
            # print(f"editcap Error: {result.stderr}")
            return []

        split_files = glob.glob(os.path.join(split_dir_n, "*.pcapng"))
        return split_files


    def merge_pcaps(self, pcap_list, output_file, idx):
        program = "mergecap" # "C:\\Program Files\\Wireshark\\mergecap.exe"
        os.makedirs(self.ext_pcapng, exist_ok=True)
        new_uuid = create_uuid()
        output_file = os.path.join(self.ext_pcapng, f"{new_uuid}.pcapng")
        pcap_list = change_list(pcap_list)

        command = [program, "-w", output_file] + pcap_list

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise Exception(f"mergecap error: {result.stderr}")
        # print(f"Merged into: {output_file}")

        return output_file


    def extract_conv(self, pcap_file, filter_pkt):
        program = "tshark" # "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로
        command = [
            program,
            "-r", pcap_file,
            "-Y", filter_pkt,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "tcp.payload",
            "-e", "udp.payload",
            "-e", "_ws.col.Protocol",
            "-o", "nameres.mac_name:FALSE"
        ]

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"[ERROR] Failed to extract fields:\n{result.stderr}")

        return result.stdout


    def extract_pcap(self, pcap_file, filter_pkt):
        """필터 조건에 맞는 패킷만 새로운 pcapng 파일로 저장"""
        os.makedirs(self.ext_pcapng, exist_ok=True)
        program = "tshark" # "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로

        command = [
            program,
            "-r", pcap_file,
            "-Y", filter_pkt,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.payload",
            "-e", "udp.payload",
        ]

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"[ERROR] Failed to extract filtered pcap:\n{result.stderr}")

        return result.stdout
    

    def run_editcap(self, args):
        idx, chunk, pcap_file, output_pcapng = args
        temp_output = output_pcapng if idx == 0 else f"part{idx}_{output_pcapng}"
        command = [
            "editcap" # "C:\\Program Files\\Wireshark\\editcap.exe",
            "-r", pcap_file,
            temp_output
        ] + chunk
        subprocess.run(command, stderr=subprocess.PIPE, text=True)
        return temp_output
    

    def extract_matched_frames(self, input_pcap, matched_frames):
        if not matched_frames:
            # print("No matched frames to extract.")
            return []

        program = "editcap" #"C:\\Program Files\\Wireshark\\editcap.exe"  # editcap 경로
        base_name = os.path.splitext(os.path.basename(input_pcap))[0]
        output_dir = os.path.join(self.ext_pcapng, "split")
        os.makedirs(output_dir, exist_ok=True)

        chunk_size = 512
        total_chunks = (len(matched_frames) + chunk_size - 1) // chunk_size
        output_files = []

        for i in range(total_chunks):
            chunk_frames = matched_frames[i*chunk_size:(i+1)*chunk_size]
            output_pcap = os.path.join(output_dir, f"{base_name}{i+1}.pcapng")
            output_files.append(output_pcap)

            command = [
                program,
                "-r", input_pcap,
                output_pcap
            ] + chunk_frames

            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                # print(f"[ERROR] Failed to extract frames chunk {i+1}:\n{result.stderr}")
                return []

            # print(f"Extracted chunk {i+1}/{total_chunks} with {len(chunk_frames)} frames to {output_pcap}")

        return output_files