import os
import subprocess
import shutil
import glob

class wireshark_api:
    def __init__(self, config):
        self.basedir = config['basedir']
        self.parse_json = os.path.join(self.basedir, config['parse_list'])
        self.result_dir = os.path.join(self.basedir, config['parse_result_dir'])
        self.split_dir = os.path.join(self.basedir, config['split_pcaps'])
        self.ext_pcapng = os.path.join(self.basedir, config['filtered_pcapng_dir'])
        # self.merged_output = os.path.join(self.basedir, config['split'])
        
    # editcap을 이용해 pcap 파일을 chunk_size 개의 패킷 단위로 분할
    def split_pcap(self, pcap_file, chunk_size=500000):
        program = "C:\\Program Files\\Wireshark\\editcap.exe"
        os.makedirs(self.split_dir, exist_ok=True)

        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        split_dir_n = os.path.join(self.split_dir, base_name)
        os.makedirs(split_dir_n, exist_ok=True)
        output_pattern = os.path.join(split_dir_n, base_name)
        split_file_pcap = output_pattern + ".pcapng"

        command = [program, "-c", str(chunk_size), pcap_file, split_file_pcap]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            shutil.rmtree(split_dir_n)
            print(f"editcap Error: {result.stderr}")
            return []

        split_files = glob.glob(os.path.join(split_dir_n, f"{base_name}_*"))
        return split_files

    def merge_pcaps(self, pcap_list, output_file):
        program = "C:\\Program Files\\Wireshark\\mergecap.exe"
        os.makedirs(self.ext_pcapng, exist_ok=True)
        output_file = os.path.join(self.ext_pcapng, f"{output_file}_filtered.pcapng")

        command = [program, "-w", output_file] + pcap_list

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise Exception(f"mergecap error: {result.stderr}")
        print(f"Merged into: {output_file}")

    def extract_conv(self, pcap_file, filter_pkt):
        command = [
            "tshark",
            "-r", pcap_file,
            "-2",
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

        print(f"[INFO] Extracted fields from: {pcap_file}")
        return result.stdout


    def extract_pcap(self, pcap_file, filter_pkt):
        """필터 조건에 맞는 패킷만 새로운 pcapng 파일로 저장"""
        os.makedirs(self.ext_pcapng, exist_ok=True)
        program = "C:\\Program Files\\Wireshark\\tshark.exe" # tshark 기본 경로
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        output_file = os.path.join(self.ext_pcapng, f"{base_name}_ext.pcapng")

        command = [
            program,
            "-2",
            "-r", pcap_file,
            "-Y", filter_pkt,
            "-w", output_file
        ]

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"[ERROR] Failed to extract filtered pcap:\n{result.stderr}")

        print(f"[INFO] Saved filtered pcap to: {output_file}")
        return output_file