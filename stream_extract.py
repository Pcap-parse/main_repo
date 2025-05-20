import os
import json
import subprocess
from datetime import datetime
import re
from multiprocessing import Pool, cpu_count
import filter_conversations_test
import extract_pcapng

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # 현재 스크립트 기준 디렉터리
JSON_FOLDER = os.path.join(BASE_DIR, "tshark_json")
FILTER_INFO_JSON = os.path.join(BASE_DIR, "filter_list.json")
PCAP_FOLDER = os.path.join(BASE_DIR,"pcaps")

def extract_frame_numbers_by_stream(pcap_file, stream_ids, proto="tcp"):
    """
    특정 프로토콜(tcp 또는 udp)의 stream 번호 목록으로부터 frame.number 추출
    """
    frame_numbers = {}

    for stream_id in stream_ids:
        display_filter = f"{proto}.stream == {stream_id}"
        command = [
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "-r", pcap_file,
            "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.number"
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        frames = result.stdout.strip().splitlines()

        if frames:
            frame_numbers[stream_id] = frames

    return frame_numbers

def tshark_extract_streams(pcap_file, display_filter, output_txt):
    # tshark로는 프레임 번호만 추출, 시간 소요 문제
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "udp.stream"
    ]
    #with open(output_txt, "w") as f:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(command)
    return result.stdout


def streams_list(streams):
    tcp_frames = []
    udp_frames = []
    for line in streams.splitlines():
        if line[0] == '\t':
            udp_frames.append(line)
        else:
            tcp_frames.append(line)
        
    #tcp_frames = dedup_list(tcp_frames)
    #udp_frames = dedup_list(udp_frames)
    print("tcp_frames: ", len(tcp_frames))
    print("udp_frames: ", len(udp_frames))

    return tcp_frames, udp_frames

def frames_save(frames, output_txt):
    with open(output_txt, "w") as f:
        for frame in frames:
            f.write(frame + "\n")

def flatten_frames_dict(frames_dict):
    all_frames = []
    for frame_list in frames_dict.values():
        all_frames.extend(frame_list)
    return all_frames

def extract_single_stream_frames(args):
    pcap_file, stream_id, proto = args
    display_filter = f"{proto}.stream == {stream_id}"
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number"
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    frames = result.stdout.strip().splitlines()
    return (stream_id, frames) if frames else None

def extract_frame_numbers_by_stream_parallel(pcap_file, stream_ids, proto="tcp"):
    args_list = [(pcap_file, stream_id, proto) for stream_id in stream_ids]
    frame_numbers = {}

    with Pool(cpu_count()) as pool:
        results = pool.map(extract_single_stream_frames, args_list)

    for result in results:
        if result:
            stream_id, frames = result
            frame_numbers[stream_id] = frames

    return frame_numbers

def chunk_list(data, size):
    """리스트를 일정 크기로 쪼갬"""
    for i in range(0, len(data), size):
        yield data[i:i + size]

def extract_frames_by_stream_batch(pcap_file, stream_ids, proto="tcp", batch_size=20):
    frame_numbers = []
    
    for batch in chunk_list(stream_ids, batch_size):
        # tcp.stream == 1 || tcp.stream == 2 ...
        stream_filter = ' || '.join([f"{proto}.stream == {sid}" for sid in batch])
        
        command = [
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "-r", pcap_file,
            "-Y", stream_filter,
            "-T", "fields",
            "-e", "frame.number"
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        frames = result.stdout.strip().splitlines()
        frame_numbers.extend(frames)

    return frame_numbers

def extract_frame_batch(args):
    idx, pcap_file, stream_batch, proto = args
    stream_filter = ' || '.join([f"{proto}.stream == {sid}" for sid in stream_batch])
    """
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", stream_filter,
        "-o", "tcp.desegment_tcp_streams:true",
        "-T", "fields",
        "-e", "frame.number"
    ]"""
    file = f"filterd_test{idx}.pcapng"
    command = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "-r", pcap_file,
        "-Y", stream_filter,
        "-w", file
    ]
    subprocess.run(command, capture_output=True, text=True)
    
    #return result.stdout.strip().splitlines()
    return file

def extract_frames_by_stream_batches_parallel(pcap_file, stream_ids, proto="tcp", batch_size=20):
    def chunk_list(data, size):
        for i in range(0, len(data), size):
            yield data[i:i + size]

    args_list = [(idx, pcap_file, batch, proto) for idx, batch in enumerate(chunk_list(stream_ids, batch_size))]

    all_frames = []
    with Pool(cpu_count()) as pool:
        part_files = pool.map(extract_frame_batch, args_list)
    output_pcapng = "finished.pcapng"
    if len(part_files) > 1:
        merged_output = output_pcapng.replace(".pcapng", "_merged.pcapng")
        merge_command = ["C:\\Program Files\\Wireshark\\mergecap.exe", "-w", merged_output] + part_files
        subprocess.run(merge_command, stderr=subprocess.PIPE, text=True)

        for i, part_file in enumerate(part_files):
            if i != 0 and os.path.exists(part_file):
                try:
                    os.remove(part_file)
                except Exception as e:
                    print(f"[WARNING] Failed to delete {part_file}: {e}")

        print(f"[SUCCESS] Merged output: {merged_output}")
    else:
        print(f"[SUCCESS] Output: {output_pcapng}")

    """
    for frames in results:
        all_frames.extend(frames)
    return all_frames"""

def dedup_list(items):
    return list(dict.fromkeys(items))

    
if __name__ == "__main__":
    pcap_path = r"D:\script\wireshark\pcaps\test_5gb_2_00001_20141118235633.pcapng"
    start = datetime.now()
    # 1. stream 추출
    streams = tshark_extract_streams(pcap_path, "dns", "extract_frames.txt")
    tcp_streams, udp_streams = streams_list(streams)

    print(f"tcp_streams : {len(tcp_streams)}")
    print(f"udp_streams : {len(udp_streams)}")
    # 2. 병렬로 frame.number 추출
    tcp_frames = extract_frames_by_stream_batches_parallel(pcap_path, tcp_streams, proto="tcp", batch_size=100)
    udp_frames = extract_frames_by_stream_batches_parallel(pcap_path, udp_streams, proto="udp", batch_size=100)

    # 3. 저장
    #frames_save(tcp_frames, "tcp_frames.txt")
    #frames_save(udp_frames, "udp_frames.txt")

    #extract_pcapng.parallel_editcap_extract(pcap_path, "sample_filterd.pcapng", "tcp_frames.txt")
    end = datetime.now()
    print(f"시작시간 : {start.strftime('%H:%M:%S')}")
    print(f"종료시간 : {end.strftime('%H:%M:%S')}")