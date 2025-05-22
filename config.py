import os

config = {
    'basedir': os.path.dirname(os.path.abspath(__file__)) ,
    'parse_list': 'tshark_list.json',
    'parse_result_dir': 'tshark_json',
    'split_pcaps': 'split',
    'pcapng_data_dir': 'pcaps',
    'filtered_pcapng_dir': 'pcapng_extract',
    'filter_list': 'filter_list.json',
}