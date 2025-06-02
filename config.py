import os
import operator as op

config = {
    'basedir': os.path.dirname(os.path.abspath(__file__)) ,
    'parse_list': 'tshark_list.json',
    'parse_result_dir': 'tshark_json',
    'split_pcaps': 'split',
    'pcapng_data_dir': 'pcaps',
    'filtered_pcapng_dir': 'extracts',
    'filter_list': 'filter_list.json',
    'filtered_list': 'extract_list.json'
}

operator_precedence = {
    "!": 3,
    "&&": 2,
    "||": 1
}

operator_symbols = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "lt": "<",
    "ge": ">=",
    "le": "<="
}

ops = {
    "==": op.eq,
    "!=": op.ne,
    ">": op.gt,
    "<": op.lt,
    ">=": op.ge,
    "<=": op.le
}

filter_pkt_default = (
    "!tcp.analysis.retransmission && "
    "!tcp.analysis.fast_retransmission && "
    "!tcp.analysis.spurious_retransmission && "
    "!_ws.malformed && "
    "(tcp.srcport || udp.srcport)"
)