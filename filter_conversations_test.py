import json
import re
import operator as op

# 필드 매핑: 입력된 'addr_A'와 같은 값을 실제 필드명인 'Address A'로 변환
field_mapping = {
    "addr_a": "Address A",
    "addr_b": "Address B",
    "bits_s_atob": "Bits/s A to B",
    "bits_s_btoa": "Bits/s B to A",
    "bytes": "Bytes",
    "bytes_atob": "Bytes A to B",
    "bytes_btoa": "Bytes B to A",
    "duration": "Duration",
    "packets": "Packets",
    "packets_atob": "Packets A to B",
    "packets_btoa": "Packets B to A",
    "rel_start": "Rel Start",
    "stream_id": "Stream ID",
}

def load_json(file_path):
    """JSON 파일을 로드합니다."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def parse_condition(condition):
    """사용자가 입력한 필터링 조건을 파싱하고 변환합니다."""
    # 조건을 파싱하고 연산자와 값 사이의 불필요한 공백을 제거합니다.
    match = re.match(r"(\w+)\s*(==|!=|>=|<=|>|<)\s*(.*)", condition.strip())
    if match:
        field = match.group(1).strip()  # 예: 'addr_A'
        operator = match.group(2).strip()  # 예: '=='
        value = match.group(3).strip(' "').strip()  # 값에서 불필요한 공백과 따옴표 제거

        # 매핑된 필드 이름으로 변환 (언더스코어 형식으로 변경 후 매핑)
        mapped_field = field.lower().replace(' ', '_').replace('-', '_')
        if mapped_field in field_mapping:
            field = field_mapping[mapped_field]
        
        print(f"Parsed condition: Field = {field}, Operator = {operator}, Value = {value}")  # 디버깅 로그
        return field, operator, value
    else:
        print(f"조건 파싱 실패: 잘못된 형식입니다. 입력 값: '{condition}'")  # 디버깅 로그
    return None, None, None

def convert_value(value):
    """주어진 value가 문자열일 때와 숫자일 때를 구분하여 적절히 변환."""
    if isinstance(value, str):
        if value.isdigit():  # 숫자 문자열일 경우
            return int(value)
        try:
            return float(value)  # 실수로 변환 시도
        except ValueError:
            return value  # 숫자가 아니면 그대로 반환
    return value

def apply_operator(entry_value, operator, condition_value):
    """주어진 연산자에 따라 값을 비교합니다."""
    # 데이터 타입을 맞추기 위해 값 변환
    entry_value = convert_value(entry_value)
    condition_value = convert_value(condition_value)

    ops = {
        "==": op.eq,
        "!=": op.ne,
        ">": op.gt,
        "<": op.lt,
        ">=": op.ge,
        "<=": op.le
    }
    
    return ops.get(operator, lambda x, y: False)(entry_value, condition_value)

def filter_data(data, condition):
    """주어진 조건으로 데이터를 필터링합니다."""
    filtered_data = []
    # 조건을 파싱하여 필드와 값을 추출
    field, operator, value = parse_condition(condition)

    # 조건이 유효하면 필터링 수행
    if field and operator and value:
        # 문자열 값이라면 그 값을 그대로 사용
        condition_value = value

        for prefix_key, prefix_data in data.items():
            # 전체 딕셔너리 항목을 순회
            print(f"필터링 중: {prefix_key} 데이터 탐색")
            for entry in prefix_data:
                if isinstance(entry, dict):
                    if field in entry:
                        # 필드 값의 데이터 타입을 확인 후 비교
                        entry_value = entry[field]

                        if entry_value == "":
                            continue
                        
                        # 비교 연산자 적용
                        if apply_operator(entry_value, operator, condition_value):
                            filtered_data.append(entry)
    return filtered_data

def display_filtered_data(filtered_data):
    """필터링된 데이터를 출력합니다."""
    if filtered_data:
        for item in filtered_data:
            print(json.dumps(item, indent=4))
    else:
        print("조건에 맞는 데이터가 없습니다.")

def save_filtered_data(filtered_data, output_file):
    """필터링된 데이터를 파일에 저장합니다."""
    with open(output_file, 'w') as file:
        json.dump(filtered_data, file, indent=4)
    print(f"필터링된 데이터가 '{output_file}'에 저장되었습니다.")

def main():
    # 1. pcap 파일의 JSON 데이터 불러오기
    file_path = input("JSON 파일 경로를 입력하세요: ")
    data = load_json(file_path)
    
    # 2. 사용자로부터 필터링 조건 받기
    condition = input("필터링할 조건을 입력하세요 (예: addr_A == c4:75:ab:0f:1b:08 또는 packets == 3): ")
    
    # 3. 필터링된 데이터 얻기
    filtered_data = filter_data(data, condition)
    
    # 4. 필터링된 데이터 출력
    display_filtered_data(filtered_data)
    
    # 5. 필터링된 데이터를 저장할지 여부 묻기
    save_option = input("필터링된 데이터를 파일에 저장할까요? (y/n): ")
    if save_option.lower() == 'y':
        output_file = input("저장할 파일 경로를 입력하세요: ")
        save_filtered_data(filtered_data, output_file)

if __name__ == "__main__":
    main()