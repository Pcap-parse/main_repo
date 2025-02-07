import json

def load_json(file_path):
    """JSON 파일을 로드합니다."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def filter_data(data, field, value):
    """주어진 field와 value로 데이터를 필터링합니다."""
    filtered_data = []
    for entry in data:
        # field가 존재하고, 해당 값이 일치하는 경우에만 필터링
        if field in entry and entry[field] == value:
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
    field = input("필터링할 필드를 입력하세요 (예: 'Ethernet'): ")
    value = input(f"{field} 필드에 해당하는 값을 입력하세요: ")
    
    # 입력 받은 값을 적절히 변환
    # 예시: 문자열 값이면 그대로, 숫자 값이면 int로 변환
    if value.isdigit():
        value = int(value)
    
    # 3. 필터링된 데이터 얻기
    filtered_data = filter_data(data, field, value)
    
    # 4. 필터링된 데이터 출력
    display_filtered_data(filtered_data)
    
    # 5. 필터링된 데이터를 저장할지 여부 묻기
    save_option = input("필터링된 데이터를 파일에 저장할까요? (y/n): ")
    if save_option.lower() == 'y':
        output_file = input("저장할 파일 경로를 입력하세요: ")
        save_filtered_data(filtered_data, output_file)

if __name__ == "__main__":
    main()
