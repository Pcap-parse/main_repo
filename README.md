# main_repo  

## 1주차  
pcap 파싱(pyshark 활용)  
json 형식으로 파싱  
결과 : test4.py, pyshark_test.py  

## 2주차  
필터 제작  
블랙리스트, 화이트리스트 -> 원하는 값을 필터링 시킬수 있게  
결과 : filter_conversations_test.py, JH_filter_conv.py  

## 3주차  
1. pcap 파싱 수정  
pyshark -> tshark를 백그라운드에서 실행하는 방식  
너무 오래 걸려서 tshark 직접 사용하는게 빠름  
  
2. 필터 만들기  
결과는 일단 통계로, 나중에 패킷별 결과도 추가  
