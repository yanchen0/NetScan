# NetScan

�ֲ�ʽ���߳�ȫ��ɨ��

ʵ�ֹ��ܣ�
1��task_portscan.py ������-f ��IP��ַ�б� [china_ip_list.txt] ������� [ip_list] ���޶� <20000����

2��port_scan.py ������Nmap��, ȡ����[china_ip_list.txt] �������˿�ɨ�裬�����¼����� [result_port_scan]

3��service_scan.py ����ȡ���Ŷ˿ڵĶ���  [result_port_scan] ,�ٽ���ɨ�裬��[address\hostnames\ipv6\mac\os] ϵͳ�ؼ���Ϣ����������[result_service_scan]

4��http_scan.py��  Ϊservice_scan.py����չ�� ��ȡhttp����������Ϣ��