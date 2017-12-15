# NetScan		

分布式多线程全网扫描		 

  		  
![Alt text](https://github.com/yanchen0/NetScan/blob/master/0.jpg)

  		  
![Alt text](https://github.com/yanchen0/NetScan/blob/master/1.jpg)


实现功能：		

1：task_portscan.py ：参数-f ，IP地址列表 [china_ip_list.txt] 进入队列 [ip_list] ，限额 <20000条。

2：port_scan.py ：调用Nmap库, 取队列[china_ip_list.txt] 做开放端口扫描，将结果录入队列 [result_port_scan]。

3：service_scan.py ：获取开放端口的队列  [result_port_scan] ,再进行扫描，将[address\hostnames\ipv6\mac\os] 系统关键信息保存至队列[result_service_scan]

4：http_scan.py：  为service_scan.py的扩展， 获取http服务的相关信息。