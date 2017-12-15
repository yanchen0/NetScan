import pika
import json
import time
import os
import threading  
from multiprocessing.dummy import Process
from datetime import datetime
import re
import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter
import sys
import IPy
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportDecoder, ReportEncoder
import pygeoip
gi = pygeoip.GeoIP("GeoLiteCity.dat")  

'''
post json format
{
	"address":"193.168.15.158",
	"ipv6":"",
	"mac":"xxxx-xxxx-xxxx-xxx",
	"hostname":"www.rising.com.cn",
	"port":80,
	"state":"open",
    "protocol":"tcp"
    "type":"http",
	"tag":"normal",
	"os":{"product":"xp","vendor":"microsoft"},
	"service":{"product":"iis","version":"","extrainfo":"","ostype":"","context":""}
}
'''

task_queue = "result_port_scan"
post_queue = "result_service_scan"
rabbituri = 'amqp://rabbit:rabbit@193.168.15.156/netscan'

default_scan_argv = "-sV -O"
mon_service_list = {"http":"http_list","http-proxy":"http_list"}


curdir,pyfile=os.path.split(sys.argv[0])

lock = threading.RLock()

def init_logger(logger):
    if not logger.name:
        logger.name='app'
    logger.setLevel(logging.DEBUG)  #must set the root level
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(Formatter('%(asctime)s\t%(levelname)s\t%(message)s'))
    logger.addHandler(stdout_handler)
    logdir=os.path.join(curdir,'logs')
    if os.path.exists(logdir) == False:
        os.makedirs(logdir)
    logfile=os.path.join(logdir,'{0}_log.txt'.format(logger.name))
    file_handler = RotatingFileHandler(logfile,maxBytes=5*1024*1024,backupCount=5)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(Formatter('%(asctime)s\t%(levelname)s\t%(message)s'))
    logger.addHandler(file_handler)

    logfile=os.path.join(logdir,'{0}_error.txt'.format(logger.name))
    file_handler = RotatingFileHandler(logfile,maxBytes=5*1024*1024,backupCount=5)
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(Formatter('''
    Time:               %(asctime)s
    Message type:       %(levelname)s
    Location:           %(pathname)s:%(lineno)d
    Module:             %(module)s
    Function:           %(funcName)s
    Message:
    %(message)s
    '''))
    logger.addHandler(file_handler)

logger=logging.getLogger('service_scan_msg')
init_logger(logger)

def main():
    workers=[]
    workers.append(Process(target=process_service_scan,args=(rabbituri, task_queue, 'amq.direct')))
    for p in workers:
        p.start()
    for p in workers:
        p.join()


def post_report(nmap_report, post_channel,scan_tag):
    host_keys = [ "address", "hostnames", "ipv6", "mac"]
    for nmap_host in nmap_report.hosts:
        try:
            jhost = {}
            if not nmap_host.is_up():
                continue 
            for hkey in host_keys:
                jhost[hkey] = getattr(nmap_host, hkey)

            jhost['tag'] = scan_tag
            jhost['os'] = get_os(nmap_host)

            for nmap_service in nmap_host.services:
                try:
                    if not nmap_service.open():
                        continue
                    post_info = jhost
                    post_info['type'] = nmap_service.service
                    basic_info = get_basic_info(nmap_service)
                    post_info.update(basic_info)

                    detail_info = get_detail_info(nmap_service)
                    post_info['service'] = detail_info
                    info = gi.record_by_addr(post_info['address'])
                    country_code = info['country_code']
                    post_info['geo']=country_code

                    nmap_report_json = json.dumps(post_info)
                    print nmap_report_json
                    post_channel.basic_publish(exchange='amq.direct',routing_key=post_queue,body=nmap_report_json)

                    #service_result={'ms-sql-s':'ms-sql-s','ftp':'ftp','ssh':'ssh','telnet':'telnet','smtp':'smtp','mysql':'mysql','pop3':'pop3','microsoft-ds':'microsoft-ds','http':'http','http-proxy':'http-proxy','domain':'domain'}
                    for i in mon_service_list: 
                        if post_info['type']==i:
                            http_data={}
                            http_data['ip']=post_info['address']
                            http_data['port']=post_info['port']
                            http_data['tag']=post_info['tag']


                            print country_code
                            #http_data['geo']=country_code

                            http_json = json.dumps(http_data)
                            print http_json

                            post_channel.basic_publish(exchange='',routing_key=mon_service_list[i],body=http_json)


                except Exception as e:
                    logger.error(e.message)
        except Exception as e:
            logger.error(e.message)

def get_os(nmap_host):
    rval = {'vendor': 'unknown', 'product': 'unknown'}
    try:
        if nmap_host.is_up() and nmap_host.os_fingerprinted:
            cpelist = nmap_host.os.os_cpelist()
            if len(cpelist):
                mcpe = cpelist.pop()
                rval.update({'vendor': mcpe.get_vendor(),
                            'product': mcpe.get_product()})
    except Exception as e:
        logger.error(e.message)
    return rval



def get_detail_info(nmap_service):
    detail_info = {}
    try:
        banner_info = nmap_service.banner
        if not len(banner_info):
            return detail_info
        
        dict_test={}
        banner_keys = ['product','version','extrainfo','devicetype','ostype']
        for banner_key in banner_keys:
            index = banner_info.find(banner_key)
            if index != -1:
                dict_test[banner_key] = index
        
        len_dict = len(dict_test)
        if len_dict == 0:
            return detail_info
        
        dict_test = sorted(dict_test.items(),key=lambda item:item[1])

        str_list = []
        index_start = 0
        index_end = 0
        if len_dict == 1:
            str_list.append(banner_info)
        else:
            for i in range(0,len_dict-1):
                tuple_test = dict_test[i]
                index_start = tuple_test[1]
                tuple_test = dict_test[i+1]
                index_end = tuple_test[1]
                str_list.append(banner_info[index_start:index_end])

            str_list.append(banner_info[index_end:])

        if len(str_list) == 0:
            return detail_info

        for item in str_list:
            item_list = str(str(item).strip()).split(':')
            detail_info[str(item_list[0]).strip()] = str(item_list[1]).strip()

        detail_info['context'] = banner_info
    
    except Exception as e:
        logger.error(e.message)

    return detail_info


def get_basic_info(nmap_service):
    service_keys = ["port", "protocol", "state"]
    jservice = {}
    for skey in service_keys:
        jservice[skey] = getattr(nmap_service, skey)
         
    return jservice

def do_scan(ip,argm):
    try:
        nmap_report = None
        nm = NmapProcess(ip, options=argm) 
        rc = nm.run()
        if nm.rc == 0:
            nmap_result=nm.stdout
            nmap_report = NmapParser.parse_fromstring(nmap_result)
        else:
            logger.error(nm.stderr)
    except Exception as e:
        logger.error(e.message)

    return nmap_report

def scan(ip,argv,scan_tag):
    ret = False
    try:
        scan_results = do_scan(ip,argv)
        if scan_results:
            conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
            channel = conn.channel()
            post_report(scan_results,channel,scan_tag)
            conn.close()
            ret = True
    except Exception as e:
       logger.error(e.message)
    
    return ret


def process_service_scan(rabbituri,src,dest,rabbituri2=None):
    lasttime=datetime.now()

    while(True):
        try:
            conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
            channel = conn.channel()

            while(True):
                (getok,properties,body)=channel.basic_get(src,no_ack=True)
                if not body:
                    logger.debug('[no tasks...{0}]'.format(src))
                    if (datetime.now()-lasttime).total_seconds()>600:
                        lasttime=datetime.now()
                        conn.close()
                        break
                    time.sleep(1)
                    continue
                lasttime=datetime.now()
                obj=None
                try:
                    obj=json.loads(body.decode())
                except:
                    logger.error('invalid msg,{0}'.format(body.decode))
                if obj:
                    if obj.get('ip') and obj.get('tag') and obj.get('port'):
                        port_list = []
                        scan_ip=obj['ip'].encode("ascii")
                        scan_tag = obj['tag'].encode("ascii")
                        port_list = obj.get('port')

                        str_port_list = []
                        for item in  port_list:
                            str_port_list.append(str(item))
                        scan_port = ','.join(str_port_list)                       
                        scan_argv = "%s -p%s" % (default_scan_argv,scan_port)
                        ip = IPy.IP(scan_ip)
                        
                        logger.debug('[task ip:%s,cmd:%s]'%(str(ip),scan_argv))

                        t = threading.Thread(target=scan,args=(str(ip),scan_argv,scan_tag)) 
                        t.start()
                        while True:  
                            if threading.activeCount()-1>30:  ## 
                                time.sleep(1)  
                            else:  
                                break 

                        #if not scan(str(ip),scan_argv,scan_tag):
                        #    scan(str(ip),scan_argv,scan_tag)

        except Exception as e:
            logger.error(e.message)
            time.sleep(10)

if __name__=='__main__':
    main()