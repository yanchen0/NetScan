import pika
import json
import time
import os
from multiprocessing.dummy import Process
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter
import sys
import IPy
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportDecoder, ReportEncoder
import threading  

task_queue = "ip_list"
post_queue = "result_port_scan"
default_priority = 5
rabbituri = 'amqp://rabbit:rabbit@193.168.15.156/netscan'

curdir,pyfile=os.path.split(sys.argv[0])

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


logger=logging.getLogger('port_scan_msg')
init_logger(logger)


def main():
    workers=[]
    workers.append(Process(target=process_port_scan,args=(rabbituri, task_queue, 'amq.direct')))
    for p in workers:
        p.start()
    for p in workers:
        p.join()


def store_report(nmap_report, post_channel,scan_tag,priority):
    for nmap_host in nmap_report.hosts:
        try:
            jhost = {}
            if not nmap_host.is_up():
            #if getattr(nmap_host, 'status') == 'down':
                return jhost
            jhost['ip'] = getattr(nmap_host, 'ipv4')
            jhost['tag'] = scan_tag
            port_list = []
            for nmap_service in nmap_host.services:
                if getattr(nmap_service, 'state') == 'open':
                    port_list.append(nmap_service.port)

            if len(port_list):
                jhost['port'] = port_list
                nmap_report_json = json.dumps(jhost)
                logger.debug("scan result: %s" % (port_list))
                post_channel.basic_publish(exchange='',routing_key=post_queue,body=nmap_report_json,properties=pika.BasicProperties(priority=int(priority))) 

        except Exception as e:
            logger.error(e.message)


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

def scan(ip,argv,scan_tag,priority):
    ret = False
    conn = None
    try:
        logger.debug( "start scan ip: %s" % (ip) )
        scan_results = do_scan(ip,argv)
        if scan_results:
            conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
            channel = conn.channel()
            store_report(scan_results,channel,scan_tag,priority)
            conn.close()
            ret = True
            logger.debug("end scan ip: %s" % (ip))
        else:
            logger.info( "scan ip: %s failed,cmd: %s!" % (ip,argv))

    except Exception as e:
        if conn:
            conn.close()
        logger.error(("ip: %s,cmd: %s,err: %s") % (ip,argv,e.message))
    
    return ret

def process_port_scan(rabbituri,src,dest,rabbituri2=None):
    lasttime=datetime.now()
    while(True):
        try:
            conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
            channel = conn.channel()
            while(True):
                (getok,properties,body)=channel.basic_get(src,no_ack=True)
                priority = default_priority
                if not body:
                    logger.debug('no tasks...[{0}]'.format(src))
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
                    if obj.get('ip') and obj.get('cmd')and obj.get('tag'):
                        priority = properties.priority
                        scan_ip=obj['ip'].encode("ascii")
                        scan_argv = obj['cmd'].encode("ascii")
                        scan_tag = obj['tag'].encode("ascii")

                        ip = IPy.IP(scan_ip)
                        post_data = {}
                        for x in ip:
                            if str(x).split('.')[-1]!=str(0):
                                if str(x).split('.')[-1]!=str(255):
                                    logger.debug('task ip:%s,cmd:%s'%(str(x),scan_argv))
                                    t = threading.Thread(target=scan,args=(str(x),scan_argv,scan_tag,priority)) 
                                    t.start()
                                    while True:  
                                        if threading.activeCount()-1>60:  ## 
                                            time.sleep(1)  
                                        else:  
                                            break

                                    #if not scan(str(x),scan_argv,scan_tag,priority): 
                                    #    scan(str(x),scan_argv,scan_tag,priority)
        except Exception as e:
            logger.error(e.message)
            time.sleep(10)

if __name__=='__main__':
    main()