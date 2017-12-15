from IPy import IP
import httplib
import urllib2
import json,re,pika
import socket   
import sys  
import IPy
import threading  
import time,os
from datetime import datetime
from multiprocessing.dummy import Process
curdir,pyfile=os.path.split(sys.argv[0])

import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter

#Port = [80,8080,443]
result = []  



def main():
    workers=[]
    workers.append(Process(target=process_counters_msg,args=('amqp://rabbit:rabbit@193.168.15.156/netscan', 'http_list', 'amq.direct')))
    for p in workers:
        p.start()
    for p in workers:
        p.join()




def scan(Domain,port,tag):  
    #for port in Port:
    try:
        #print Domain,port
        conn = httplib.HTTPConnection(Domain,port,timeout=10)
        conn.request("GET", "/")
        r1 = conn.getresponse()
        content=r1.read()  
        ver=''
        
        if r1.version == 9:
            ver = "HTTP/0.9"
        elif r1.version == 10:
            ver = 'HTTP/1.0'
        elif r1.version == 11:
            ver = 'HTTP/1.1'

        title=''
        
        if content!='':
            #print content
            p = re.compile(r'<title>(.*)</title>')
            if title!=[]:
                title=p.findall(r1.read())
            title=p.findall(content)
            #print title[0]

        r={}
        r['ip']=Domain
        r['title']=title[0]
        r['port']=str(port)
        r['status']=ver+' '+str(r1.status)+' '+r1.reason
        r['server']=r1.msg['Server']
        r['content']=content  
        r['tag']=tag
        try:
            content = urllib2.urlopen('https://%s/robots.txt'%Domain,timeout=2).read()
            r['robots']=content
        except Exception as e:
            r['robots']=''

        #print r
        r2={}
        r2['ip']=Domain
        r2['port']=str(port)
        print json.dumps(r2)


        #print Domain,':',port,ver,r1.status,r1.reason,  r1.msg['Server']
        #with open('ip.txt','a')as fp:
        #    fp.write(json.dumps(r)+'\n')   

        post_rabbituri = 'amqp://rabbit:rabbit@193.168.15.156/netscan'
        conn = pika.BlockingConnection(pika.URLParameters(post_rabbituri))
        channel = conn.channel()
        channel.basic_publish(exchange='amq.direct',routing_key='result_http_scan',body=json.dumps(r))
        conn.close()
    except Exception as e:
        pass




def init_logger(logger):
    if not logger.name:
        logger.name='app'
    logger.setLevel(logging.INFO)  #must set the root level
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
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


def process_counters_msg(rabbituri,src,dest,rabbituri2=None):
    lasttime=datetime.now()
    logger=logging.getLogger('process_counters_msg')
    init_logger(logger)
    while(True):
        try:
            print('init rabbitmq connection...[{0}]'.format(rabbituri))
            conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
            channel = conn.channel()
            #print('init redis connection...[{0}]'.format('193.168.15.156:6379'))
            #r=redis.Redis(host='193.168.15.157',port=6379)

            while(True):
                (getok,properties,body)=channel.basic_get(src,no_ack=True)
                if not body:
                    print('no tasks...[{0}]'.format(src))
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

                    if obj.get('ip') and obj.get('tag')and obj.get('port'):
                    #if obj.get('address') :

                        #scan_ip=obj['address'].encode("ascii")
                        scan_ip=obj['ip']
                        scan_tag = obj['tag']
                        scan_port = obj['port']
                        

             
                        #print('[task ip:%s]'%scan_ip)


                        scan(scan_ip,scan_port,scan_tag)
                        '''t = threading.Thread(target=scan,args=(scan_ip,scan_port,scan_tag)) 
                        t.start()
                        while True:  
                            if threading.activeCount()-1>100:  ## 
                                time.sleep(1)  
                            else:  
                                break  
                        '''

                                    #scan(str(x),scan_argv,scan_tag)
                # channel.basic_ack(getok.delivery_tag)
        except Exception as e:
            print(e)
            time.sleep(10)





if __name__=='__main__':
    main()