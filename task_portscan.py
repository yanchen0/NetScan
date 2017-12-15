import sys
import json
import pika
import IPy
import getopt
import json
import base64   
import urllib   
import httplib
import time

task_queue = "ip_list"
rabbituri = 'amqp://rabbit:rabbit@193.168.15.156/netscan'
##########################
priority = 5
max_ip_list_len = 20000

#http://193.168.15.156:15672/api/queues/netscan/ftp
def get_queue_length(queue_name):
    ret = False
    length = 0
    #try:
    auth = base64.b64encode('rabbit' + ':'+ 'rabbit')    
    headers = {"Authorization": "Basic "+ auth, "Content-Type": "application/json"}     
    conn = httplib.HTTPConnection("193.168.15.156:15672")    
    conn.request("GET","/api/queues/netscan/%s" % (queue_name), '', headers)  
    response = conn.getresponse()
    info = json.loads(response.read())
    length = info[u'messages_ready']
    ret = True
    #except Exception as e:
    #print e.message

    return ret,length


def publish_msg(channel,ip_json,priority):
    #try:
    channel.basic_publish(exchange='',routing_key=task_queue,body=ip_json,properties=pika.BasicProperties(priority=int(priority))) 
    #except Exception as e:
    #    print e.message


def post_ip(scan_ip,scan_argv,scan_tag,file_out,priority):

    conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
    channel = conn.channel()

    if file_out:
        file_out.write(str(scan_ip))
        file_out.write('\n')
        file_out.flush()

    post_data = {}
    ip = IPy.IP(scan_ip)
    post_len = ip.len()
    print 'scan: ',ip,'len: ',post_len,'rabbit: '
    while True:
        ret,queue_len = get_queue_length(task_queue)
        if ret:
            print max_ip_list_len,'-',queue_len,'>',post_len,'or',queue_len
            if max_ip_list_len - queue_len > post_len or queue_len == 0:
                break
            else:
                print("queue is full,sleep 5 minutes!")
        else:
            print("get queue length failed,sleep 5 minutes!")

        time.sleep( 5 * 60)
        
    conn.close()

    conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
    channel = conn.channel()
    iTotal = 0
    for x in ip:
        print x
        #try:
        post_data['ip'] = str(x)
        post_data['cmd'] = scan_argv
        post_data['tag'] = scan_tag
        ip_json = json.dumps(post_data)
        publish_msg(channel,ip_json,priority)
        iTotal = iTotal + 1
        print iTotal,queue_len, '>', max_ip_list_len
        if iTotal + queue_len > max_ip_list_len:
            print("queue is full,sleep 5 minutes!")
            time.sleep(5*60)
            iTotal = 0
            ret,queue_len = get_queue_length(task_queue)
                
        #except Exception as e:
        #    print e.message
    
    conn.close()

def save_ip_file(path):
    file = open(path, 'w')  
    for ip in ip_list:  
        file.write(ip)  
        file.write('\n')  
    file.close()  


def post_ip_from_file(path,scan_argv,scan_tag,file_out,priority):
    file = open(path,'r')
    for line in file:
        try:
            ips=line.replace("\n","")
            post_ip(ips,scan_argv,scan_tag,file_out,priority)
        except Exception as e:
            print e.message
    file.close()

def create_task():
    print('init rabbitmq connection...[{0}]'.format(rabbituri))
    conn = pika.BlockingConnection(pika.URLParameters(rabbituri))
    channel = conn.channel()

def usage():  
    print "Usage:%s [-i|-f] [-c] [-o] args...." %(sys.argv[0])
    print "-i 193.168.1.1 or 193.168.1.0/24"
    print "-f iplistfile"
    print "-c scan arg"
    print "-t tag of the task"
    print "-p priority of the task"
    print "-o output file all ip add to the task"

def main():
    try:
        #print('init rabbitmq connection...[{0}]'.format(rabbituri))

        priority = 5    # default priority 1
        ext_ip = False
        scan_argv = ""
        scan_tag=""
        iplist=""
        from_file = False
        file_out = None
        opts,args = getopt.getopt(sys.argv[1:], "ei:f:c:t:p:o:h", ["exp","ip","file","cmd","tag","pri","out","help"]) 
        for opt,arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit(1)
            elif opt in ("-i", "--ip"):
                iplist= arg
            elif opt in ("-f","--file"):
                from_file=True
                file_ip = arg
            elif opt in ("-c","--cmd"):
                scan_argv = arg
            elif opt in ("-t","--tag"):
                scan_tag = arg
            elif opt in ("-o","--out"):
                file_out = open(arg, 'w')
            elif opt in ("-p","--pri"):
                priority = arg
            else:  
                print("%s  ==> %s" %(opt, arg))
        if scan_argv.strip()=='':
            scan_argv = "-n --open"
        if scan_tag.strip()=='':
            scan_tag = "normal"
        global is_out
        if from_file:
            post_ip_from_file(file_ip,scan_argv,scan_tag,file_out,priority)
        else:
            post_ip(iplist,scan_argv,scan_tag,file_out,priority)
        
        if file_out:
            file_out.close()

    except getopt.GetoptError:
        print("getopt error!")
        usage()
        sys.exit(1)

if __name__ == '__main__':
    #get_queue_length('ftp')
    main()