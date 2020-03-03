# -*- coding: utf-8 -*-
#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess
#  import pysnooper
import threading
import os
import nmap
import argparse
import json
from IPy import IP

iolock = threading.Lock()
class Task:
    def __init__(self,ip,ports_list):
         self.ip=ip
         ports_list.sort()
         self.ports=','.join([str(x) for x in ports_list])

class Mas_Scanner(threading.Thread):  
    def __init__(self,task_list):
        threading.Thread.__init__(self)
        self.task_list=task_list
        self.result={}
    
    #  @pysnooper.snoop()
    def analyze(self,data,ip):#analyze and add task scan result to scanner result
        ports_list=[]
        for line in data.split('\n'):
            if line!='':
                port = line.split()[3] # xx/tcp
                port = port.split('/')[0] 
                ports_list.append(port)

        if ip in self.result:
            self.result[ip]=self.result[ip]+ports_list
        else:
            self.result[ip]=ports_list

        if ports_list !=[]:
            iolock.acquire()
            print('find ports on host:',ip,':')
            print(ports_list)
            iolock.release()

    #  @pysnooper.snoop()
    def start_task(self,task): #one task scan only one ip with different ports
        iolock.acquire()
        print("masscan scanning ip:",task.ip)
        iolock.release()
        cmd = 'masscan {ip} -p{ports} --wait 0 --rate 1500'.format(ip=task.ip,ports=task.ports)
        proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        proc.wait()
        stdoutdata=proc.stdout.read().decode('UTF-8')
        stderrdata = proc.stderr.read().decode('UTF-8')
        #  print(stdoutdata)
        self.analyze(stdoutdata,task.ip)
    
    def run(self):
        for task in self.task_list:
            self.start_task(task)
        # p = subprocessPopen(cmd,)

# for namp scanner, a task inlude one ip with its all ports
class Nmap_Scanner:
    def __init__(self,task_list):
        self.task_list = task_list
        self.result={}


    def start_task(self,task):
        print('start determine service/version of ports on host:',task.ip)
        nm = nmap.PortScanner()
        nm.scan(hosts=task.ip,ports=task.ports,arguments='-T4 -sV -Pn -sS',sudo=True)
        #  if task.ip in nm:
        self.result[task.ip]=nm[task.ip]
        #  else:
            #  self.result[task.ip]=None

    def print_scan_result(self):
        for ip in self.result:
            print('----------------------------------------------------')
            print('Host : {}'.format(ip))
            print('--------------------')
            ports_dict = sorted(self.result[ip]['tcp'])
            for port in ports_dict:
                portinfo=self.result[ip]['tcp'][port]
                str_buffer = 'port : {port}\tstate : {state}\t{name} {product} {version}'.format(port=port,
                                                                                               state=portinfo['state'],
                                                                                               name=portinfo['name'],
                                                                                               product=portinfo['product'],
                                                                                               version=portinfo['version'])
                print(str_buffer)
    def output_file(self,filename):
        json_data = {}
        for ip in self.result:
            ports_dict = sorted(self.result[ip]['tcp'])
            json_data[ip]={}
            for port in ports_dict:
                portinfo=self.result[ip]['tcp'][port]
                json_data[ip][port] = {
                    'state':portinfo['state'],
                   'name':portinfo['name'],
                   'product':portinfo['product'],
                   'version':portinfo['version']
                   }
        with open(filename, 'w') as f:
            json.dump(json_data, f)

    def run(self):
        for task in self.task_list:
            self.start_task(task)

# @pysnooper.snoop()
def split_task(ip): #split ports range in 5 pieces and return a list
    ports_list = [str(x) for x in range(1,65536)]
    n = int(65535/5)
    task_list = []
    for x in range(5):
        list_ = ports_list[n*x:n*x+n]
        task = Task(ip,list_)
        task_list.append(task)
    
    return task_list

    




#  @pysnooper.snoop()
def main():
    if os.getuid() != 0:
        print('please run this script with root!')
        exit()


    parser = argparse.ArgumentParser()
    parser.add_argument('host',nargs='?',help='read ip from a file',default=None)
    parser.add_argument('-r','--input',help='read ip from a file')
    parser.add_argument('-c','--cidr',help='scan a range of ip')
    parser.add_argument('-o','--output',help='output filename')
    args = parser.parse_args()
    task_list=[]
    if args.host != None:
        task_list += split_task(args.host)
    if args.input != None:
        f = open(args.input,'r')
        for line in f:
            task_list += split_task(line.replace('\n','').replace('\r',''))
        f.close()
    if args.cidr != None:
        for ip in IP(args.cidr):
            task_list += split_task(ip)

    if task_list==[]:
        print('Please input at least one target!')
        exit()

    masscaner_num = 2
    task_per_scanner = int(len(task_list)/masscaner_num)
    masscanner_list = []

    for x in range(masscaner_num):
        scanner = Mas_Scanner(task_list[x*task_per_scanner:x*task_per_scanner+task_per_scanner])
        masscanner_list.append(scanner)
        scanner.start()

    for scanner in masscanner_list:
        scanner.join()
        
    
    masscan_result = {}
    for scanner in masscanner_list:
        for ip in scanner.result:
            if ip not in masscan_result:
                masscan_result[ip]=scanner.result[ip]
            else:
                masscan_result[ip]+=scanner.result[ip]

    print('masscan scan complete:')
    print(masscan_result)
    nmap_task_list = []
    for ip in masscan_result:
        if len(masscan_result[ip])!=0:
            nmap_task_list.append(Task(ip,masscan_result[ip]))

    nm_scanner = Nmap_Scanner(nmap_task_list)
    nm_scanner.run()
    nm_scanner.print_scan_result()
    if args.output !=None:
        nm_scanner.output_file(args.output)


if __name__=='__main__':
    main()

