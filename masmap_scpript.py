# -*- coding: utf-8 -*-
#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess
import pysnooper
import threading
import os
import nmap

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
    
    @pysnooper.snoop()
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
        print(self.result[ip])
        print(ports_list)

    @pysnooper.snoop()
    def start_task(self,task): #one task scan only one ip with different ports
        # cmd = 'masscan {ip} -p{ports} --rate 50000 --wait 0'.format(ip=task.ip,ports=task.ports)
        cmd = 'masscan {ip} -p{ports} --wait 0 --rate 1500'.format(ip=task.ip,ports=task.ports)
        # print(cmd)
        proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        proc.wait()
        stdoutdata=proc.stdout.read().decode('UTF-8')
        stderrdata = proc.stderr.read().decode('UTF-8')
        print(stdoutdata)
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
        nm = nmap.PortScanner()
        nm.scan(hosts=task.ip,ports=task.ports,arguments='-T4 -sV -Pn -sS',sudo=True)
        self.result[task.ip]=nm[task.ip]

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
    def run(self):
        for task in self.task_list:
            self.start_task(task)

# @pysnooper.snoop()
def split_task(ip): #split ports range in 5 pieces and return a list
    ports_list = [str(x) for x in range(1,49152)]
    n = int(65535/5)
    task_list = []
    for x in range(5):
        list_ = ports_list[n*x:n*x+n]
        task = Task(ip,list_)
        task_list.append(task)
    
    return task_list

    




@pysnooper.snoop()
def main():
    # print([x.ports for x in split_task('47.93.234.29')])
    if os.getuid() != 0:
        print('please run this script with root!')
        exit()
    task_list = split_task('47.93.234.29')
    masscaner_num = 2
    task_per_scanner = int(len(task_list)/masscaner_num)
    masscanner_list = []
    # x = 0
    # scanner = Mas_Scanner([Task('47.93.234.29',[22,]),])
    # scanner = Mas_Scanner(task_list[x*task_per_scanner:x*task_per_scanner+task_per_scanner])
    # scanner.run()
    # print(scanner.result)
    # exit()
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

    print(masscan_result)
    nmap_task_list = []
    for ip in masscan_result:
        nmap_task_list.append(Task(ip,masscan_result[ip]))

    nm_scanner = Nmap_Scanner(nmap_task_list)
    nm_scanner.run()
    nm_scanner.print_scan_result()


if __name__=='__main__':
    print(Task('47.',[6600,22]).ports)
    nm_scanner = Nmap_Scanner([Task('47.93.234.29',[6600,22])])
    nm_scanner.run()
    nm_scanner.print_scan_result()
    # main()




    # task_ = Task('47.93.234.29',[22,4444])
    # nm = Nmap_Scanner([task_,])
    # nm.run()
    # nm.print_scan_result()
    #  scanner=Mas_Scanner([task_,])
    #  scanner.run()
    #  print(scanner.result)
    # scanner.run()
