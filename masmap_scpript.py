# -*- coding: utf-8 -*-
#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess
import pysnooper
import nmap

class Task:
    def __init__(self,ip,ports_list):
         self.ip=ip
         self.ports=','.join([str(x) for x in ports_list])

class Mas_Scanner:  
    def __init__(self,task_list):
        self.task_list=task_list
        self.result={}
    
    # @pysnooper.snoop()
    def analyze(self,data,ip):#analyze and add task scan result to scanner result
        ports_list=[]
        for line in data.split('\n'):
            if line!='':
                port = line.split()[3] # xx/tcp
                port = port.split('/')[0] 
                ports_list.append(port)

        if ip in self.result:
            self.result[ip]=self.result[ip]+ports_list
        self.result[ip]=ports_list

    def start_task(self,task): #one task scan only one ip with different ports
        cmd = 'masscan {ip} -p{ports} --rate 50000'.format(ip=task.ip,ports=task.ports)
        print(cmd)
        proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdoutdata=proc.stdout.read().decode('UTF-8')
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
            for port in self.result[ip]['tcp']:
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


if __name__=='__main__':
    task_ = Task('47.93.234.29',[22,4444])
    nm = Nmap_Scanner([task_,])
    nm.run()
    nm.print_scan_result()
    #  scanner=Mas_Scanner([task_,])
    #  scanner.run()
    #  print(scanner.result)
    # scanner.run()
