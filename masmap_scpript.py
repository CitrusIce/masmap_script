# -*- coding: utf-8 -*-
#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess
import pysnooper

class task:
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

    def start_task(self,task): #one task scan only one ip
        cmd = 'masscan {ip} -p{ports} --rate 50000'.format(ip=task.ip,ports=task.ports)
        print(cmd)
        proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdoutdata=proc.stdout.read().decode('UTF-8')
        self.analyze(stdoutdata,task.ip)
    
    def run(self):
        for task in self.task_list:
            self.start_task(task)
        # p = subprocessPopen(cmd,)


if __name__=='__main__':
    task_ = task('47.93.234.29',list(range(1,1000)))
    scanner=Mas_Scanner([task_,])
    scanner.run()
    print(scanner.result)
    # scanner.run()