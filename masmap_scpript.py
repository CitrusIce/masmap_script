#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess

class task:
    def __init__(self,ip,ports):
         self.ip=ip
         self.ports=ports

class Mas_Scanner:
    def __init__(self,task_list):
        self.task_list=task_list
        self.result={}
    
    def analyze(self,data,ip):#analyze and add task scan result to scanner result
        ports_list=[]
        for line in data.split('\n'):
            port = line.split()[3] # xx/tcp
            port = port.split('/')[0] 
            ports_list.append(port)

        if ip in self.result:
            self.result[ip]=self.result[ip]+ports_list
        self.result[ip]=ports_list

    def start_task(self,task): #one task scan only one ip
        cmd = 'masscan {ip} -p{ports} --rate 50000'.format(ip=task.ip,ports=task.ports)
        stdoutdata = subprocess.getoutput(cmd)
        self.analyze(stdoutdata,task.ip)
    


    def run(self):
        for task in self.task_list:
            self.start_task(task)
        # p = subprocessPopen(cmd,)


if __name__=='__main__':
    pass
    # scanner=Mas_Scanner(1,2)
    # scanner.run()