#  首先运行2或3个并发的Masscan任务，所有的65535个端口分为4-5个更小的范围；
#  获取主机列表以及Masscan扫描出的开放端口的组合列表；
#  使用这些列表作为Nmap的扫描目标并执行常规Nmap扫描。

import subprocess

class Mas_Scanner:
    def __init__(self,target,ports):
        self.target=target 
        self.ports=ports

    def run(self):
        cmd = 'masscan {ip} -p{ports} --rate 50000'
        p = subprocess.Popen(cmd,)


