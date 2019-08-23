# -*- coding:utf-8 -*-

import paramiko
from multiprocessing import Pool
import time
import requests
import json
import os

####################################### class start #######################################

class Emergency_Response(object):
    def __init__(self, ssh, ip):
        self.ssh = ssh
        self.ip = ip
        self.log = self.mkdir()

    def __del__(self):
        try:
            self.ssh.close()
        except Exception as e:
            self.logging(3, str(e))

    def mkdir(self):
        if not os.path.isdir('./log'):
            os.mkdir('./log')
        if not os.path.isdir('./log/'+self.ip):
            os.mkdir('./log/'+self.ip)
        name = './log/'+self.ip+'/'+self.ip + '_' + time.strftime("%Y%m%d%H%M%S", time.localtime())
        return name

    def logging(self, type, msg):
        # 1-info 2-waring 3-error
        if type == 2:
            ex = '[Waring] '
        elif type == 3:
            ex = '[Error] '
        else:
            ex = ''
        with open(self.log, 'a', encoding='utf-8') as f:
            f.write('%s%s\n' % (ex, msg))

    # 检查IP归属
    def check_remote_ip(self, ip):
        url = 'https://api.ip.sb/geoip/' + ip
        try:
            r = requests.get(url=url, timeout=(5, 10))
            data = json.loads(r.text)
            if 'country' in data and data['country'] != 'China':
                return data['country']
            else:
                return -1 
        except Exception as e:
            self.logging(2, str(e))
            return -1
            
    # 1.获取系统基本信息
    def system_info(self):
        command = "ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | awk BEGIN{RS=EOF}'{gsub(/\\n/,\" \");print}' && hostname && uname -ro && date"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            ip = info[0]
            hostname = info[1]
            version = info[2]
            time = info[3]
            info_write = '  当前系统IP地址为：'+ip+'\n'+'  当前系统主机名称为：'+hostname+'\n'+'  当前系统内核版本为:'+version+'\n'+'  当前系统时间为：'+time
            self.logging(1, str(info_write))
        except Exception as e:
            self.logging(3, str(e))

    # 2.根据netstat，获取异常程序pid，并定位异常所在路径
    def netstat_analysis(self):
        command = "netstat -antp | grep 'ESTABLISHED\|SYN_SENT\|SYN_RECV' | awk '{print $5,$7}'"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            remote_ip = {}
            pids = set()
            for line in info:
                ip = ''.join(line.split()[0].split(':')[:-1])
                if line.split()[1] != '-':
                    pid = line.split()[1].split('/')[0]
                    pname = line.split()[1].split('/')[1]
                else:
                    pid = pname = None        

                if ip not in remote_ip:
                    country = self.check_remote_ip(ip)
                    if country != -1:
                        self.logging(1, '  发现国外ip: '+ip+'，归属地：'+country)
                        remote_ip[ip] = True
                    else:
                        remote_ip[ip] = False    

            if (remote_ip[ip] == True) and (pid not in pids) and (pid != None):
                pids.add(pid)
                self.logging(1, '  发现可疑进程 pid: '+pid+'，进程名：'+pname)
                self.check_pid(pid)
        except Exception as e:
            self.logging(3, str(e))
    
    # 3.根据cpu占用率，获取异常程序pid，并定位异常所在路径
    def cpu_analysis(self):
        command = "ps -aux | awk 'NR!=1' | sort -nr -k 3 | awk '$3>=0.1{print $2,$3}'"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            cpus = stdout.read().decode('utf-8').strip().splitlines()
            for cpu in cpus:
                pid = cpu.split()[0]
                how = cpu.split()[1]
                self.logging(1, '  发现可疑进程 pid: '+pid+'，CPU使用率：'+how)
                self.check_pid(pid)
        except Exception as e:
            self.logging(3, str(e))
    
    # 获取进程详细信息
    def check_pid(self, pid):
        command = "ls -l /proc/" + pid + " | awk 'NR==11||NR==13{print $11}'"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
        except Exception as e:
            self.logging(3, str(e))

        try:
            dir = info[0]
            exe = info[1]
            self.logging(1, '    进程目录: '+dir+'，可执行文件：'+exe)
        except:
            self.logging(1, '    没有找到进程详细信息')   

    #4.查看系统启动项目，根据时间排序，列出最近修改的前5个启动项
    def get_init(self):
        command = "ls -lth /etc/rc.d/init.d | sed -n '2,6p'"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  根据最近修改时间，系统启动项前5名如下：')
            for line in info:
                self.logging(1, '    '+line)
        except Exception as e:
            self.logging(3, str(e))

    #5.查看历史命令，列出处存在可疑参数的命令；
    def get_history(self):
        command = "tail -200 ~/.bash_history | grep -a 'wget\|curl\|rpm\|install\|tar\|zip\|chmod\|rm\|mv\|chown'"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  发现以下可疑命令，需要进行手动确认：')
            for line in info:
                self.logging(1, '    '+line)
        except Exception as e:
            self.logging(3, str(e))
    
    #6.查看特权用户和当前登录用户
    def get_uers(self):
        try:
            command = "awk -F: '$3==0{print $1}' /etc/passwd"
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  特权用户有：')
            for x in info:
                self.logging(1, '    '+x)
            
            command = "who"
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  当前登录用户（tty本地登陆  pts远程登录）：')
            for x in info:
                self.logging(1, '    '+x)

        except Exception as e:
            self.logging(3, str(e))

    #7.查看定时任务
    def get_crontab(self):
        command = "crontab -l"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            if info == []:
                self.logging(1, '  暂无定时任务')
            else:
                self.logging(1, '  定时任务有：')
                for line in info:
                    self.logging(1, '    '+line)
        except Exception as e:
            self.logging(3, str(e))

    #8.查看、保存最近三天系统文件修改情况
    def get_filerevise(self):
        command = "find ./ -mtime 0 -o -mtime 1 -o -mtime 2  -o -mtime 3"
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  最近三天修改文件：')
            for line in info:
                self.logging(1, '    '+line)
        except Exception as e:
            self.logging(3, str(e))

    #9.分析secure日志
    def check_secure_log(self):
        try:
            command = "grep 'Failed password for root' /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | awk 'NR<=10'"
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  爆破主机的root帐号次数最多前十位的IP：')
            for line in info:
                self.logging(1, '    '+line.strip())

            command = "grep 'Accepted' /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr"
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  登录成功的IP：')
            for line in info:
                self.logging(1, '    '+line.strip())

            command = "grep 'Accepted' /var/log/secure | awk '{print $1,$2,$3,$9,$11}' | tail -10"
            stdin, stdout, stderr = self.ssh.exec_command(command)
            info = stdout.read().decode('utf-8').strip().splitlines()
            self.logging(1, '  最后10次登录成功的时间：')
            for line in info:
                self.logging(1, '    '+line)

        except Exception as e:
            self.logging(3, str(e))

####################################### class finish #######################################

def start(ip):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip[0], ip[1], ip[2], ip[3], timeout=10)
    except Exception as e:
        print(ip[0]+' 连接失败：'+str(e))
        return 

    er = Emergency_Response(ssh, ip[0])
    er.logging(1, '1. 获取系统基本信息')
    er.system_info()
    er.logging(1, '\n2. 网络端口检查')
    er.netstat_analysis()
    er.logging(1, '\n3. CPU占有率检查')
    er.cpu_analysis()
    er.logging(1, '\n4. 系统启动项目检查')
    er.get_init()
    er.logging(1, '\n5. 历史命令检查')
    er.get_history()
    er.logging(1, '\n6. 特权用户和当前登录用户检查')
    er.get_uers()
    er.logging(1, '\n7. crontab定时任务检查')
    er.get_crontab()
    er.logging(1, '\n8. 文件修改情况检查')
    er.get_filerevise()
    er.logging(1, '\n9. secure日志检查')
    er.check_secure_log()
    return ip[0]

def call(msg):
    if msg == None:
        return
    print(msg+' 已完成')

if __name__ == '__main__':
    with open('ips.txt') as f:
        tmp = f.readlines()
    ips = []
    for x in tmp:
        if x.strip() != '':
            ips.append(x.strip())
    pool = Pool(4)
    print('此次排查任务共有%d个IP：' % len(ips))
    for ip in ips:
        print(ip.split()[0])
        pool.apply_async(start, args=(ip.split(),), callback=call)
    pool.close()
    pool.join()
    print('全部完成')
