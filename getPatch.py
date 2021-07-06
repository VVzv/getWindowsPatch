# !/usr/bin/python
# -*- coding:utf-8 -*-
# __Author__: VVzv

'''
本脚本是根据CVE编号获取微软官方不同操作系统补丁编号的
'''
import sys
import requests

from colorama import init
if sys.platform.lower() == "win32":
    init(autoreset=True)

print("如不清楚操作系统版本，可使用winver指令查看!")
cve_code = input("[*] 请输入CVE编号(格式:CVE-2021-24094):").strip() #"CVE-2021-24094"
windows_ver = input("[*] 请输入操作系统版本(格式:Windows 10 20H2):").strip() #"Windows 10 20h2"
splist_winver = windows_ver.split(" ")
windows_code = splist_winver[0].lower() + " " + splist_winver[1]
url = "https://api.msrc.microsoft.com/sug/v2.0/zh-CN/affectedProduct?$filter=cveNumber+eq+'{}'".format(cve_code.upper())
headers={
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
}

req = requests.get(url, headers=headers)
patch_list = []
if req.status_code == 200:
    patch_list = req.json()['value']
else:
    print("\033[31m[-][{}] 请求错误!\033[0m".format(req.status_code))

c = 0
patch_code = 0
patch_down = ''
print("\033[36m[*] 发现{}补丁信息：\033[0m".format(cve_code))
for p in patch_list:
    windows_version = p['product']
    patch_num = p['kbArticles'][0]['articleName']
    patch_download_url = p['kbArticles'][0]['downloadUrl']
    if windows_code in windows_version.lower() and splist_winver[-1] in windows_version.lower():
        print("\033[36m[*] \033[36m{}\033[0m｜\033[36m{}\033[0m｜\033[36m{}\033[0m".format(windows_version, patch_num, patch_download_url))
        patch_code = patch_num
        patch_down = patch_download_url
        c += 1

if c == 0:
    print("\033[35m[-] 未发现'{}'的'{}'微软官方补丁，请检查操作系统版本或CVE是否输入错误。\033[0m".format(cve_code, windows_ver))
else:
    print("\033[32m[+] {}的{}微软官方补丁为：[KB{}]\033[0m".format(windows_ver, cve_code, patch_code))
    print("\033[32m[+] 下载地址为：{}\033[0m".format(patch_down))


