>p=k*M+(65537**a %M)



# Backdoor 题目详细解题报告

## 题目信息

- 题目名称: Backdoor
- 考点: RSALib-CVE漏洞 (ROCA - Return of Coppersmith Attack, CVE-2017-15361)
- 题目文件:
  - `pub.pem`: RSA公钥文件
  - `flag.enc`: 加密后的flag文件
  - `task.py`: 加密脚本

## 题目分析

### 1. 文件内容解析

首先，我们分析了题目提供的文件：

**pub.pem**:
```
-----BEGIN PUBLIC KEY-----
MFMwDQYJKoZIhvcNAQEBBQADQgAwPwI4BXdHlrMB4cf0C0lFBWiLH94h9tX/zmNv
8WfYXjfXp7dJPjPBfUQXolyiSmcWMUzxhuFpltz8Z5sCAwEAAQ==
-----END PUBLIC KEY-----
```

**flag.enc**:
```
MDIxNDJhZjdjZTcwZmUwZGRhZTExNmJiN2U5NjI2MDI3NGVlOTI1MmE4Y2I1MjhlN2ZkZDI5ODA5YzJhNjAzMjcyN2MwNTUyNjEzM2FlNDYxMGVkOTQ0NTcyZmYxYWJmY2QwYjE3YWEyMmVmNDRhMg==
```

**task.py**:
```python
#!/usr/bin/python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import gmpy2, binascii
import base64
from FLAG import flag

def rsa_encrypt(message):
    with open('./pub.pem' ,'r') as f:
        key = RSA.import_key(f.read())
    e = key.e
    n = key.n
    c = pow(bytes_to_long(flag), e, n)

    ciphertext = binascii.hexlify(long_to_bytes(c))
    return ciphertext

if __name__ == "__main__":
    text = base64.b64encode(rsa_encrypt(flag))
    with open('flag.enc','wb') as f:
        f.write(text)
```

### 2. RSA参数解析

通过解析公钥文件，我们得到:
- 模数 n = 15518961041625074876182404585394098781487141059285455927024321276783831122168745076359780343078011216480587575072479784829258678691739
- 公钥指数 e = 65537

### 3. 加密过程分析

根据task.py，加密过程如下：
1. 将flag转换为整数: `m = bytes_to_long(flag)`
2. RSA加密: `c = pow(m, e, n)`
3. 转换为十六进制字符串: `hex_c = binascii.hexlify(long_to_bytes(c))`
4. Base64编码: `base64.b64encode(hex_c)`
5. 保存到flag.enc

所以解密过程是：base64解码 → 十六进制转整数 → RSA解密

解析后的密文为：
```
02142af7ce70fe0ddae116bb7e96260274ee9252a8cb528e7fdd29809c2a6032727c05526133ae4610ed944572ff1abfcd0b17aa22ef44a2
```

对应的整数密文 c = 5902102609936183530036413041949205016072856184947596155784933422689438216690059498706287388882989673839294236821030261398121787376802

## 解题思路与漏洞分析

### 1. ROCA漏洞 (CVE-2017-15361) 简介

ROCA (Return of Coppersmith Attack) 是一种针对RSA实现的攻击方法，CVE编号为CVE-2017-15361。该漏洞影响了Infineon Technologies AG生产的RSA密钥生成库。

漏洞的核心问题是：受影响的库在生成RSA质因数时使用了特定的数学结构，导致生成的质因数不够随机，具有可预测的模式。

### 2. 漏洞原理

受影响的库使用以下公式生成质因数：
```
p = k*M + (65537^a mod M)
```

其中：
- M 是前x个素数的乘积
- k 是一个正整数
- a 是一个正整数
- 65537 是常用的RSA公钥指数

这种生成方式使得质因数p具有特定的数学结构，攻击者可以利用这一结构来恢复私钥。

### 3. 解题过程

#### 步骤1: 解析密文
首先对`flag.enc`进行Base64解码，得到十六进制字符串，再转换为整数作为密文c。

#### 步骤2: 分析RSA参数
从`pub.pem`中提取公钥参数n和e。

#### 步骤3: 利用ROCA漏洞分解n
根据ROCA漏洞原理，质因数p具有形式`p = k*M + (65537^a mod M)`。

对于不同长度的RSA密钥，使用的素数个数不同：
- 512-960位密钥：使用前39个素数计算M
- 992-1952位密钥：使用前71个素数计算M
- 1984-3936位密钥：使用前126个素数计算M
- 3968-4096位密钥：使用前225个素数计算M

我们的n是443位，应该使用前39个素数计算M。

计算M：
```python
vals = 39
M = 1
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]
for x in range(0, vals):
    M = M * primes[x]
```

得到M = 962947420735983927056946215901134429196419130606213075415963491270

#### 步骤4: 暴力搜索k和a
由于k和a的值不会太大，可以进行暴力搜索：

```python
for a in range(1, 20):
    for k in range(50):
        p = k*M + (65537**a % M)
        if is_prime(p):
            q = n // p
            if is_prime(q):
                # 找到因数分解
                print('p=%d\nq=%d' % (p, q))
```

通过搜索，我们找到：
- k = 4
- a = 18
- p = 4582433561127855310805294456657993281782662645116543024537051682479
- q = 3386619977051114637303328519173627165817832179845212640767197001941

验证：p * q = n，且p和q都是素数。

#### 步骤5: RSA解密
有了p和q，我们可以计算私钥并解密：

```python
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag)
```

## 完整解题代码

```python
#!/usr/bin/env python3
from Crypto.Util.number import *
import gmpy2
import binascii
import base64

# 1. 解析密文
with open('flag.enc', 'rb') as f:
    encrypted_data = f.read()

# Base64解码
decoded_data = base64.b64decode(encrypted_data)
hex_str = decoded_data.decode()
c = int(hex_str, 16)

# 2. RSA参数
e = 65537
n = 15518961041625074876182404585394098781487141059285455927024321276783831122168745076359780343078011216480587575072479784829258678691739

# 3. ROCA漏洞利用
vals = 39
M = 1
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]

for x in range(0, vals):
    M = M * primes[x]

# 暴力搜索k和a
for a in range(1, 20):
    for k in range(50):
        p = k*M + (65537**a % M)
        if gmpy2.is_prime(p):
            q = n // p
            if gmpy2.is_prime(q):
                print('找到因数分解:')
                print('p=%d' % p)
                print('q=%d' % q)
                
                # 4. 解密
                phi = (p - 1) * (q - 1)
                d = int(gmpy2.invert(e, phi))
                m = pow(c, d, n)
                flag = long_to_bytes(m)
                print('flag:', flag.decode())
                break
```

## 知识点解释

### 1. ROCA漏洞 (CVE-2017-15361)

ROCA是一种针对RSA实现的攻击，影响了Infineon Technologies AG生产的RSA密钥生成库。该漏洞允许攻击者从公钥中恢复私钥。

漏洞的关键在于受影响的库使用特定的数学公式生成质因数：
```
p = k*M + (65537^a mod M)
```

其中M是前几个素数的乘积，这使得质因数具有可预测的结构。

### 2. Coppersmith方法

Coppersmith方法是一种用于寻找多项式小根的技术，在ROCA攻击中被用来恢复私钥。当RSA的质因数具有部分已知信息时，可以使用这种方法恢复完整的因数。

### 3. SageMath在密码学中的应用

SageMath是密码学研究中常用的工具，它提供了丰富的数学函数，包括：
- 多项式环和有限域运算
- 格基约化算法
- 数论函数（如因数分解、素数测试等）

对于本题，如果使用SageMath，可以更方便地使用Coppersmith方法。

## 解题过程总结

本题是一个典型的ROCA漏洞利用题目。解题的关键步骤包括：

1. 理解题目提示`p = k*M + (65537^a mod M)`的含义
2. 识别这是CVE-2017-15361 (ROCA)漏洞
3. 根据密钥长度确定使用的素数个数来计算M
4. 通过暴力搜索找到合适的k和a值
5. 利用因数分解进行RSA解密

## 防护建议

1. 避免使用存在已知漏洞的密码库
2. 定期更新和审查使用的加密库
3. 使用经过充分验证的随机数生成器
4. 对于RSA密钥生成，确保使用安全的质因数生成方法
5. 定期检查密钥是否受到已知漏洞影响

## 学习建议

1. 深入学习RSA密码系统的数学原理
2. 了解常见的RSA实现漏洞和攻击方法
3. 掌握Coppersmith方法及其在密码分析中的应用
4. 学习使用SageMath等数学工具进行密码学分析
5. 关注CVE漏洞数据库，了解最新的安全漏洞

## 运行脚本

我们创建了解题脚本，位于：
- `/Users/apple/github/ctf解题思路/Backdoor/verify_solution.py`

要运行脚本，请使用以下命令：
```bash
python3 /Users/apple/github/ctf解题思路/Backdoor/verify_solution.py
```

## 结论

本题考查了对ROCA漏洞(CVE-2017-15361)的理解和利用能力。通过分析题目提示并识别出这是经典的ROCA漏洞，我们成功地利用了受影响库的质因数生成缺陷，通过暴力搜索找到了因数分解，最终成功解密获得了flag：

**flag{760958c9-cca9-458b-9cbe-ea07aa1668e4}**