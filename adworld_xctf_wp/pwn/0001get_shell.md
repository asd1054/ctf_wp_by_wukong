>运行就能拿到shell呢，真的

pwn 入门题目，做题之前先说几个常用的工具（大佬总不至于跑来找这个题的 wp
吧 *手动狗头*）
IDA Pro
IDA 是一款优秀的静态反汇编工具，好处就不多说了，什么一键 F5、字符串搜索、
函数位置查找等等，好用的不得了，下载可以去 [ 看雪论
坛](https://www.kanxue.com/)找。
pwntools
[pwntools 官网](https://pwntools.readthedocs.io/en/stable/)是这样说的：pwntools
是一个 CTF 框架和开发库。它是用 Python 编写的，旨在快速构建原型和开发，
并使利用编写尽可能简单。
实际上就是用来帮助写 exp 的 python 库，用这个可以快速利用漏洞达到目的
**ps:这个东西只支持 python2**
peda
这个就基本算不上是一个工具了，它是 gdb（Linux 下的动态调试工具）的插件，
功能挺强大的
安装：
 git clone https://github.com/longld/peda.git ~/peda
 echo "source ~/peda/peda.py" >> ~/.gdbinit
 echo "DONE! debug your program with gdb and enjoy"
好了，咱们开始进入正题
首先下载附件拿到一个文件，直接扔到 Linux 中查一下（checksec 在下载好
pwntools 后就有）
从图上可以看出它是一个 64 位程序，开了 NX 防护（堆栈不可执行）。唔，好的，
基本信息咱们已经知道了，然后可以试着执行一下这个程序（Linux 下）：
emmm...啥玩儿，这就结束了？？？（╯‵□′）╯︵┴─┴
好吧，客官们可以走了，后续用 nc（Linux 自带）连接一下就行，命令：
nc ip 地址 ip 端口


![[get_shell.png]]