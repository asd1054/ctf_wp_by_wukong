```html

<html lang="zh-CN">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0" />
    <title>ctf.show_web11</title>
</head>
<body>
    <center>
    <h2>ctf.show_web11</h2>
    <hr>
		<h3>管理员认证</h3>
		<form method="get" action="login.php">

			密&nbsp;&nbsp;&nbsp;码：<input type="password" name="password" value="123456"></br>
			<input type="submit" value="登陆">
		</form>
	    </center><br>
		<code><span style="color: #000000">
<br /><span style="color: #0000BB">&lt;?php<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #007700">function&nbsp;</span><span style="color: #0000BB">replaceSpecialChar</span><span style="color: #007700">(</span><span style="color: #0000BB">$strParam</span><span style="color: #007700">){<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">$regex&nbsp;</span><span style="color: #007700">=&nbsp;</span><span style="color: #DD0000">"/(select|from|where|join|sleep|and|\s|union|,)/i"</span><span style="color: #007700">;<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return&nbsp;</span><span style="color: #0000BB">preg_replace</span><span style="color: #007700">(</span><span style="color: #0000BB">$regex</span><span style="color: #007700">,</span><span style="color: #DD0000">""</span><span style="color: #007700">,</span><span style="color: #0000BB">$strParam</span><span style="color: #007700">);<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if(</span><span style="color: #0000BB">strlen</span><span style="color: #007700">(</span><span style="color: #0000BB">$password</span><span style="color: #007700">)!=</span><span style="color: #0000BB">strlen</span><span style="color: #007700">(</span><span style="color: #0000BB">replaceSpecialChar</span><span style="color: #007700">(</span><span style="color: #0000BB">$password</span><span style="color: #007700">))){<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;die(</span><span style="color: #DD0000">"sql&nbsp;inject&nbsp;error"</span><span style="color: #007700">);<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if(</span><span style="color: #0000BB">$password</span><span style="color: #007700">==</span><span style="color: #0000BB">$_SESSION</span><span style="color: #007700">[</span><span style="color: #DD0000">'password'</span><span style="color: #007700">]){<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;echo&nbsp;</span><span style="color: #0000BB">$flag</span><span style="color: #007700">;<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}else{<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;echo&nbsp;</span><span style="color: #DD0000">"error"</span><span style="color: #007700">;<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br />&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color: #0000BB">?&gt;<br /></span><br /><br /></span>
</code>
</body>
</html>

```

根据提示，是对password进行注入，常规注入失败，开始读逻辑

本题也可以不用抓包 在F12里面找到cookie，将PHPSESSION删掉，再将输入框中的123456删掉，点提交即可

另外 如果在密码字段中输入的是本地存储的 PHPSESSID，而不是实际的密码，那么在比较用户输入的密码与 `$_SESSION['password']` 时，它们肯定是不匹配的。因为 `$_SESSION['password']` 应该存储的是用户的实际密码，而不是 PHPSESSID。 它根据你的PHPSESSID来确定服务器里面存的password是哪个，将它删掉，服务器就没法确认是哪个，置为空。然后你输入的password又为空，就能使题目的`$password==$_SESSION['password']`条件成立

服务端判断接收的Password是否等于session的password，由于session是通过session_id记录的，所以我们删除客户端的session_id，这样服务端就查不到我们的session，所以会等于NULL。

又因为，是弱类型比较，空字符等于NULL，条件成立。所以，我们再让密码等于空字符串，即可获得flag。


ctfshow{d247c58d-e069-4401-b71d-de487fafc49c}