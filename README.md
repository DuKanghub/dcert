# 介绍

演示如何在代码中使用lego，参考lego cmd代码。去除cmd相关代码，重新封装相关函数。

本代码只演示了alidns使用。支持阿里dns自动验证及http验证来签发letsencrypt免费证书。

# 使用

## 修改配置

将代码根目录的`config.yaml.demo`改名为`config.yaml`，并在对应字段填上自己的信息。

- Email: 邮箱，用于注册账号。
- SavePath：保存目录。用于保存用户信息和签发的证书。
- CADirURL：CA目录地址，可以理解成申请证书的apiserver。用于申请证书。默认已经写上生产环境地址。
- AliAccessKeyId和AliAccessKeySecret：阿里用户的AccessKeyId和Secret。可以用主账号。也可以创建编程用的RAM用户。需要有完整DNS管理权限。

# 申请证书

打开main.go

```go
//定义你要申请证书的域名
domains := []string{"dev.dukanghub.com"}	
//如果要申请通配符证书，可如下定义
//domains := []string{"dukanghub.com", "*.dukanghub.com"}
//使用dns验证，需要配置有权限的阿里云用户AccessKeyId和AccessKeySecret
challenge := "dns"	//验证方式，可选值：dns, http
cmd.GetSSLCerts(challenge, domains)
```

如果使用http验证，需要将域名解析到公网可访问的服务器上，然后将`.well-known`反向代理至运行本程序的ip 18888端口。

证书如果签发成功。会保存在`${SavePath}/certificates`目录下。

假设申请域名为`dev.dukanghub.com`，则证书是在这个目录下的`dev.dukanghub.com.crt`或`dev.dukanghub.com.pem`(两个都可以，二者选其一，看自己喜欢)，私钥是`dev.dukanghub.com.key`，这两个文件就是web服务器要用到的ssl证书。



