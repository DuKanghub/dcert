package main

import (
	"github.com/DuKanghub/dcert/cmd"
)

//先将config.yaml.demo改名为config.yaml，修改配置为自己真实配置。
//配置文件处理：cmd/config.go
//配置也可以在cmd/config.go中直接定义。
func main()  {
	//domains := []string{"dukanghub.com", "*.dukanghub.com"}	//通配符证书这么传入域名
	//challenge := "dns"	//验证方式，可选值：dns, http
	domains := []string{"dev.dukanghub.com"}	//这里写自己要申请证书的域名
	challenge := "dns"	//验证方式，可选值：dns, http
	cmd.GetSSLCerts(challenge, domains)
}