package cmd

import (
	"fmt"
	"github.com/spf13/viper"
	"strings"
)

type Config struct {
	Email string `yaml:"Email"`	//yaml字段名不能有_或-，否则解析不到。
	SavePath string `yaml:"SavePath"`
	CADirURL string `yaml:"CADirURL"`
	AliAccessKeyId string `yaml:"AliAccessKeyId"`
	AliAccessKeySecret string `yaml:"AliAccessKeySecret"`
}
//const (
//	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
//	//CADirURL = "http://192.168.99.100:4000/directory"	//自建CA环境用这个
//	//CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"	//测试环境用这个
//	//CADirURL = "https://acme.zerossl.com/v2/DV90"	//zerossl的接口，但是lego是否支持暂没确认。
//	CADirURL = "https://acme-v02.api.letsencrypt.org/directory" //生产环境用
//	SavePath = "G:/acme"                                        //账号与证书保存位置
//)
var conf Config
var (	//这里定义自己的一些账号信息
	Email = ""	//邮箱是必须的，写自己的
	AliAccessKeyId  = ""	//这里写自己的阿里RAM账号对应的KeyID和Secret
	AliAccessKeySecret = ""
	CADirURL = ""
	SavePath = ""
)
func init()  {	//初始化一些变量
	ReadConfig()
	if strings.TrimSpace(AliAccessKeyId) == "" {
		//AliAccessKeyId = os.Getenv("AliAccessKeyId")	//设置环境变量时名字要与这里的一样。
		AliAccessKeyId = conf.AliAccessKeyId
	}
	if strings.TrimSpace(AliAccessKeySecret) == "" {
		//AliAccessKeySecret = os.Getenv("AliAccessKeySecret")
		AliAccessKeySecret = conf.AliAccessKeySecret
	}
	if strings.TrimSpace(Email) == "" {
		Email = conf.Email
	}
	if strings.TrimSpace(CADirURL) == "" {
		CADirURL = conf.CADirURL
	}
	if strings.TrimSpace(SavePath) == "" {
		SavePath = conf.SavePath
	}


}

func ReadConfig()  {
	v := viper.New()
	v.SetConfigFile("config.yaml")
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	if err = v.Unmarshal(&conf);err!=nil {
		fmt.Println(err)
	}
	fmt.Printf("%+v\n", conf)
}