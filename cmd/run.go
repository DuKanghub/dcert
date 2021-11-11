package cmd

import (
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"
	"log"
	"strings"
	"time"
)
const rootPathWarningMessage = `!!!! HEADS UP !!!!

Your account credentials have been saved in your Let's Encrypt
configuration directory at "%s".

You should make a secure backup of this folder now. This
configuration directory will also contain certificates and
private keys obtained from Let's Encrypt so making regular
backups of this folder is ideal.
`

func GetSSLCerts(challenge string, domains []string) {
	accountsStorage := NewAccountsStorage(Email)
	account, client := setup(accountsStorage)
	var err error
	if account.Registration == nil {
		reg, err := register(client)
		if err != nil {
			log.Fatalf("Could not complete registration\n\t%v", err)
		}
		account.Registration = reg
		if err = accountsStorage.Save(account); err != nil {
			log.Fatal(err)
		}

		fmt.Printf(rootPathWarningMessage, accountsStorage.GetRootPath())
	}
	certsStorage := NewCertificatesStorage()
	certsStorage.CreateRootFolder()
	challenge = strings.ToUpper(challenge)
	if challenge == "DNS" {
		//使用dns验证
		if strings.TrimSpace(AliAccessKeyId) == "" || strings.TrimSpace(AliAccessKeySecret) == "" {
			log.Fatal("使用dns验证需要传入 AliAccessKeyId 和 AliAccessKeySecret ")
		}
		dnsConfig := &alidns.Config{
			APIKey: AliAccessKeyId,
			SecretKey: AliAccessKeySecret,
			TTL: 600,
			HTTPTimeout: 60* time.Second,
		}
		dnsProvider, err := alidns.NewDNSProviderConfig(dnsConfig)
		if err != nil {
			log.Fatal(err)
		}
		err = client.Challenge.SetDNS01Provider(
			dnsProvider,
			dns01.AddRecursiveNameservers([]string{"114.114.114.114:53", "dns11.hichina.com:53", "dns12.hichina.com:53"}),
			dns01.AddDNSTimeout(60*time.Second),
		)
	} else if challenge == "HTTP" {
		//HTTP验证：起一个http server监听18888，需保证外网能访问到。
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "18888"))
	}

	if err != nil {
		log.Fatal(err)
	}

	cert, err := obtainCertificate(domains, client)
	if err != nil {
		// Make sure to return a non-zero exit code if ObtainSANCertificate returned at least one error.
		// Due to us not returning partial certificate we can just exit here instead of at the end.
		log.Fatalf("Could not obtain certificates:\n\t%v", err)
	}
	certsStorage.SaveResource(cert)

}

func register(client *lego.Client) (*registration.Resource, error) {
	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func obtainCertificate(domains []string, client *lego.Client) (*certificate.Resource, error) {

	if len(domains) > 0 {
		// obtain a certificate, generating a new private key
		request := certificate.ObtainRequest{
			Domains:                        domains,
			Bundle:                         false,
		}
		return client.Certificate.Obtain(request)
	}
	return nil,errors.New("请传入1个域名")
}