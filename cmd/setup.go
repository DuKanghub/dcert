package cmd

import (
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"log"
	"os"
	"time"
)

const filePerm os.FileMode = 0o600
func createNonExistingFolder(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o700)
	} else if err != nil {
		return err
	}
	return nil
}
func setup(accountsStorage *AccountsStorage) (*AcmeAccount, *lego.Client) {
	privateKey := accountsStorage.GetPrivateKey(certcrypto.RSA2048)
	var account *AcmeAccount
	if accountsStorage.ExistsAccountFilePath() {
		account = accountsStorage.LoadAccount(privateKey)
	} else {
		account = &AcmeAccount{Email: accountsStorage.GetUserID(), key: privateKey}
	}
	client := newClient(account, certcrypto.RSA2048)

	return account, client
}
func newClient(acc registration.User, keyType certcrypto.KeyType) *lego.Client {
	config := lego.NewConfig(acc)
	config.CADirURL = CADirURL

	config.Certificate = lego.CertificateConfig{
		KeyType: keyType,
		Timeout: 7*24*60*60 * time.Second,	//这个时间不知道是做什么用的
	}
	config.UserAgent = fmt.Sprintf("lego-cli/%s", "dev")


	config.HTTPClient.Timeout = 300 * time.Second


	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("Could not create client: %v", err)
	}


	return client
}