package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type AccountsStorage struct {
	userID          string
	rootPath        string
	rootUserPath    string
	keysPath        string
	accountFilePath string
}

func NewAccountsStorage(email string) *AccountsStorage {
	// TODO: move to account struct? Currently MUST pass email.
	serverURL, err := url.Parse(CADirURL)
	if err != nil {
		log.Fatal(err)
	}

	rootPath := filepath.Join(SavePath, "accounts")
	serverPath := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(serverURL.Host)
	fmt.Println("serverPath:", serverPath)
	accountsPath := filepath.Join(rootPath, serverPath)
	rootUserPath := filepath.Join(accountsPath, email)

	return &AccountsStorage{
		userID:          email,
		rootPath:        rootPath,
		rootUserPath:    rootUserPath,
		keysPath:        filepath.Join(rootUserPath, "keys"),
		accountFilePath: filepath.Join(rootUserPath, "account.json"),
	}
}
func (s *AccountsStorage) ExistsAccountFilePath() bool {
	accountFile := filepath.Join(s.rootUserPath, "account.json")
	if _, err := os.Stat(accountFile); os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
	}
	return true
}
func (s *AccountsStorage) Save(account *AcmeAccount) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	return os.WriteFile(s.accountFilePath, jsonBytes, filePerm)
}
func (s *AccountsStorage) LoadAccount(privateKey crypto.PrivateKey) *AcmeAccount {
	fileBytes, err := os.ReadFile(s.accountFilePath)
	if err != nil {
		log.Fatalf("Could not load file for account %s: %v", s.userID, err)
	}

	var account AcmeAccount
	err = json.Unmarshal(fileBytes, &account)
	if err != nil {
		log.Fatalf("Could not parse file for account %s: %v", s.userID, err)
	}

	account.key = privateKey

	if account.Registration == nil || account.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(privateKey)
		if err != nil {
			log.Fatalf("Could not load account for %s. Registration is nil: %#v", s.userID, err)
		}

		account.Registration = reg
		err = s.Save(&account)
		if err != nil {
			log.Fatalf("Could not save account for %s. Registration is nil: %#v", s.userID, err)
		}
	}

	return &account
}
func tryRecoverRegistration( privateKey crypto.PrivateKey) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&AcmeAccount{key: privateKey})
	config.CADirURL = CADirURL
	config.UserAgent = fmt.Sprintf("lego-cli/%s", "dev")

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}
func (s *AccountsStorage) GetUserID() string {
	return s.userID
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}
	return nil, errors.New("unknown private key type")
}
func (s *AccountsStorage) GetRootPath() string {
	return s.rootPath
}

func (s *AccountsStorage) GetRootUserPath() string {
	return s.rootUserPath
}

func (s *AccountsStorage) createKeysFolder() {
	if err := createNonExistingFolder(s.keysPath); err != nil {
		log.Fatalf("Could not check/create directory for account %s: %v", s.userID, err)
	}
}
func (s *AccountsStorage) GetPrivateKey(keyType certcrypto.KeyType) crypto.PrivateKey {
	accKeyPath := filepath.Join(s.keysPath, s.userID+".key")

	if _, err := os.Stat(accKeyPath); os.IsNotExist(err) {
		log.Printf("No key found for account %s. Generating a %s key.", s.userID, keyType)
		s.createKeysFolder()

		privateKey, err := generatePrivateKey(accKeyPath, keyType)
		if err != nil {
			log.Fatalf("Could not generate RSA private account key for account %s: %v", s.userID, err)
		}

		log.Printf("Saved key to %s", accKeyPath)
		return privateKey
	}

	privateKey, err := loadPrivateKey(accKeyPath)
	if err != nil {
		log.Fatalf("Could not load RSA private key from file %s: %v", accKeyPath, err)
	}

	return privateKey
}
func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = certOut.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}