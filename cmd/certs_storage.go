package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/idna"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type CertificatesStorage struct {
	rootPath    string
	archivePath string
	pem         bool
}

// NewCertificatesStorage create a new certificates storage.
func NewCertificatesStorage() *CertificatesStorage {
	return &CertificatesStorage{
		rootPath:    filepath.Join(SavePath, "certificates"),
		archivePath: filepath.Join(SavePath, "archives"),
		pem:         true,
	}
}
func (s *CertificatesStorage) CreateRootFolder() {
	err := createNonExistingFolder(s.rootPath)
	if err != nil {
		log.Fatalf("Could not check/create path: %v", err)
	}
}
func (s *CertificatesStorage) SaveResource(certRes *certificate.Resource) {
	domain := certRes.Domain

	// We store the certificate, private key and metadata in different files
	// as web servers would not be able to work with a combined file.
	err := s.WriteFile(domain, ".crt", certRes.Certificate)
	if err != nil {
		log.Fatalf("Unable to save Certificate for domain %s\n\t%v", domain, err)
	}

	if certRes.IssuerCertificate != nil {
		err = s.WriteFile(domain, ".issuer.crt", certRes.IssuerCertificate)
		if err != nil {
			log.Fatalf("Unable to save IssuerCertificate for domain %s\n\t%v", domain, err)
		}
	}

	if certRes.PrivateKey != nil {
		// if we were given a CSR, we don't know the private key
		err = s.WriteFile(domain, ".key", certRes.PrivateKey)
		if err != nil {
			log.Fatalf("Unable to save PrivateKey for domain %s\n\t%v", domain, err)
		}

		if s.pem {
			err = s.WriteFile(domain, ".pem", bytes.Join([][]byte{certRes.Certificate, certRes.PrivateKey}, nil))
			if err != nil {
				log.Fatalf("Unable to save Certificate and PrivateKey in .pem for domain %s\n\t%v", domain, err)
			}
		}
	} else if s.pem {
		// we don't have the private key; can't write the .pem file
		log.Fatalf("Unable to save pem without private key for domain %s\n\t%v; are you using a CSR?", domain, err)
	}

	jsonBytes, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		log.Fatalf("Unable to marshal CertResource for domain %s\n\t%v", domain, err)
	}

	err = s.WriteFile(domain, ".json", jsonBytes)
	if err != nil {
		log.Fatalf("Unable to save CertResource for domain %s\n\t%v", domain, err)
	}
}

func (s *CertificatesStorage) WriteFile(domain, extension string, data []byte) error {
	var baseFileName string

	baseFileName = sanitizedDomain(domain)

	filePath := filepath.Join(s.rootPath, baseFileName+extension)

	return os.WriteFile(filePath, data, filePerm)
}

// sanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		log.Fatal(err)
	}
	return safe
}

func (s *CertificatesStorage) ReadCertificate(domain, extension string) ([]*x509.Certificate, error) {
	content, err := s.ReadFile(domain, extension)
	if err != nil {
		return nil, err
	}

	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}
func (s *CertificatesStorage) ReadFile(domain, extension string) ([]byte, error) {
	return os.ReadFile(s.GetFileName(domain, extension))
}

func (s *CertificatesStorage) GetFileName(domain, extension string) string {
	filename := sanitizedDomain(domain) + extension
	return filepath.Join(s.rootPath, filename)
}
