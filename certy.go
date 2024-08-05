package certy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	letsencryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	letsencryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
)

// DomainAcme is a struct for domain acme data
type DomainAcme struct {
	Sans       []string        `json:"sans"`
	IssuerData IssuerData      `json:"issuer_data"`
	AccountKey *rsa.PrivateKey `json:"account_key"`
	CertFile   string          `json:"cert_file"`
	KeyFile    string          `json:"key_file"`
	ExpireDate time.Time       `json:"expire_date"`
	IssueDate  time.Time       `json:"issue_date"`
	CustomCert bool            `json:"custom_cert"`
}

// Check is need renew certificate or not
func (d *DomainAcme) RenewRequired() bool {
	// check is need renew certificate or not
	return time.Now().After(d.ExpireDate.AddDate(0, 0, -2))
}

func (d *DomainAcme) IsNull() bool {
	// check is domain acme data is null or not
	return d.IssuerData.Ca == "" && d.IssuerData.URL == "" && d.IssuerData.ChallengeToken == "" && d.AccountKey == nil && d.IssueDate.IsZero()
}

// Expired is a method for checking certificate is expired or not
func (d *DomainAcme) Expired() bool {
	return time.Now().After(d.ExpireDate)
}

// IssuerData is a struct for issuer data
type IssuerData struct {
	URL            string `json:"url"`
	Ca             string `json:"ca"`
	ChallengeToken string `json:"challenge_token"`
}

// Manager is a struct for managing certificates
type Manager struct {
	Email    string
	Location string
	Staging  bool
}

// NewManager is a constructor for Manager struct
// email: email for letsencrypt account
// location: location to store acme data and certificates
func NewManager(email, location string, staging bool) *Manager {
	return &Manager{
		Email:    email,
		Location: location,
		Staging:  staging,
	}
}

// IssueCert is a method for issuing letsencrypt certificate
func (m *Manager) IssueCert(domain string) {
	m.issueLetsEncryptCert(m.Email, domain, m.Location)
}

// GetChallengeToken is a method for getting challenge token
func (m *Manager) GetChallengeToken(domain string) string {
	// m.Location + "/" + domain + "/" + domain + "-acme.json"
	location := fmt.Sprintf("%s/%s/%s-acme.json", m.Location, domain, domain)
	file, err := os.ReadFile(location)
	if err != nil {
		log.Fatalf("Failed to read domain acme file: %v", err)
	}

	var domainAcme DomainAcme
	if err := json.Unmarshal(file, &domainAcme); err != nil {
		log.Fatalf("Failed to unmarshal domain acme data: %v", err)
	}

	return domainAcme.IssuerData.ChallengeToken
}

// GetCert is a method for getting tls certificate
func (m *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	location := fmt.Sprintf("%s/%s/%s-acme.json", m.Location, domain, domain)
	file := fmt.Sprintf("%s/%s/%s-cert.crt", m.Location, domain, domain)
	key := fmt.Sprintf("%s/%s/%s-key.pem", m.Location, domain, domain)

	if _, err := os.Stat(location); os.IsNotExist(err) {
		return nil, errors.New("domain acme data not found")
	}

	certFileData, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("Failed to read certificate file " + err.Error())
	}

	keyFileData, err := os.ReadFile(key)
	if err != nil {
		return nil, errors.New("Failed to read key file " + err.Error())
	}

	cert, err := tls.X509KeyPair(certFileData, keyFileData)
	if err != nil {
		return nil, errors.New("Failed to get x509 key pair " + err.Error())
	}

	return &cert, nil
}

// GetAcmeFileData is a method for getting acme file data
func (m *Manager) GetAcmeFileData(domain string) (*DomainAcme, error) {
	// m.Location + "/" + domain + "/" + domain + "-acme.json"
	location := fmt.Sprintf("%s/%s/%s-acme.json", m.Location, domain, domain)
	file, err := os.ReadFile(location)
	if err != nil {
		return nil, err
	}

	var domainAcme DomainAcme
	if err := json.Unmarshal(file, &domainAcme); err != nil {
		return nil, err
	}

	return &domainAcme, nil
}

// HTTPHandler is a http handler for serving acme challenge
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if request path is has acme challenge
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}

		token := r.URL.Path[len("/.well-known/acme-challenge/"):]

		acmeData, err := m.GetAcmeFileData(r.Host)
		if err != nil {
			log.Fatalf("Failed to get acme file data: %v", err)
		}

		client := &acme.Client{
			DirectoryURL: acme.LetsEncryptURL,
			Key:          acmeData.AccountKey,
		}

		// HTTP-01 challenge response
		http01, err := client.HTTP01ChallengeResponse(m.GetChallengeToken(r.Host))
		if err != nil {
			log.Fatalf("HTTP-01 challenge response failed: %v", err)
		}

		if token == m.GetChallengeToken(r.Host) {
			w.Write([]byte(http01))
		} else {
			fallback.ServeHTTP(w, r)
		}
	})
}

var issuings = make(map[string]bool)

// issueLetsEncryptCert is a function for issuing letsencrypt certificate
func (m *Manager) issueLetsEncryptCert(email, domain, location string) {

	// check location is exists or not if not create it
	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err := os.Mkdir(location, 0755); err != nil {
			log.Fatalf("Failed to create directory: %v", err)
		}
	}

	// create folder for domain
	location = location + "/" + domain
	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err := os.Mkdir(location, 0755); err != nil {
			log.Fatalf("Failed to create domain directory: %v", err)
		}
	}

	// if not exists create domainAcme.json file
	domainAcmeFile := location + "/" + domain + "-acme.json"
	if _, err := os.Stat(domainAcmeFile); os.IsNotExist(err) {
		if _, err := os.Create(domainAcmeFile); err != nil {
			log.Fatalf("Failed to create domain acme file: %v", err)
		}
	}

	// read domainAcme.json file
	acmefile, err := os.ReadFile(domainAcmeFile)
	if err != nil {
		log.Fatalf("Failed to read domain acme file: %v", err)
	}

	var domainAcme DomainAcme
	json.Unmarshal(acmefile, &domainAcme)

	if !domainAcme.RenewRequired() {
		return
	}

	if !domainAcme.Expired() {
		log.Println("Certificate is not expired: " + domain)
		return
	}

	if _, ok := issuings[domain]; ok {
		log.Println("Issuing already in progress: " + domain)
		return
	} else {
		issuings[domain] = true
	}

	// Generate a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Account key generation failed: %v", err)
	}

	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		Key:          accountKey,
	}

	if m.Staging {
		client.DirectoryURL = letsencryptStagingURL
	}

	// Register a new ACME account
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	acct, err = client.Register(context.TODO(), acct, acme.AcceptTOS)
	if err != nil {
		log.Fatalf("Account registration failed: %v", err)
	}
	fmt.Printf("Account registered: %v\n", acct.URI)

	if domainAcme.IsNull() {
		// create domainAcme struct
		domainAcme = DomainAcme{
			Sans: []string{domain},
			IssuerData: IssuerData{
				URL: acct.URI,
				Ca:  client.DirectoryURL,
			},
			AccountKey: accountKey,
		}
	}

	// save domainAcme struct to domainAcme.json file
	jsonData, err := json.Marshal(domainAcme)
	if err != nil {
		log.Fatalf("Failed to marshal domain acme data: %v", err)
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Fatalf("Failed to write domain acme data: %v", err)
	}

	// Create a new order for the domain
	order, err := client.AuthorizeOrder(context.TODO(), acme.DomainIDs(domain))
	if err != nil {
		log.Fatalf("Order authorization failed: %v", err)
	}

	// HTTP-01 challenge for domain verification
	var chal *acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(context.TODO(), authzURL)
		if err != nil {
			log.Fatalf("Failed to get authorization: %v", err)
		}
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal != nil {
			break
		}
	}

	if chal == nil {
		log.Fatalf("No HTTP-01 challenge found")
	}

	domainAcme.IssuerData.ChallengeToken = chal.Token
	log.Println("Challenge token: " + chal.Token)

	// save domainAcme struct to domainAcme.json file
	jsonData, err = json.Marshal(domainAcme)
	if err != nil {
		log.Fatalf("Failed to marshal domain acme data: %v", err)
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Fatalf("Failed to write domain acme data: %v", err)
	}

	// Accept the challenge
	_, err = client.Accept(context.TODO(), chal)
	if err != nil {
		log.Fatalf("Challenge acceptance failed: %v", err)
	}

	// Wait for challenge to be valid
	for {
		log.Println("Checking challenge status", chal.URI, chal.Status)
		authz, err := client.GetAuthorization(context.TODO(), chal.URI)
		if err != nil {
			log.Printf("Failed to get authorization: %v \n", err)
		}
		if authz.Status == acme.StatusValid {
			break
		}
		if authz.Status == acme.StatusInvalid {
			log.Printf("Challenge failed: %v \n", authz)
		}
		// Wait before checking again
		time.Sleep(10 * time.Second)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("ECDSA private key generation failed: %v", err)
	}

	// Create a CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}, ecdsaPrivateKey)
	if err != nil {
		log.Fatalf("Certificate request creation failed: %v", err)
	}

	// Finalize the order and get the certificate
	der, _, err := client.CreateOrderCert(context.TODO(), order.FinalizeURL, csr, true)
	if err != nil {
		log.Fatalf("Certificate issuance failed: %v", err)
	}

	// der contains the certificate chain
	// Save the certificate chain to same file with different blocks

	certFile := location + "/" + domain + "-cert.crt"
	keyFile := location + "/" + domain + "-key.pem"

	if _, err := os.Create(certFile); err != nil {
		log.Fatalf("Failed to create certificate file: %v", err)
	}

	file, err := os.OpenFile(certFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	for _, b := range der {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		// Write to file
		if err := pem.Encode(file, block); err != nil {
			log.Fatalf("Failed to write certificate: %v", err)
		}

	}

	ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	if err != nil {
		log.Fatalf("Failed to marshal ECDSA private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaPrivateKeyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		log.Fatalf("Failed to write key: %v", err)
	}

	crtFileData, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	keyFileData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	domainAcme.CertFile = string(crtFileData)
	domainAcme.KeyFile = string(keyFileData)

	// normally letsencrypt certificate expires in 90 days
	// but we will set it to 88 days to renew it before it expires
	domainAcme.ExpireDate = time.Now().AddDate(0, 0, 88)
	domainAcme.IssueDate = time.Now()

	// save domainAcme struct to domainAcme.json file
	jsonData, err = json.Marshal(domainAcme)
	if err != nil {
		log.Fatalf("Failed to marshal domain acme data: %v", err)
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Fatalf("Failed to write domain acme data: %v", err)
	}

	fmt.Println("Certificate and key saved to " + location)
}

func (m *Manager) AddCustomCert(domain, certFileData, keyfileData string) {
	os.MkdirAll(m.Location+"/"+domain, 0755)

	location := fmt.Sprintf("%s/%s", m.Location, domain)
	acmelocation := fmt.Sprintf("%s/%s/%s-acme.json", m.Location, domain, domain)

	if _, err := os.Stat(location); os.IsNotExist(err) {
		if _, err := os.Create(location); err != nil {
			log.Fatalf("Failed to create domain acme file: %v", err)
		}
	}

	if _, err := os.Stat(acmelocation); os.IsNotExist(err) {
		if _, err := os.Create(acmelocation); err != nil {
			log.Fatalf("Failed to create domain acme file: %v", err)
		}
	}

	domainAcme := DomainAcme{
		Sans:       []string{},
		IssuerData: IssuerData{},
		CertFile:   certFileData,
		KeyFile:    keyfileData,
		CustomCert: true,
	}

	jsonData, err := json.Marshal(domainAcme)
	if err != nil {
		log.Fatalf("Failed to marshal domain acme data: %v", err)
	}

	if err := os.WriteFile(acmelocation, jsonData, 0644); err != nil {
		log.Fatalf("Failed to write domain acme data: %v", err)
	}

	certFile := location + "/" + domain + "-cert.crt"
	keyFile := location + "/" + domain + "-key.pem"

	if _, err := os.Create(certFile); err != nil {
		log.Fatalf("Failed to create certificate file: %v", err)
	}

	if _, err := os.Create(keyFile); err != nil {
		log.Fatalf("Failed to create key file: %v", err)
	}

	if err := os.WriteFile(certFile, []byte(certFileData), 0644); err != nil {
		log.Fatalf("Failed to write certificate file: %v", err)
	}

	if err := os.WriteFile(keyFile, []byte(keyfileData), 0644); err != nil {
		log.Fatalf("Failed to write key file: %v", err)
	}

	fmt.Println("Custom certificate and key saved to " + location)
}
