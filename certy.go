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
		log.Println("Failed to read domain acme file: ", err)
	}

	var domainAcme DomainAcme
	if err := json.Unmarshal(file, &domainAcme); err != nil {
		log.Println("Failed to unmarshal domain acme data: ", err)
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
			log.Println("Failed to get acme file data: ", err)
		}

		client := &acme.Client{
			DirectoryURL: acme.LetsEncryptURL,
			Key:          acmeData.AccountKey,
		}

		// HTTP-01 challenge response
		http01, err := client.HTTP01ChallengeResponse(m.GetChallengeToken(r.Host))
		if err != nil {
			log.Println("HTTP-01 challenge response failed: ", err)
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
	if m == nil {
		log.Println("Manager is nil")
		return
	}

	// check location is exists or not if not create it
	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err := os.Mkdir(location, 0755); err != nil {
			log.Println("Failed to create directory: ", err)
		}
	}

	// create folder for domain
	location = location + "/" + domain
	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err := os.Mkdir(location, 0755); err != nil {
			log.Println("Failed to create domain directory: ", err)
		}
	}

	// if not exists create domainAcme.json file
	domainAcmeFile := location + "/" + domain + "-acme.json"
	if _, err := os.Stat(domainAcmeFile); os.IsNotExist(err) {
		if _, err := os.Create(domainAcmeFile); err != nil {
			log.Println("Failed to create domain acme file: ", err)
		}
	}

	// read domainAcme.json file
	acmefile, err := os.ReadFile(domainAcmeFile)
	if err != nil {
		log.Println("Failed to read domain acme file: ", err)
	}
	var domainAcme DomainAcme

	if len(acmefile) == 0 {
		domainAcme = DomainAcme{}
	} else {
		if err := json.Unmarshal(acmefile, &domainAcme); err != nil {
			log.Println("Failed to unmarshal domain acme data: ", err)
			return
		}
	}

	if !domainAcme.RenewRequired() {
		return
	}

	if !domainAcme.Expired() {
		return
	}

	if issuings[domain] {
		log.Println("Issuing already in progress: " + domain)
		return
	} else {
		issuings[domain] = true
	}

	// Generate a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Println("Account key generation failed: ", err)
	} else {
		log.Println("Account key generated")
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
	acct, err2 := client.Register(context.Background(), acct, acme.AcceptTOS)
	if err2 != nil {
		log.Println("Account registration failed: ", err2)
	}

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
		log.Println("Failed to marshal domain acme data: ", err)
		issuings[domain] = false
		return
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Println("Failed to write domain acme data: ", err)
		issuings[domain] = false
		return
	}

	// Create a new order for the domain
	order, err := client.AuthorizeOrder(context.TODO(), acme.DomainIDs(domain))
	if err != nil {
		log.Println("Order authorization failed: ", err)
		issuings[domain] = false
		return
	}

	// HTTP-01 challenge for domain verification
	var chal *acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(context.TODO(), authzURL)
		if err != nil {
			log.Println("Failed to get authorization: ", err)
			issuings[domain] = false
			return
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
		log.Println("No HTTP-01 challenge found")
		issuings[domain] = false
		return
	}

	domainAcme.IssuerData.ChallengeToken = chal.Token

	// save domainAcme struct to domainAcme.json file
	jsonData, err = json.Marshal(domainAcme)
	if err != nil {
		log.Println("Failed to marshal domain acme data: ", err)
		issuings[domain] = false
		return
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Println("Failed to write domain acme data: ", err)
		issuings[domain] = false
		return
	}

	// Accept the challenge
	_, err = client.Accept(context.TODO(), chal)
	if err != nil {
		log.Println("Challenge acceptance failed: ", err)
		issuings[domain] = false
		return
	}

	// Wait for challenge to be valid
	for {
		log.Println("Checking challenge status", chal.URI, chal.Status)
		authz, err := client.GetAuthorization(context.TODO(), chal.URI)
		if err != nil {
			log.Printf("Failed to get authorization: %v \n", err)
			issuings[domain] = false
			return
		}
		if authz.Status == acme.StatusValid {
			break
		}
		if authz.Status == acme.StatusInvalid {
			log.Printf("Challenge failed: %v \n", authz)
			issuings[domain] = false
			return
		}
		// Wait before checking again
		time.Sleep(10 * time.Second)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Println("ECDSA private key generation failed: ", err)
		issuings[domain] = false
		return
	}

	// Create a CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}, ecdsaPrivateKey)
	if err != nil {
		log.Println("Certificate request creation failed: ", err)
		issuings[domain] = false
		return
	}

	// Finalize the order and get the certificate
	der, _, err := client.CreateOrderCert(context.TODO(), order.FinalizeURL, csr, true)
	if err != nil {
		log.Println("Certificate issuance failed: ", err)
		issuings[domain] = false
		return
	}

	// der contains the certificate chain
	// Save the certificate chain to same file with different blocks

	certFile := location + "/" + domain + "-cert.crt"
	keyFile := location + "/" + domain + "-key.pem"

	if _, err := os.Create(certFile); err != nil {
		log.Println("Failed to create certificate file: ", err)
		issuings[domain] = false
		return
	}

	file, err := os.OpenFile(certFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open file: ", err)
	}

	for _, b := range der {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		// Write to file
		if err := pem.Encode(file, block); err != nil {
			log.Println("Failed to write certificate: ", err)
			issuings[domain] = false
			return
		}

	}

	ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	if err != nil {
		log.Println("Failed to marshal ECDSA private key: ", err)
		issuings[domain] = false
		return
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaPrivateKeyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		log.Println("Failed to write key: ", err)
		issuings[domain] = false
		return
	}

	crtFileData, err := os.ReadFile(certFile)
	if err != nil {
		log.Println("Failed to read certificate file: ", err)
		issuings[domain] = false
		return
	}

	keyFileData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Println("Failed to read key file: ", err)
		issuings[domain] = false
		return
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
		log.Println("Failed to marshal domain acme data: ", err)
		issuings[domain] = false
		return
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Println("Failed to write domain acme data: ", err)
		issuings[domain] = false
		return
	}

	fmt.Println("Certificate and key saved to " + location)

	issuings[domain] = false
}

func (m *Manager) AddCustomCert(domain, certFileData, keyfileData string) {
	os.MkdirAll(m.Location+"/"+domain, 0755)

	location := fmt.Sprintf("%s/%s", m.Location, domain)
	acmelocation := fmt.Sprintf("%s/%s/%s-acme.json", m.Location, domain, domain)

	if _, err := os.Stat(location); os.IsNotExist(err) {
		if _, err := os.Create(location); err != nil {
			log.Println("Failed to create domain acme file: ", err)
		}
	}

	if _, err := os.Stat(acmelocation); os.IsNotExist(err) {
		if _, err := os.Create(acmelocation); err != nil {
			log.Println("Failed to create domain acme file: ", err)
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
		log.Println("Failed to marshal domain acme data: ", err)
	}

	if err := os.WriteFile(acmelocation, jsonData, 0644); err != nil {
		log.Println("Failed to write domain acme data: ", err)
	}

	certFile := location + "/" + domain + "-cert.crt"
	keyFile := location + "/" + domain + "-key.pem"

	if _, err := os.Create(certFile); err != nil {
		log.Println("Failed to create certificate file: ", err)
	}

	if _, err := os.Create(keyFile); err != nil {
		log.Println("Failed to create key file: ", err)
	}

	if err := os.WriteFile(certFile, []byte(certFileData), 0644); err != nil {
		log.Println("Failed to write certificate file: ", err)
	}

	if err := os.WriteFile(keyFile, []byte(keyfileData), 0644); err != nil {
		log.Println("Failed to write key file: ", err)
	}

	fmt.Println("Custom certificate and key saved to " + location)
}
