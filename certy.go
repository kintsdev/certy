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
	"path/filepath"
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
	Sans       []string   `json:"sans"`
	IssuerData IssuerData `json:"issuer_data"`
	CertFile   string     `json:"cert_file"`
	KeyFile    string     `json:"key_file"`
	ExpireDate time.Time  `json:"expire_date"`
	IssueDate  time.Time  `json:"issue_date"`
	CustomCert bool       `json:"custom_cert"`
}

// Check is need renew certificate or not
func (d *DomainAcme) RenewRequired() bool {
	// check is need renew certificate or not
	return time.Now().After(d.ExpireDate.AddDate(0, 0, -2))
}

func (d *DomainAcme) IsNull() bool {
	// check is domain acme data is null or not
	return d.IssuerData.Ca == "" && d.IssuerData.URL == "" && d.IssuerData.ChallengeToken == "" && d.IssueDate.IsZero()
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

// filePath returns the full path for a domain file
func (m *Manager) filePath(domain, suffix string) string {
	return fmt.Sprintf("%s/%s/%s%s", m.Location, domain, domain, suffix)
}

// ensureDir creates directory if it doesn't exist
func (m *Manager) ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	return nil
}

// readJSON reads and unmarshals a JSON file
func (m *Manager) readJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON from %s: %w", path, err)
	}
	return nil
}

// writeJSON marshals and writes data to a JSON file
func (m *Manager) writeJSON(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	return nil
}

// IssueCert is a method for issuing letsencrypt certificate
func (m *Manager) IssueCert(domain string) error {
	return m.issueLetsEncryptCert(m.Email, domain, m.Location)
}

// GetChallengeToken is a method for getting challenge token
func (m *Manager) GetChallengeToken(domain string) (string, error) {
	var domainAcme DomainAcme
	if err := m.readJSON(m.filePath(domain, "-acme.json"), &domainAcme); err != nil {
		return "", fmt.Errorf("failed to get challenge token: %w", err)
	}
	return domainAcme.IssuerData.ChallengeToken, nil
}

// GetCert is a method for getting tls certificate
func (m *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	certPath := m.filePath(domain, "-cert.crt")
	keyPath := m.filePath(domain, "-key.pem")

	if _, err := os.Stat(m.filePath(domain, "-acme.json")); os.IsNotExist(err) {
		return nil, fmt.Errorf("domain acme data not found for %s", domain)
	}

	certFileData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyFileData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certFileData, keyFileData)
	if err != nil {
		return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
	}

	return &cert, nil
}

// GetAcmeFileData is a method for getting acme file data
func (m *Manager) GetAcmeFileData(domain string) (*DomainAcme, error) {
	var domainAcme DomainAcme
	if err := m.readJSON(m.filePath(domain, "-acme.json"), &domainAcme); err != nil {
		return nil, fmt.Errorf("failed to get acme file data: %w", err)
	}
	return &domainAcme, nil
}

// HTTPHandler is a http handler for serving acme challenge
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}

		token := r.URL.Path[len("/.well-known/acme-challenge/"):]
		host := r.Host

		accountKey, err := m.loadAccountKey(host)
		if err != nil {
			log.Printf("Failed to load account key for %s: %v", host, err)
			fallback.ServeHTTP(w, r)
			return
		}

		client := &acme.Client{
			DirectoryURL: acme.LetsEncryptURL,
			Key:          accountKey,
		}

		challengeToken, err := m.GetChallengeToken(host)
		if err != nil {
			log.Printf("Failed to get challenge token for %s: %v", host, err)
			fallback.ServeHTTP(w, r)
			return
		}

		http01, err := client.HTTP01ChallengeResponse(challengeToken)
		if err != nil {
			log.Printf("HTTP-01 challenge response failed for %s: %v", host, err)
			fallback.ServeHTTP(w, r)
			return
		}

		if token == challengeToken {
			w.Write([]byte(http01))
		} else {
			fallback.ServeHTTP(w, r)
		}
	})
}

var issuings = make(map[string]bool)

// saveAccountKey saves the account key to a file
func (m *Manager) saveAccountKey(domain string, key *rsa.PrivateKey) error {
	location := fmt.Sprintf("%s/%s/%s-account.key", m.Location, domain, domain)

	// Convert private key to PEM format
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Save to file with restricted permissions
	return os.WriteFile(location, keyPEM, 0600)
}

// loadAccountKey loads the account key from a file
func (m *Manager) loadAccountKey(domain string) (*rsa.PrivateKey, error) {
	location := fmt.Sprintf("%s/%s/%s-account.key", m.Location, domain, domain)

	// Read the key file
	keyPEM, err := os.ReadFile(location)
	if err != nil {
		return nil, err
	}

	// Decode PEM block
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse the private key
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// issueLetsEncryptCert is a function for issuing letsencrypt certificate
func (m *Manager) issueLetsEncryptCert(email, domain, location string) error {
	if m == nil {
		return errors.New("manager is nil")
	}

	// Ensure directories exist
	if err := m.ensureDir(location); err != nil {
		return fmt.Errorf("failed to create base directory: %w", err)
	}

	domainDir := filepath.Join(location, domain)
	if err := m.ensureDir(domainDir); err != nil {
		return fmt.Errorf("failed to create domain directory: %w", err)
	}

	// Initialize or load domain acme data
	var domainAcme DomainAcme
	acmeFile := m.filePath(domain, "-acme.json")

	if err := m.readJSON(acmeFile, &domainAcme); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read acme file: %w", err)
		}
		domainAcme = DomainAcme{}
	}

	if !domainAcme.RenewRequired() && !domainAcme.Expired() {
		return nil
	}

	if issuings[domain] {
		return fmt.Errorf("issuing already in progress for %s", domain)
	}
	issuings[domain] = true
	defer func() { issuings[domain] = false }()

	// Try to load existing account key first
	accountKey, err := m.loadAccountKey(domain)
	if err != nil {
		// If no existing key, generate a new one
		accountKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("account key generation failed: %w", err)
		}

		// Save the new account key immediately
		if err := m.saveAccountKey(domain, accountKey); err != nil {
			return fmt.Errorf("failed to save account key: %w", err)
		}
		log.Println("Account key generated and saved")
	} else {
		log.Println("Loaded existing account key")
	}

	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		Key:          accountKey,
	}

	if m.Staging {
		client.DirectoryURL = letsencryptStagingURL
	}

	// Register a new ACME account if needed
	var acct *acme.Account
	if domainAcme.IsNull() {
		acct = &acme.Account{Contact: []string{"mailto:" + email}}
		acct, err = client.Register(context.Background(), acct, acme.AcceptTOS)
		if err != nil {
			return fmt.Errorf("account registration failed: %w", err)
		}

		domainAcme = DomainAcme{
			Sans: []string{domain},
			IssuerData: IssuerData{
				URL: acct.URI,
				Ca:  client.DirectoryURL,
			},
		}

		// save domainAcme struct to domainAcme.json file
		if err := m.writeJSON(acmeFile, domainAcme); err != nil {
			return fmt.Errorf("failed to write domain acme data: %w", err)
		}
	} else {
		// Use existing account
		acct = &acme.Account{
			URI: domainAcme.IssuerData.URL,
		}
	}

	// Create a new order for the domain
	order, err := client.AuthorizeOrder(context.TODO(), acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("order authorization failed: %w", err)
	}

	// HTTP-01 challenge for domain verification
	var chal *acme.Challenge
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(context.TODO(), authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization: %w", err)
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
		return fmt.Errorf("no HTTP-01 challenge found")
	}

	domainAcme.IssuerData.ChallengeToken = chal.Token

	// save domainAcme struct to domainAcme.json file
	if err := m.writeJSON(acmeFile, domainAcme); err != nil {
		return fmt.Errorf("failed to write domain acme data: %w", err)
	}

	// Accept the challenge
	_, err = client.Accept(context.TODO(), chal)
	if err != nil {
		return fmt.Errorf("challenge acceptance failed: %w", err)
	}

	// Wait for challenge to be valid
	for {
		log.Println("Checking challenge status", chal.URI, chal.Status)
		authz, err := client.GetAuthorization(context.TODO(), chal.URI)
		if err != nil {
			return fmt.Errorf("failed to get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			break
		}
		if authz.Status == acme.StatusInvalid {
			// Challenge failed, but we can retry with the same account
			log.Printf("Challenge failed for %s, will retry with same account", domain)
			// Clear the challenge token
			domainAcme.IssuerData.ChallengeToken = ""
			if err := m.writeJSON(acmeFile, domainAcme); err != nil {
				return fmt.Errorf("failed to clear challenge token: %w", err)
			}
			// Return error to trigger retry
			return fmt.Errorf("challenge failed: %v", authz)
		}
		// Wait before checking again
		time.Sleep(10 * time.Second)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Println("ECDSA private key generation failed: ", err)
		return err
	}

	// Create a CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}, ecdsaPrivateKey)
	if err != nil {
		log.Println("Certificate request creation failed: ", err)
		return err
	}

	// Finalize the order and get the certificate
	der, _, err := client.CreateOrderCert(context.TODO(), order.FinalizeURL, csr, true)
	if err != nil {
		log.Println("Certificate issuance failed: ", err)
		return err
	}

	// der contains the certificate chain
	// Save the certificate chain to same file with different blocks

	certFile := m.filePath(domain, "-cert.crt")
	keyFile := m.filePath(domain, "-key.pem")

	if _, err := os.Create(certFile); err != nil {
		log.Println("Failed to create certificate file: ", err)
		return err
	}

	file, err := os.OpenFile(certFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Failed to open file: ", err)
		return err
	}

	for _, b := range der {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		// Write to file
		if err := pem.Encode(file, block); err != nil {
			log.Println("Failed to write certificate: ", err)
			return err
		}

	}

	ecdsaPrivateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaPrivateKey)
	if err != nil {
		log.Println("Failed to marshal ECDSA private key: ", err)
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaPrivateKeyBytes})
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		log.Println("Failed to write key: ", err)
		return err
	}

	crtFileData, err := os.ReadFile(certFile)
	if err != nil {
		log.Println("Failed to read certificate file: ", err)
		return err
	}

	keyFileData, err := os.ReadFile(keyFile)
	if err != nil {
		log.Println("Failed to read key file: ", err)
		return err
	}

	domainAcme.CertFile = string(crtFileData)
	domainAcme.KeyFile = string(keyFileData)

	// normally letsencrypt certificate expires in 90 days
	// but we will set it to 88 days to renew it before it expires
	domainAcme.ExpireDate = time.Now().AddDate(0, 0, 88)
	domainAcme.IssueDate = time.Now()

	// save domainAcme struct to domainAcme.json file
	if err := m.writeJSON(acmeFile, domainAcme); err != nil {
		log.Println("Failed to write domain acme data: ", err)
		return err
	}

	fmt.Println("Certificate and key saved to " + location)

	return nil
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
