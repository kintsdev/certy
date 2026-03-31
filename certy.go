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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	letsencryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	letsencryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"

	// File permissions
	dirPerm  = 0755
	certPerm = 0644
	keyPerm  = 0600

	// Certificate renewal threshold (days before expiry)
	renewalThreshold = 30
)

// rsaPrivateKeyJSON is a JSON-serializable wrapper for rsa.PrivateKey.
// It stores the key as PEM-encoded PKCS#8 data to ensure proper round-trip serialization.
type rsaPrivateKeyJSON struct {
	*rsa.PrivateKey
}

func (k rsaPrivateKeyJSON) MarshalJSON() ([]byte, error) {
	if k.PrivateKey == nil {
		return []byte("null"), nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	pemData := pem.EncodeToMemory(block)
	return json.Marshal(string(pemData))
}

func (k *rsaPrivateKeyJSON) UnmarshalJSON(data []byte) error {
	var pemStr string
	if err := json.Unmarshal(data, &pemStr); err != nil {
		return err
	}
	if pemStr == "" {
		k.PrivateKey = nil
		return nil
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return errors.New("failed to decode PEM block for account key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse account key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return errors.New("account key is not RSA")
	}
	k.PrivateKey = rsaKey
	return nil
}

// DomainAcme is a struct for domain acme data
type DomainAcme struct {
	Sans       []string          `json:"sans"`
	IssuerData IssuerData        `json:"issuer_data"`
	AccountKey rsaPrivateKeyJSON `json:"account_key"`
	CertFile   string            `json:"cert_file"`
	KeyFile    string            `json:"key_file"`
	ExpireDate time.Time         `json:"expire_date"`
	IssueDate  time.Time         `json:"issue_date"`
	CustomCert bool              `json:"custom_cert"`
}

// RenewRequired checks if certificate needs renewal
func (d *DomainAcme) RenewRequired() bool {
	if d.ExpireDate.IsZero() {
		return true
	}
	// Renew 30 days before expiry
	return time.Now().After(d.ExpireDate.AddDate(0, 0, -renewalThreshold))
}

func (d *DomainAcme) IsNull() bool {
	return d.IssuerData.Ca == "" && d.IssuerData.URL == "" &&
		d.IssuerData.ChallengeToken == "" && d.AccountKey.PrivateKey == nil &&
		d.IssueDate.IsZero()
}

// Expired checks if certificate is expired
func (d *DomainAcme) Expired() bool {
	if d.ExpireDate.IsZero() {
		return true
	}
	return time.Now().After(d.ExpireDate)
}

// IssuerData is a struct for issuer data
type IssuerData struct {
	URL            string `json:"url"`
	Ca             string `json:"ca"`
	ChallengeToken string `json:"challenge_token"`
}

// Logger is an optional interface for logging. If nil, no logs are emitted.
type Logger interface {
	Printf(format string, v ...interface{})
}

// Manager is a struct for managing certificates
type Manager struct {
	Email     string
	Location  string
	Staging   bool
	Logger    Logger
	mu        sync.RWMutex
	issuings  map[string]bool
	certCache sync.Map // domain -> *tls.Certificate
}

// NewManager creates a new certificate manager
func NewManager(email, location string, staging bool) *Manager {
	return &Manager{
		Email:    email,
		Location: location,
		Staging:  staging,
		issuings: make(map[string]bool),
	}
}

// logf logs a message if a Logger is configured.
func (m *Manager) logf(format string, v ...interface{}) {
	if m.Logger != nil {
		m.Logger.Printf(format, v...)
	}
}

// directoryURL returns the ACME directory URL based on the Staging flag.
func (m *Manager) directoryURL() string {
	if m.Staging {
		return letsencryptStagingURL
	}
	return letsencryptProdURL
}

// validateDomain checks that the domain name is safe to use as a path component.
func validateDomain(domain string) error {
	if domain == "" {
		return errors.New("empty domain name")
	}
	if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\\x00") {
		return fmt.Errorf("invalid domain name: %q", domain)
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long: %d characters", len(domain))
	}
	return nil
}

// IssueCert issues a Let's Encrypt certificate for the domain
func (m *Manager) IssueCert(ctx context.Context, domain string) error {
	if err := validateDomain(domain); err != nil {
		return err
	}
	return m.issueLetsEncryptCert(ctx, m.Email, domain, m.Location)
}

// GetChallengeToken gets the challenge token for a domain
func (m *Manager) GetChallengeToken(domain string) (string, error) {
	if err := validateDomain(domain); err != nil {
		return "", err
	}
	location := filepath.Join(m.Location, domain, fmt.Sprintf("%s-acme.json", domain))

	file, err := os.ReadFile(location)
	if err != nil {
		return "", fmt.Errorf("failed to read domain acme file: %w", err)
	}

	var domainAcme DomainAcme
	if err := json.Unmarshal(file, &domainAcme); err != nil {
		return "", fmt.Errorf("failed to unmarshal domain acme data: %w", err)
	}

	return domainAcme.IssuerData.ChallengeToken, nil
}

// GetCert gets TLS certificate for a domain. Certificates are cached in memory
// and only reloaded from disk on cache miss.
func (m *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if err := validateDomain(domain); err != nil {
		return nil, err
	}

	// Check in-memory cache first
	if cached, ok := m.certCache.Load(domain); ok {
		return cached.(*tls.Certificate), nil
	}

	location := filepath.Join(m.Location, domain, fmt.Sprintf("%s-acme.json", domain))
	certFile := filepath.Join(m.Location, domain, fmt.Sprintf("%s-cert.crt", domain))
	keyFile := filepath.Join(m.Location, domain, fmt.Sprintf("%s-key.pem", domain))

	if _, err := os.Stat(location); os.IsNotExist(err) {
		return nil, fmt.Errorf("domain acme data not found for %s", domain)
	}

	certFileData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyFileData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certFileData, keyFileData)
	if err != nil {
		return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
	}

	// Store in cache
	m.certCache.Store(domain, &cert)

	return &cert, nil
}

// InvalidateCertCache removes a domain's certificate from the in-memory cache,
// forcing the next GetCert call to reload from disk.
func (m *Manager) InvalidateCertCache(domain string) {
	m.certCache.Delete(domain)
}

// GetAcmeFileData gets acme file data for a domain
func (m *Manager) GetAcmeFileData(domain string) (*DomainAcme, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	location := filepath.Join(m.Location, domain, fmt.Sprintf("%s-acme.json", domain))

	file, err := os.ReadFile(location)
	if err != nil {
		return nil, fmt.Errorf("failed to read acme file: %w", err)
	}

	var domainAcme DomainAcme
	if err := json.Unmarshal(file, &domainAcme); err != nil {
		return nil, fmt.Errorf("failed to unmarshal domain acme data: %w", err)
	}

	return &domainAcme, nil
}

// HTTPHandler is a http handler for serving acme challenge
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request path has acme challenge
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			fallback.ServeHTTP(w, r)
			return
		}

		token := r.URL.Path[len("/.well-known/acme-challenge/"):]
		if token == "" {
			http.Error(w, "Empty challenge token", http.StatusBadRequest)
			return
		}

		acmeData, err := m.GetAcmeFileData(r.Host)
		if err != nil {
			m.logf("Failed to get acme file data for %s: %v", r.Host, err)
			http.Error(w, "Domain not found", http.StatusNotFound)
			return
		}

		if acmeData.AccountKey.PrivateKey == nil {
			http.Error(w, "Invalid account key", http.StatusInternalServerError)
			return
		}

		client := &acme.Client{
			DirectoryURL: m.directoryURL(),
			Key:          acmeData.AccountKey.PrivateKey,
		}

		// HTTP-01 challenge response
		http01, err := client.HTTP01ChallengeResponse(token)
		if err != nil {
			m.logf("HTTP-01 challenge response failed for %s: %v", r.Host, err)
			http.Error(w, "Challenge failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(http01))
	})
}

// isIssuing checks if certificate issuance is already in progress
func (m *Manager) isIssuing(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.issuings[domain]
}

// setIssuing sets the issuing status for a domain
func (m *Manager) setIssuing(domain string, status bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issuings[domain] = status
}

// issueLetsEncryptCert issues a Let's Encrypt certificate
func (m *Manager) issueLetsEncryptCert(ctx context.Context, email, domain, location string) error {
	if m == nil {
		return errors.New("manager is nil")
	}

	// Check if already issuing
	if m.isIssuing(domain) {
		return fmt.Errorf("issuing already in progress for domain: %s", domain)
	}

	m.setIssuing(domain, true)
	defer m.setIssuing(domain, false)

	// Create base location directory
	if err := os.MkdirAll(location, dirPerm); err != nil {
		return fmt.Errorf("failed to create base directory: %w", err)
	}

	// Create domain directory
	domainLocation := filepath.Join(location, domain)
	if err := os.MkdirAll(domainLocation, dirPerm); err != nil {
		return fmt.Errorf("failed to create domain directory: %w", err)
	}

	// Check existing certificate
	domainAcmeFile := filepath.Join(domainLocation, fmt.Sprintf("%s-acme.json", domain))
	var domainAcme DomainAcme

	if _, err := os.Stat(domainAcmeFile); err == nil {
		// File exists, read it
		acmefile, err := os.ReadFile(domainAcmeFile)
		if err != nil {
			return fmt.Errorf("failed to read domain acme file: %w", err)
		}

		if len(acmefile) > 0 {
			if err := json.Unmarshal(acmefile, &domainAcme); err != nil {
				return fmt.Errorf("failed to unmarshal domain acme data: %w", err)
			}
		}
	}

	// Check if renewal is needed
	if !domainAcme.RenewRequired() && !domainAcme.Expired() {
		return nil // Certificate is still valid
	}

	// Generate a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("account key generation failed: %w", err)
	}

	client := &acme.Client{
		DirectoryURL: m.directoryURL(),
		Key:          accountKey,
	}

	// Register a new ACME account
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	acct, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("account registration failed: %w", err)
	}

	if domainAcme.IsNull() {
		domainAcme = DomainAcme{
			Sans: []string{domain},
			IssuerData: IssuerData{
				URL: acct.URI,
				Ca:  client.DirectoryURL,
			},
			AccountKey: rsaPrivateKeyJSON{accountKey},
		}
	} else {
		domainAcme.AccountKey = rsaPrivateKeyJSON{accountKey}
	}

	// Save domainAcme struct
	if err := m.saveDomainAcme(domainAcmeFile, domainAcme); err != nil {
		return fmt.Errorf("failed to save domain acme data: %w", err)
	}

	// Create a new order for the domain
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("order authorization failed: %w", err)
	}

	// Find HTTP-01 challenge
	chal, err := m.findHTTP01Challenge(ctx, client, order)
	if err != nil {
		return fmt.Errorf("failed to find HTTP-01 challenge: %w", err)
	}

	// Update challenge token
	domainAcme.IssuerData.ChallengeToken = chal.Token
	if err := m.saveDomainAcme(domainAcmeFile, domainAcme); err != nil {
		return fmt.Errorf("failed to save challenge token: %w", err)
	}

	// Accept the challenge
	_, err = client.Accept(ctx, chal)
	if err != nil {
		return fmt.Errorf("challenge acceptance failed: %w", err)
	}

	// Wait for authorization to be valid
	_, err = client.WaitAuthorization(ctx, chal.URI)
	if err != nil {
		return fmt.Errorf("challenge validation failed: %w", err)
	}

	// Generate ECDSA key pair
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ECDSA private key generation failed: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}, ecdsaPrivateKey)
	if err != nil {
		return fmt.Errorf("certificate request creation failed: %w", err)
	}

	// Finalize the order and get the certificate
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}

	// Save certificate and key files
	certFile := filepath.Join(domainLocation, fmt.Sprintf("%s-cert.crt", domain))
	keyFile := filepath.Join(domainLocation, fmt.Sprintf("%s-key.pem", domain))

	if err := m.saveCertificateChain(certFile, der); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	if err := m.savePrivateKey(keyFile, ecdsaPrivateKey); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Parse real expiry from the leaf certificate
	leafCert, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	// Update domainAcme with new certificate info
	domainAcme.CertFile = certFile
	domainAcme.KeyFile = keyFile
	domainAcme.ExpireDate = leafCert.NotAfter
	domainAcme.IssueDate = leafCert.NotBefore

	// Save final domainAcme struct
	if err := m.saveDomainAcme(domainAcmeFile, domainAcme); err != nil {
		return fmt.Errorf("failed to save final domain acme data: %w", err)
	}

	// Invalidate cached cert so the new one is loaded on next TLS handshake
	m.InvalidateCertCache(domain)

	m.logf("Certificate and key saved to %s", domainLocation)
	return nil
}

// findHTTP01Challenge finds HTTP-01 challenge in the order
func (m *Manager) findHTTP01Challenge(ctx context.Context, client *acme.Client, order *acme.Order) (*acme.Challenge, error) {
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			continue
		}

		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				return c, nil
			}
		}
	}
	return nil, errors.New("no HTTP-01 challenge found")
}

// saveDomainAcme saves domain acme data to file
func (m *Manager) saveDomainAcme(filename string, data DomainAcme) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain acme data: %w", err)
	}

	if err := os.WriteFile(filename, jsonData, certPerm); err != nil {
		return fmt.Errorf("failed to write domain acme data: %w", err)
	}

	return nil
}

// saveCertificateChain saves certificate chain to file
func (m *Manager) saveCertificateChain(filename string, der [][]byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, certPerm)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer file.Close()

	for _, cert := range der {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
		if err := pem.Encode(file, block); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
	}

	return nil
}

// savePrivateKey saves private key to file
func (m *Manager) savePrivateKey(filename string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(filename, keyPEM, keyPerm); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// AddCustomCert adds a custom certificate for a domain
func (m *Manager) AddCustomCert(domain, certPEM, keyPEM string) error {
	if err := validateDomain(domain); err != nil {
		return err
	}

	domainLocation := filepath.Join(m.Location, domain)

	// Create domain directory
	if err := os.MkdirAll(domainLocation, dirPerm); err != nil {
		return fmt.Errorf("failed to create domain directory: %w", err)
	}

	// Parse the certificate to extract the real expiry date
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to decode certificate PEM")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save certificate and key files
	certFile := filepath.Join(domainLocation, fmt.Sprintf("%s-cert.crt", domain))
	keyFile := filepath.Join(domainLocation, fmt.Sprintf("%s-key.pem", domain))

	if err := os.WriteFile(certFile, []byte(certPEM), certPerm); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	if err := os.WriteFile(keyFile, []byte(keyPEM), keyPerm); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	// Create acme file location
	acmeLocation := filepath.Join(domainLocation, fmt.Sprintf("%s-acme.json", domain))

	// Create domainAcme struct — store file paths, not PEM content
	domainAcme := DomainAcme{
		Sans:       []string{domain},
		IssuerData: IssuerData{},
		CertFile:   certFile,
		KeyFile:    keyFile,
		CustomCert: true,
		ExpireDate: parsedCert.NotAfter,
		IssueDate:  parsedCert.NotBefore,
	}

	// Save acme data
	if err := m.saveDomainAcme(acmeLocation, domainAcme); err != nil {
		return fmt.Errorf("failed to save domain acme data: %w", err)
	}

	// Invalidate cached cert so the new one is loaded on next TLS handshake
	m.InvalidateCertCache(domain)

	return nil
}
