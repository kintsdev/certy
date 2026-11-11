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
	"io/fs"
	"net"
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

	// accountKeyFile holds the ACME account key shared by all domains, stored in Manager.Location.
	accountKeyFile = "account-key.pem"

	acmeChallengePath = "/.well-known/acme-challenge/"
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
	pemData, err := encodeRSAKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}
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
	key, err := decodeRSAKey([]byte(pemStr))
	if err != nil {
		return err
	}
	k.PrivateKey = key
	return nil
}

func encodeRSAKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func decodeRSAKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block for account key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse account key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("account key is not RSA")
	}
	return rsaKey, nil
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

// RenewRequired reports whether the certificate is missing or expires within renewalThreshold days.
func (d *DomainAcme) RenewRequired() bool {
	if d.ExpireDate.IsZero() {
		return true
	}
	return time.Now().After(d.ExpireDate.AddDate(0, 0, -renewalThreshold))
}

// IsNull reports whether no ACME data has been recorded.
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

// Manager manages certificates. The zero value is usable, but NewManager is preferred.
type Manager struct {
	Email    string
	Location string
	Staging  bool
	Logger   Logger

	mu         sync.Mutex // guards accountKey
	accountKey *rsa.PrivateKey
	issuing    sync.Map // domain -> struct{}, domains with an issuance in progress
	certCache  sync.Map // domain -> *tls.Certificate
}

// NewManager creates a new certificate manager
func NewManager(email, location string, staging bool) *Manager {
	return &Manager{
		Email:    email,
		Location: location,
		Staging:  staging,
	}
}

func (m *Manager) logf(format string, v ...interface{}) {
	if m.Logger != nil {
		m.Logger.Printf(format, v...)
	}
}

func (m *Manager) directoryURL() string {
	if m.Staging {
		return letsencryptStagingURL
	}
	return letsencryptProdURL
}

// domainFile returns the path of a domain's file, e.g. <Location>/<domain>/<domain>-acme.json.
func (m *Manager) domainFile(domain, suffix string) string {
	return filepath.Join(m.Location, domain, domain+suffix)
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

// GetChallengeToken gets the challenge token for a domain
func (m *Manager) GetChallengeToken(domain string) (string, error) {
	d, err := m.GetAcmeFileData(domain)
	if err != nil {
		return "", err
	}
	return d.IssuerData.ChallengeToken, nil
}

// GetAcmeFileData gets acme file data for a domain
func (m *Manager) GetAcmeFileData(domain string) (*DomainAcme, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(m.domainFile(domain, "-acme.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read acme file: %w", err)
	}
	var d DomainAcme
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("failed to unmarshal domain acme data: %w", err)
	}
	return &d, nil
}

// GetCert returns the TLS certificate for the requested server name. It is meant
// to be used as tls.Config.GetCertificate. Certificates are cached in memory and
// reloaded from disk on cache miss or when the cached certificate has expired
// (e.g. renewed by another process).
func (m *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if err := validateDomain(domain); err != nil {
		return nil, err
	}

	if v, ok := m.certCache.Load(domain); ok {
		cert := v.(*tls.Certificate)
		if cert.Leaf == nil || time.Now().Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
	}

	if _, err := os.Stat(m.domainFile(domain, "-acme.json")); err != nil {
		return nil, fmt.Errorf("domain acme data not found for %s", domain)
	}
	certPEM, err := os.ReadFile(m.domainFile(domain, "-cert.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(m.domainFile(domain, "-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
	}

	m.certCache.Store(domain, &cert)
	return &cert, nil
}

// InvalidateCertCache removes a domain's certificate from the in-memory cache,
// forcing the next GetCert call to reload from disk.
func (m *Manager) InvalidateCertCache(domain string) {
	m.certCache.Delete(domain)
}

// HTTPHandler serves HTTP-01 ACME challenges and passes every other request to
// fallback. It must be reachable over plain HTTP on port 80. A nil fallback
// responds with 404.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if fallback == nil {
		fallback = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, acmeChallengePath) {
			fallback.ServeHTTP(w, r)
			return
		}

		token := strings.TrimPrefix(r.URL.Path, acmeChallengePath)
		if token == "" {
			http.Error(w, "Empty challenge token", http.StatusBadRequest)
			return
		}

		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		acmeData, err := m.GetAcmeFileData(host)
		if err != nil {
			m.logf("Failed to get acme file data for %s: %v", host, err)
			http.Error(w, "Domain not found", http.StatusNotFound)
			return
		}
		if acmeData.AccountKey.PrivateKey == nil {
			http.Error(w, "Invalid account key", http.StatusInternalServerError)
			return
		}

		client := &acme.Client{DirectoryURL: m.directoryURL(), Key: acmeData.AccountKey.PrivateKey}
		resp, err := client.HTTP01ChallengeResponse(token)
		if err != nil {
			m.logf("HTTP-01 challenge response failed for %s: %v", host, err)
			http.Error(w, "Challenge failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(resp))
	})
}

// IssueCert issues a Let's Encrypt certificate for the domain, or renews it if
// it expires within 30 days. It is a no-op when the current certificate is
// still valid, so it is safe to call periodically. HTTPHandler must be serving
// port 80 for the domain while this runs.
func (m *Manager) IssueCert(ctx context.Context, domain string) error {
	if err := validateDomain(domain); err != nil {
		return err
	}

	if _, busy := m.issuing.LoadOrStore(domain, struct{}{}); busy {
		return fmt.Errorf("issuing already in progress for domain: %s", domain)
	}
	defer m.issuing.Delete(domain)

	d, err := m.GetAcmeFileData(domain)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Unreadable or corrupt data must not block issuance forever; start fresh.
			m.logf("Ignoring unreadable acme data for %s: %v", domain, err)
		}
		d = &DomainAcme{}
	}
	if !d.RenewRequired() {
		return nil
	}

	if err := os.MkdirAll(filepath.Join(m.Location, domain), dirPerm); err != nil {
		return fmt.Errorf("failed to create domain directory: %w", err)
	}

	accountKey, err := m.getAccountKey()
	if err != nil {
		return err
	}

	client := &acme.Client{DirectoryURL: m.directoryURL(), Key: accountKey}
	acct := &acme.Account{}
	if m.Email != "" {
		acct.Contact = []string{"mailto:" + m.Email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("account registration failed: %w", err)
	}

	// Persist the account key before validation: HTTPHandler reads it to answer the challenge.
	d.Sans = []string{domain}
	d.IssuerData = IssuerData{URL: string(client.KID), Ca: client.DirectoryURL}
	d.AccountKey = rsaPrivateKeyJSON{accountKey}
	if err := m.saveDomainAcme(domain, d); err != nil {
		return err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("order authorization failed: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := m.authorize(ctx, client, authzURL, domain, d); err != nil {
			return err
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order not ready: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ECDSA private key generation failed: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return fmt.Errorf("certificate request creation failed: %w", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}
	if len(der) == 0 {
		return errors.New("certificate issuance failed: empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	var certPEM []byte
	for _, c := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := m.domainFile(domain, "-cert.crt")
	keyFile := m.domainFile(domain, "-key.pem")
	if err := writeFileAtomic(keyFile, keyPEM, keyPerm); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}
	if err := writeFileAtomic(certFile, certPEM, certPerm); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	d.CertFile = certFile
	d.KeyFile = keyFile
	d.ExpireDate = leaf.NotAfter
	d.IssueDate = leaf.NotBefore
	d.CustomCert = false
	if err := m.saveDomainAcme(domain, d); err != nil {
		return err
	}

	m.InvalidateCertCache(domain)
	m.logf("Certificate and key saved to %s", filepath.Dir(certFile))
	return nil
}

// authorize completes the HTTP-01 challenge for one authorization, unless it is already valid.
func (m *Manager) authorize(ctx context.Context, client *acme.Client, authzURL, domain string, d *DomainAcme) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("failed to get authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}

	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no HTTP-01 challenge found")
	}

	d.IssuerData.ChallengeToken = chal.Token
	if err := m.saveDomainAcme(domain, d); err != nil {
		return err
	}

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("challenge acceptance failed: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("challenge validation failed: %w", err)
	}
	return nil
}

// getAccountKey loads the shared ACME account key from disk, creating it on
// first use. Reusing one account avoids Let's Encrypt's account creation rate limits.
func (m *Manager) getAccountKey() (*rsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.accountKey != nil {
		return m.accountKey, nil
	}

	path := filepath.Join(m.Location, accountKeyFile)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err := decodeRSAKey(data)
		if err != nil {
			return nil, fmt.Errorf("invalid account key file %s: %w", path, err)
		}
		m.accountKey = key
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to read account key: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("account key generation failed: %w", err)
	}
	pemData, err := encodeRSAKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.Location, dirPerm); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}
	if err := writeFileAtomic(path, pemData, keyPerm); err != nil {
		return nil, fmt.Errorf("failed to save account key: %w", err)
	}
	m.accountKey = key
	return key, nil
}

// saveDomainAcme writes the domain's acme data. It contains the account key, so it is not world-readable.
func (m *Manager) saveDomainAcme(domain string, d *DomainAcme) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain acme data: %w", err)
	}
	if err := writeFileAtomic(m.domainFile(domain, "-acme.json"), data, keyPerm); err != nil {
		return fmt.Errorf("failed to write domain acme data: %w", err)
	}
	return nil
}

// AddCustomCert adds a custom certificate for a domain
func (m *Manager) AddCustomCert(domain, certPEM, keyPEM string) error {
	if err := validateDomain(domain); err != nil {
		return err
	}

	// Validates that the key matches the certificate and parses the leaf for its dates.
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("invalid certificate or key: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Join(m.Location, domain), dirPerm); err != nil {
		return fmt.Errorf("failed to create domain directory: %w", err)
	}

	certFile := m.domainFile(domain, "-cert.crt")
	keyFile := m.domainFile(domain, "-key.pem")
	if err := writeFileAtomic(keyFile, []byte(keyPEM), keyPerm); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	if err := writeFileAtomic(certFile, []byte(certPEM), certPerm); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	d := &DomainAcme{
		Sans:       []string{domain},
		CertFile:   certFile,
		KeyFile:    keyFile,
		CustomCert: true,
		ExpireDate: leaf.NotAfter,
		IssueDate:  leaf.NotBefore,
	}
	if err := m.saveDomainAcme(domain, d); err != nil {
		return err
	}

	m.InvalidateCertCache(domain)
	return nil
}

// writeFileAtomic writes data to a temp file and renames it over name, so
// readers never observe a partially written file.
func writeFileAtomic(name string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
