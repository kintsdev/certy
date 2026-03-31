package certy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDomainAcme_RenewRequired(t *testing.T) {
	tests := []struct {
		name     string
		expire   time.Time
		expected bool
	}{
		{
			name:     "expired certificate",
			expire:   time.Now().AddDate(0, 0, -1),
			expected: true,
		},
		{
			name:     "expiring soon",
			expire:   time.Now().AddDate(0, 0, 25),
			expected: true,
		},
		{
			name:     "valid certificate",
			expire:   time.Now().AddDate(0, 0, 60),
			expected: false,
		},
		{
			name:     "zero time",
			expire:   time.Time{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DomainAcme{ExpireDate: tt.expire}
			result := d.RenewRequired()
			if result != tt.expected {
				t.Errorf("RenewRequired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDomainAcme_Expired(t *testing.T) {
	tests := []struct {
		name     string
		expire   time.Time
		expected bool
	}{
		{
			name:     "expired certificate",
			expire:   time.Now().AddDate(0, 0, -1),
			expected: true,
		},
		{
			name:     "valid certificate",
			expire:   time.Now().AddDate(0, 0, 60),
			expected: false,
		},
		{
			name:     "zero time",
			expire:   time.Time{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DomainAcme{ExpireDate: tt.expire}
			result := d.Expired()
			if result != tt.expected {
				t.Errorf("Expired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDomainAcme_IsNull(t *testing.T) {
	tests := []struct {
		name     string
		acme     DomainAcme
		expected bool
	}{
		{
			name:     "null acme",
			acme:     DomainAcme{},
			expected: true,
		},
		{
			name: "non-null acme",
			acme: DomainAcme{
				IssuerData: IssuerData{
					URL: "https://example.com",
					Ca:  "CA",
				},
				AccountKey: rsaPrivateKeyJSON{&rsa.PrivateKey{}},
				IssueDate:  time.Now(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.acme.IsNull()
			if result != tt.expected {
				t.Errorf("IsNull() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewManager(t *testing.T) {
	email := "test@example.com"
	location := "/tmp/certs"
	staging := true

	manager := NewManager(email, location, staging)

	if manager.Email != email {
		t.Errorf("Expected email %s, got %s", email, manager.Email)
	}

	if manager.Location != location {
		t.Errorf("Expected location %s, got %s", location, manager.Location)
	}

	if manager.Staging != staging {
		t.Errorf("Expected staging %v, got %v", staging, manager.Staging)
	}

	if manager.issuings == nil {
		t.Error("Expected issuings map to be initialized")
	}
}

func TestManager_AddCustomCert(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "certy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager("test@example.com", tempDir, false)
	domain := "example.com"
	certData, keyData := generateSelfSignedCert(t, domain)

	err = manager.AddCustomCert(domain, certData, keyData)
	if err != nil {
		t.Fatalf("AddCustomCert failed: %v", err)
	}

	// Check if files were created
	acmeFile := filepath.Join(tempDir, domain, domain+"-acme.json")
	certFile := filepath.Join(tempDir, domain, domain+"-cert.crt")
	keyFile := filepath.Join(tempDir, domain, domain+"-key.pem")

	if _, err := os.Stat(acmeFile); os.IsNotExist(err) {
		t.Error("ACME file was not created")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify key file has restrictive permissions
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("Expected key file permission 0600, got %o", keyInfo.Mode().Perm())
	}

	// Verify ACME data
	acmeData, err := manager.GetAcmeFileData(domain)
	if err != nil {
		t.Fatalf("Failed to get ACME data: %v", err)
	}

	if !acmeData.CustomCert {
		t.Error("Expected CustomCert to be true")
	}

	if len(acmeData.Sans) != 1 || acmeData.Sans[0] != domain {
		t.Error("Expected domain in Sans array")
	}

	// Verify CertFile/KeyFile store paths, not PEM content
	if acmeData.CertFile != certFile {
		t.Errorf("Expected CertFile to be path %s, got %s", certFile, acmeData.CertFile)
	}
	if acmeData.KeyFile != keyFile {
		t.Errorf("Expected KeyFile to be path %s, got %s", keyFile, acmeData.KeyFile)
	}

	// Verify expiry was parsed from the certificate (not hardcoded 1 year)
	if acmeData.ExpireDate.IsZero() {
		t.Error("Expected ExpireDate to be set from certificate")
	}
}

func TestManager_GetAcmeFileData_NotFound(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "certy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager("test@example.com", tempDir, false)

	_, err = manager.GetAcmeFileData("nonexistent.com")
	if err == nil {
		t.Error("Expected error for non-existent domain")
	}
}

func TestManager_GetChallengeToken_NotFound(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "certy_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager("test@example.com", tempDir, false)

	_, err = manager.GetChallengeToken("nonexistent.com")
	if err == nil {
		t.Error("Expected error for non-existent domain")
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"empty domain", "", true},
		{"path traversal with ..", "../etc/passwd", true},
		{"path traversal with /", "foo/bar", true},
		{"path traversal with backslash", "foo\\bar", true},
		{"null byte", "foo\x00bar", true},
		{"too long domain", string(make([]byte, 254)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestRsaPrivateKeyJSON_RoundTrip(t *testing.T) {
	// Generate a real RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	original := DomainAcme{
		Sans: []string{"example.com"},
		IssuerData: IssuerData{
			URL: "https://acme.example.com",
			Ca:  "https://ca.example.com",
		},
		AccountKey: rsaPrivateKeyJSON{key},
		CertFile:   "/path/to/cert",
		KeyFile:    "/path/to/key",
		IssueDate:  time.Now().Truncate(time.Second),
		ExpireDate: time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second),
	}

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal
	var restored DomainAcme
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify the key survived the round trip
	if restored.AccountKey.PrivateKey == nil {
		t.Fatal("AccountKey is nil after round trip")
	}
	if restored.AccountKey.D.Cmp(key.D) != 0 {
		t.Error("AccountKey.D mismatch after round trip")
	}
	if restored.AccountKey.N.Cmp(key.N) != 0 {
		t.Error("AccountKey.N mismatch after round trip")
	}
}

func TestRsaPrivateKeyJSON_NilRoundTrip(t *testing.T) {
	original := DomainAcme{
		Sans: []string{"example.com"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var restored DomainAcme
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if restored.AccountKey.PrivateKey != nil {
		t.Error("Expected nil AccountKey after round trip with nil key")
	}
}

func TestManager_DirectoryURL(t *testing.T) {
	staging := NewManager("test@example.com", "/tmp", true)
	if staging.directoryURL() != letsencryptStagingURL {
		t.Errorf("Expected staging URL, got %s", staging.directoryURL())
	}

	prod := NewManager("test@example.com", "/tmp", false)
	if prod.directoryURL() != letsencryptProdURL {
		t.Errorf("Expected prod URL, got %s", prod.directoryURL())
	}
}

func TestManager_AddCustomCert_InvalidDomain(t *testing.T) {
	manager := NewManager("test@example.com", "/tmp", false)

	err := manager.AddCustomCert("../evil", "cert", "key")
	if err == nil {
		t.Error("Expected error for path traversal domain")
	}
}

// generateSelfSignedCert generates a self-signed certificate and key PEM for testing.
func generateSelfSignedCert(t *testing.T, domain string) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return string(certBlock), string(keyBlock)
}
