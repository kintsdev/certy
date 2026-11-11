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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestManager_AddCustomCert_Permissions(t *testing.T) {
	dir := t.TempDir()
	m := NewManager("test@example.com", dir, false)
	certPEM, keyPEM := generateSelfSignedCert(t, "example.com")
	if err := m.AddCustomCert("example.com", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(m.domainFile("example.com", "-acme.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("acme file permission = %o, want 0600", info.Mode().Perm())
	}
}

func TestManager_AddCustomCert_KeyMismatch(t *testing.T) {
	m := NewManager("test@example.com", t.TempDir(), false)
	certPEM, _ := generateSelfSignedCert(t, "example.com")
	_, otherKey := generateSelfSignedCert(t, "example.com")
	if err := m.AddCustomCert("example.com", certPEM, otherKey); err == nil {
		t.Error("expected error for mismatched key")
	}
	if _, err := os.Stat(m.domainFile("example.com", "-cert.crt")); !os.IsNotExist(err) {
		t.Error("certificate must not be written when validation fails")
	}
}

func TestManager_GetCert(t *testing.T) {
	m := NewManager("test@example.com", t.TempDir(), false)
	certPEM, keyPEM := generateSelfSignedCert(t, "example.com")
	if err := m.AddCustomCert("example.com", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	first, err := m.GetCert(hello)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.GetCert(hello)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("expected cached certificate on second call")
	}

	// An expired cached certificate is reloaded from disk.
	expired := *first
	expired.Leaf = &x509.Certificate{NotAfter: time.Now().Add(-time.Hour)}
	m.certCache.Store("example.com", &expired)
	reloaded, err := m.GetCert(hello)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded == &expired {
		t.Error("expected expired cached certificate to be reloaded")
	}

	if _, err := m.GetCert(&tls.ClientHelloInfo{ServerName: "unknown.com"}); err == nil {
		t.Error("expected error for unknown domain")
	}
}

func TestManager_IssueCert_ValidCertIsNoop(t *testing.T) {
	m := NewManager("test@example.com", t.TempDir(), false)
	certPEM, keyPEM := generateSelfSignedCert(t, "example.com") // valid for a year
	if err := m.AddCustomCert("example.com", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	// Would hit the network (and fail) if it attempted issuance.
	if err := m.IssueCert(context.Background(), "example.com"); err != nil {
		t.Errorf("IssueCert on valid cert = %v, want nil", err)
	}
}

func TestManager_IssueCert_InProgress(t *testing.T) {
	m := NewManager("test@example.com", t.TempDir(), false)
	m.issuing.Store("example.com", struct{}{})
	err := m.IssueCert(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Errorf("IssueCert = %v, want already in progress error", err)
	}
}

func TestManager_GetAccountKey_Reused(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := encodeRSAKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, accountKeyFile), pemData, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := NewManager("test@example.com", dir, false).getAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Error("expected existing account key to be loaded from disk")
	}
}

func TestManager_HTTPHandler(t *testing.T) {
	dir := t.TempDir()
	m := NewManager("test@example.com", dir, true)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "example.com"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.saveDomainAcme("example.com", &DomainAcme{AccountKey: rsaPrivateKeyJSON{key}}); err != nil {
		t.Fatal(err)
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := m.HTTPHandler(fallback)

	serve := func(host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := serve("example.com", "/"); rec.Code != http.StatusTeapot {
		t.Errorf("non-challenge request: got %d, want fallback", rec.Code)
	}
	for _, host := range []string{"example.com", "example.com:80"} {
		rec := serve(host, "/.well-known/acme-challenge/token123")
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "token123.") {
			t.Errorf("host %q: got %d %q, want key authorization", host, rec.Code, rec.Body.String())
		}
	}
	if rec := serve("unknown.com", "/.well-known/acme-challenge/token123"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown domain: got %d, want 404", rec.Code)
	}
	rec := httptest.NewRecorder()
	m.HTTPHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("nil fallback: got %d, want 404", rec.Code)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	name := filepath.Join(t.TempDir(), "file")
	for _, content := range []string{"first", "second"} {
		if err := writeFileAtomic(name, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Errorf("content = %q, want %q", got, content)
		}
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("permission = %o, want 0644", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(name))
	if len(entries) != 1 {
		t.Errorf("expected no leftover temp files, got %d entries", len(entries))
	}
}
