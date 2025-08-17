package certy

import (
	"crypto/rsa"
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
				AccountKey: &rsa.PrivateKey{},
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
	certData := "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
	keyData := "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----"

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
