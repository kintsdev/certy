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
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	letsencryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	letsencryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
)

type DomainAcme struct {
	Sans       []string   `json:"sans"`
	IssuerData IssuerData `json:"issuer_data"`
}

type IssuerData struct {
	URL            string `json:"url"`
	Ca             string `json:"ca"`
	ChallengeToken string `json:"challenge_token"`
}

type Manager struct {
	Email    string
	Location string
}

func NewManager(email, location string) *Manager {
	return &Manager{
		Email:    email,
		Location: location,
	}
}

func (m *Manager) IssueCert(domain string) {
	IssueLetsEncryptCert(m.Email, domain, m.Location)
}

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

func (m *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// m.Location + "/" + domain + "/" + domain + "-cert.crt"
	location := fmt.Sprintf("%s/%s/%s-cert.crt", m.Location, hello.ServerName, hello.ServerName)
	cert, err := tls.LoadX509KeyPair(location, location)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// HTTPHandler is a http handler for serving acme challenge
func (m *Manager) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	token := r.URL.Path[len("/.well-known/acme-challenge/"):]
	challengeToken := m.GetChallengeToken(domain)

	if token == challengeToken {
		w.Write([]byte(challengeToken))
	} else {
		http.NotFound(w, r)
	}
}

func IssueLetsEncryptCert(email, domain, location string) {
	// Generate a new account key
	accountKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Account key generation failed: %v", err)
	}

	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		Key:          accountKey,
	}

	if os.Getenv("ACME_ENV") == "staging" {
		client.DirectoryURL = letsencryptStagingURL
	}

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

	// Register a new ACME account
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	acct, err = client.Register(context.TODO(), acct, acme.AcceptTOS)
	if err != nil {
		log.Fatalf("Account registration failed: %v", err)
	}
	fmt.Printf("Account registered: %v\n", acct.URI)

	// if not exists create domainAcme.json file
	domainAcmeFile := location + "/" + domain + "-acme.json"
	if _, err := os.Stat(domainAcmeFile); os.IsNotExist(err) {
		if _, err := os.Create(domainAcmeFile); err != nil {
			log.Fatalf("Failed to create domain acme file: %v", err)
		}
	}

	// create domainAcme struct
	domainAcme := DomainAcme{
		Sans: []string{domain},
		IssuerData: IssuerData{
			URL: acct.URI,
			Ca:  client.DirectoryURL,
		},
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

	// save domainAcme struct to domainAcme.json file

	jsonData, err = json.Marshal(domainAcme)
	if err != nil {
		log.Fatalf("Failed to marshal domain acme data: %v", err)
	}

	if err := os.WriteFile(domainAcmeFile, jsonData, 0644); err != nil {
		log.Fatalf("Failed to write domain acme data: %v", err)
	}

	// HTTP-01 challenge response
	http01, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		log.Fatalf("HTTP-01 challenge response failed: %v", err)
	}

	http.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Path[len("/.well-known/acme-challenge/"):]
		if token == chal.Token {
			w.Write([]byte(http01))
		} else {
			http.NotFound(w, r)
		}
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
	})

	// Start the HTTP server
	go func() {
		if err := http.ListenAndServe(":80", nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Accept the challenge
	_, err = client.Accept(context.TODO(), chal)
	if err != nil {
		log.Fatalf("Challenge acceptance failed: %v", err)
	}

	// Wait for challenge to be valid
	for {
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
		time.Sleep(2 * time.Second)
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

	file, err := os.OpenFile(domain+"-cert.crt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

	fmt.Println("Certificate and key saved to cert.pem and key.pem")
}
