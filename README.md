<p align="center">
  <img src="logo.png" alt="Certy" width="200" height="200">
</p>


# Certy - Let's Encrypt Certificate Manager

Certy is a Go library for managing Let's Encrypt SSL/TLS certificates with automatic renewal and custom certificate support.

## Features

- **Automatic Let's Encrypt Certificate Management**: Issue and renew SSL certificates automatically
- **HTTP-01 Challenge Support**: Built-in ACME challenge handler for domain verification
- **Custom Certificate Support**: Add your own certificates alongside Let's Encrypt ones
- **Thread-Safe Operations**: Concurrent certificate issuance with proper locking
- **Automatic Renewal**: Certificates are renewed 30 days before expiry
- **Staging Environment Support**: Test with Let's Encrypt staging servers first

## Installation

```bash
go get github.com/kintsdev/certy
```

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "github.com/kintsdev/certy"
)

func main() {
    // Create a new certificate manager
    manager := certy.NewManager(
        "your-email@example.com", // Your email for Let's Encrypt
        "./certs",                // Directory to store certificates
        true,                     // Use staging environment first
    )

    // Issue a certificate for a domain
    err := manager.IssueCert("example.com")
    if err != nil {
        log.Fatalf("Failed to issue certificate: %v", err)
    }
}
```

### HTTP Server with Automatic Certificates

```go
package main

import (
    "crypto/tls"
    "fmt"
    "log"
    "net/http"
    "github.com/kintsdev/certy"
)

func main() {
    manager := certy.NewManager("your-email@example.com", "./certs", false)
    
    // Create server with automatic certificate management
    server := &http.Server{
        Addr: ":8443",
        TLSConfig: &tls.Config{
            GetCertificate: manager.GetCert, // Automatically selects certificates
        },
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprintf(w, "Hello from %s!", r.Host)
        }),
    }

    // Wrap with ACME challenge handler for Let's Encrypt verification
    handler := manager.HTTPHandler(server.Handler)
    server.Handler = handler

    log.Fatal(server.ListenAndServeTLS("", ""))
}
```

### Adding Custom Certificates

```go
// Add a custom certificate
err := manager.AddCustomCert(
    "custom.example.com",
    certPEMData,
    keyPEMData,
)
if err != nil {
    log.Printf("Failed to add custom certificate: %v", err)
}
```

## API Reference

### Manager

The main struct for managing certificates.

```go
type Manager struct {
    Email    string // Email for Let's Encrypt account
    Location string // Directory to store certificates
    Staging  bool   // Use staging environment
}
```

#### Methods

- `NewManager(email, location string, staging bool) *Manager` - Create a new manager
- `IssueCert(domain string) error` - Issue a Let's Encrypt certificate
- `AddCustomCert(domain, certData, keyData string) error` - Add a custom certificate
- `GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error)` - Get TLS certificate for domain
- `HTTPHandler(fallback http.Handler) http.Handler` - ACME challenge handler
- `GetAcmeFileData(domain string) (*DomainAcme, error)` - Get ACME data for domain
- `GetChallengeToken(domain string) (string, error)` - Get challenge token for domain

### DomainAcme

Represents certificate data for a domain.

```go
type DomainAcme struct {
    Sans       []string        // Subject Alternative Names
    IssuerData IssuerData      // Let's Encrypt issuer information
    AccountKey *rsa.PrivateKey // Account private key
    CertFile   string          // Certificate file path
    KeyFile    string          // Private key file path
    ExpireDate time.Time       // Certificate expiry date
    IssueDate  time.Time       // Certificate issue date
    CustomCert bool            // Whether this is a custom certificate
}
```

#### Methods

- `RenewRequired() bool` - Check if renewal is needed (30 days before expiry)
- `Expired() bool` - Check if certificate is expired
- `IsNull() bool` - Check if ACME data is empty

## File Structure

Certy creates the following directory structure:

```
certs/
├── example.com/
│   ├── example.com-acme.json    # ACME data and metadata
│   ├── example.com-cert.crt     # Certificate chain
│   └── example.com-key.pem      # Private key
└── another-domain.com/
    ├── another-domain.com-acme.json
    ├── another-domain.com-cert.crt
    └── another-domain.com-key.pem
```

## Configuration

### Environment Variables

- `CERTY_EMAIL`: Your email for Let's Encrypt (optional, can be set in code)
- `CERTY_LOCATION`: Certificate storage directory (optional, can be set in code)
- `CERTY_STAGING`: Use staging environment (optional, defaults to false)

### Let's Encrypt Rate Limits

- **Staging**: 300 new orders per 3 hours, 300 new registrations per 1 hour
- **Production**: 300 new orders per 3 hours, 300 new registrations per 3 hours

Always test with staging first!

## Security Considerations

- Private keys are stored with 0644 permissions (readable by owner only)
- Directories are created with 0755 permissions
- Account keys are RSA 4096-bit
- Certificate keys are ECDSA P-256
- Certificates expire after 88 days (renewed 30 days before expiry)

## Error Handling

All methods return proper errors that should be checked:

```go
err := manager.IssueCert("example.com")
if err != nil {
    switch {
    case strings.Contains(err.Error(), "already in progress"):
        log.Println("Certificate issuance already in progress")
    case strings.Contains(err.Error(), "challenge failed"):
        log.Println("Domain verification failed")
    default:
        log.Printf("Unexpected error: %v", err)
    }
}
```

## Testing

Run the test suite:

```bash
go test ./...
```

## Examples

See the `example/` directory for complete working examples.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Recent Fixes

This version includes several important fixes:

- **Proper error handling**: All errors are now properly returned and handled
- **Thread safety**: Added mutex protection for concurrent operations
- **File path security**: Using `filepath.Join` for secure path construction
- **Resource cleanup**: Proper file handle management and cleanup
- **Logic fixes**: Corrected certificate renewal logic and validation
- **Code organization**: Split large functions into smaller, testable functions
- **Input validation**: Added proper validation for all inputs
- **Documentation**: Comprehensive comments and examples

## Support

For issues and questions, please open an issue on GitHub.
