package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/kintsdev/certy"
)

func main() {
	// Create a new certificate manager
	manager := certy.NewManager(
		"your-email@example.com", // Your email for Let's Encrypt
		"./certs",                // Directory to store certificates
		true,                     // Use staging environment first
	)

	// Example 1: Issue a Let's Encrypt certificate
	domain := "example.com"
	fmt.Printf("Issuing certificate for %s...\n", domain)

	err := manager.IssueCert(domain)
	if err != nil {
		log.Printf("Failed to issue certificate: %v", err)
	} else {
		fmt.Printf("Certificate issued successfully for %s\n", domain)
	}

	// Example 2: Add a custom certificate
	customDomain := "custom.example.com"
	certData := `-----BEGIN CERTIFICATE-----
MIIEpDCCA4ygAwIBAgIJANm5mJniHoDvMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4g
VmlldzEQMA4GA1UEChMHQW5vbnltb3MxEDAOBgNVBAsTBUFub255bW91czEUMBIG
A1UEAxMLZXhhbXBsZS5jb20wHhcNMTYwMjA5MTY0NzA3WhcNMTcwMjA4MTY0NzA3
WjCBizELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0Fub255bW91czEQMA4GA1UECxMFQW5v
bnltb3MxFDASBgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAuQPoM3OaoIW+jF5wfaEoocKSGrsJo3WkMhl5tVjBmHtHai8K
8w5XtEalWhCgv86AH+9Vc6q3BQya+zs78rHakwjE3gB0oXD3LVSfE+EBfhT1wlfB
3qSWi6OodQF6Zqj3t3tha6iXRLgrcG7uaMS4oY+acpIWt0Uuug/w4eHULIe3bk5p
oYA6Ooz6AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABJ8tMnC7QV/fGRWoSJaqRwP
uPDa5XJYMhuCg+XmHz+W9m3dXDa7VjfBYEdKE7lmt8LDxw4SkXk4loi6l3iPPe9O
6pAUEVzayFeM5zMmcX8EPLtM7AfRj5QrQkcF8qxbJ1K1tQUxsm7AhZPKe5g3uPQt
j5otAEccijYxrQ/hUo9l5h/2vH7uqzH+dzD+Z4jdGTzbjsoz+2om9G1xHfhu3meb
1dxlNJS7VgpWkzb5OEmlhN88jKOVMLsosFCTOwzYQ9VRx3Pz6jLZb5CQZQbw+ra6
fWrO2f7WzSDievo2XJTMUoEfRieHxb5l4V5JlgRap/0WxSitSYYarjXakqctp
-----END CERTIFICATE-----`

	keyData := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5A+gzc5qghb6M
XnB9oSiiwpIauwmjdaQyGXm1WMGYe0dqLwrzDle0RqVaEKC/zoAf71VzqrcFDJr7
Ozvy8dqTCMTeAHShcPctVJ8T4QF+FPXCV8HepJaLo6h1AXpmqPe3W1tqidEuCtwb
u5oxLihj5pylha3RS66D/Dh4dQsh7duTmmhgDo6jPoCAwEAAQKCAQEAj8rTnc7B
Vf3xkVqEiWqkcD7jw2uVyWDIbgoPl5h8/lvZt3Vw2u1Y3wWBHShO5ZrPCw8cOEpF
5OKaIupd4jz3vTuqQFBFc2shXjOczJnF/BDy7TOwH0Y+UK0JHBfKsWydStbUFMbJ
uwIWQynuYN7j0LY+aLQBHHIo2Ma0P4VKPZeYf9rx+7qsx/ncw/meI3Rk8247KM/t
qJvRtcR34bt5nndXcZTSUu1YKVpM2+ThJpYTfPIyTlTC7KLBQkzsM2EPVUcdz8+o
y2W+QkGUG8Pq2un1qztn+1s0g4nr6NlyUzFKBH0Ynh8W+ZeFeSZYEWqf9FsUorU
mGGq412pKnLaTQKBgQDhR8wwMzbmYbEkKHI6W2l2gxVE9MD+5QOnRZoMffAtpDls
mCdJQ5Xq8QtBQpX9P3Z0E+K3DHtRe3k2mtZLN1g84azc0n6WYqXw2c2h99KoZ5B0
xHqrNYBmjZCHvqj5Wf0m6vnx4TYiF2lbJ7CqzXJzImI2R1BzXnXvtZzBt2MeCQKB
gQDgW7ygvXq5r5L8p3Fj8+wEjL2RjLh6XHwrL2UrnWtGf+GnkxKOKJOw6BjEsFLI
o1B4OsDXlfAZ1a5oHVjp2LQQFlbCYJipMk6YJ9DAtxeVOobYMPOCxJ0B1wa1wYHn
5lEHEUqXZ2Ix3R3W0C2VpJMLJD2GDWmCgeQ1RXlxtiQq8QKBgDLT8wxYQiokR8cn
HPM0fV4jFvdnY7x9QEGjYTePjqpkfT4bSPuCj+X0QJ7yFpGrx6lSOaMpi+r0j8Vy
2fH/lDz6XnbC3aFzPMxfpmxVOdE6l66BstpfeqBxMFRf7M0XmJw2tgp/YF1O1o5B
C6mBRBM6Zf5AgMBAAE=
-----END PRIVATE KEY-----`

	fmt.Printf("Adding custom certificate for %s...\n", customDomain)
	err = manager.AddCustomCert(customDomain, certData, keyData)
	if err != nil {
		log.Printf("Failed to add custom certificate: %v", err)
	} else {
		fmt.Printf("Custom certificate added successfully for %s\n", customDomain)
	}

	// Example 3: Create a TLS server with certificate management
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			GetCertificate: manager.GetCert,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello from %s!", r.Host)
		}),
	}

	// Wrap with ACME challenge handler
	handler := manager.HTTPHandler(server.Handler)
	server.Handler = handler

	fmt.Println("Starting HTTPS server on :8443...")
	fmt.Println("Make sure your domain points to this server for Let's Encrypt verification")

	// Start server (this will block)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
