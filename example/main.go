package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kintsdev/certy"
)

func main() {
	manager := certy.NewManager(
		"your-email@example.com", // Email for the Let's Encrypt account
		"./certs",                // Directory to store certificates
		true,                     // Use the staging environment first
	)
	domain := "example.com"

	// HTTP-01 challenges are validated over plain HTTP on port 80.
	go func() {
		log.Fatal(http.ListenAndServe(":80", manager.HTTPHandler(nil)))
	}()

	// Issue now, then check daily. IssueCert only contacts Let's Encrypt when the
	// certificate is missing or expires within 30 days.
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if err := manager.IssueCert(ctx, domain); err != nil {
				log.Printf("Failed to issue certificate for %s: %v", domain, err)
			}
			cancel()
			time.Sleep(24 * time.Hour)
		}
	}()

	server := &http.Server{
		Addr:      ":443",
		TLSConfig: &tls.Config{GetCertificate: manager.GetCert},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello from %s!", r.Host)
		}),
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
