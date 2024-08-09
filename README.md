<p align="center">
  <img src="logo.png" alt="Certy" width="200" height="200">
</p>


# Certy

[![Go Report Card](https://goreportcard.com/badge/github.com/kintsdev/certy)](https://goreportcard.com/report/github.com/kintsdev/certy)

[![GoDoc](https://godoc.org/github.com/kintsdev/certy?status.svg)](https://godoc.org/github.com/kintsdev/certy)

![License](https://img.shields.io/badge/License-MIT-blue.svg)

Certy is a Go package that automates the process of obtaining SSL certificates from Let's Encrypt using the ACME protocol. It handles the entire process from generating the account key, registering an ACME account, handling the HTTP-01 challenge, and issuing the certificate.

## Installation

To install Certy, use `go get`:

```sh
go get github.com/kintsdev/certy
```

## Usage

Here is an example of how to use Certy to issue a Let's Encrypt certificate for a domain:

### Import the package

```go
import "github.com/kintsdev/certy"
```

```go
package main

import (
    "github.com/kintsdev/certy"
    "log"
    "os"
)

func main() {
    email := "your-email@example.com"
    domain := "yourdomain.com"
    location := "/path/to/save/certificates"

    if err := os.Setenv("ACME_ENV", "staging"); err != nil {
        log.Fatalf("Failed to set environment variable: %v", err)
    }

    certy.IssueLetsEncryptCert(email, domain, location)
}

```

### Environment Variables

- `ACME_ENV`: Set this environment variable to "staging" to use the Let's Encrypt staging server. This is useful for testing. If this environment variable is not set, the production server will be used.

## Files Generated

The IssueLetsEncryptCert function will generate the following files in the current directory:

- location/yourdomain.com/yourdomain.com-cert.pem: The certificate.
- location/yourdomain.com/yourdomain.com-key.pem: The private key.
- location/yourdomain.com/yourdomain.com-acme.json: The ACME registration information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs or enhancements.
