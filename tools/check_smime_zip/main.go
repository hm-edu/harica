package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hm-edu/harica/client"
	"go.mozilla.org/pkcs7"
)

func main() {
	zipPath := flag.String("zip", "smime.zip", "Path to HARICA bulk ZIP (e.g., smime.zip)")
	out := flag.String("out", "", "Optional path to write extracted PEM certificate")
	flag.Parse()

	b, err := os.ReadFile(*zipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read zip %q: %v\n", *zipPath, err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "ZIP: %s (%d bytes)\n", *zipPath, len(b))
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "zip.NewReader failed: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "Entries (%d):\n", len(zr.File))
	for _, f := range zr.File {
		fmt.Fprintf(os.Stderr, "- %s (%d bytes)\n", f.Name, f.UncompressedSize64)
	}

	pemCert, err := client.ExtractFirstCertificatePEMFromZip(b)
	if err == nil {
		if *out != "" {
			if writeErr := os.WriteFile(*out, []byte(pemCert), 0o644); writeErr != nil {
				fmt.Fprintf(os.Stderr, "failed to write PEM to %q: %v\n", *out, writeErr)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "Wrote PEM certificate to %s\n", *out)
			return
		}
		fmt.Print(pemCert)
		return
	}

	fmt.Fprintf(os.Stderr, "\nclient.ExtractFirstCertificatePEMFromZip error: %v\n", err)

	// Extra diagnostics: try parsing each file as PEM, x509 DER, and PKCS#7.
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			fmt.Fprintf(os.Stderr, "\n[%s] open error: %v\n", f.Name, openErr)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, 25<<20))
		_ = rc.Close()
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "\n[%s] read error: %v\n", f.Name, readErr)
			continue
		}

		fmt.Fprintf(os.Stderr, "\n[%s] sniff:\n", f.Name)
		if strings.Contains(string(data), "-----BEGIN") {
			fmt.Fprintf(os.Stderr, "- looks like PEM\n")
			block, _ := pem.Decode(data)
			if block != nil {
				fmt.Fprintf(os.Stderr, "- PEM block type: %s\n", block.Type)
			}
		}
		if cert, derr := x509.ParseCertificate(data); derr == nil {
			fmt.Fprintf(os.Stderr, "- x509 DER parse OK: subject=%s\n", cert.Subject.String())
		}
		if p7, p7err := pkcs7.Parse(data); p7err == nil {
			fmt.Fprintf(os.Stderr, "- pkcs7.Parse OK: certs=%d\n", len(p7.Certificates))
			for i, c := range p7.Certificates {
				if c == nil {
					continue
				}
				fmt.Fprintf(os.Stderr, "  - [%d] subject=%s isCA=%v\n", i, c.Subject.String(), c.IsCA)
			}
		} else {
			fmt.Fprintf(os.Stderr, "- pkcs7.Parse error: %v\n", p7err)
		}
	}

	os.Exit(1)
}
